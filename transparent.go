package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/sessions"
	vhost "github.com/inconshreveable/go-vhost"
	ldap "github.com/mzimmerman/ldap"
)

var (
	store          *sessions.CookieStore
	ldc            LDAPConnector
	verbose        *bool
	http_addr      *string
	https_addr     *string
	proxy_hostname *string
)

type LDAPConnector struct {
	BindPrefix string
	BindSuffix string
	Address    string
}

func (auth LDAPConnector) Authenticate(user, pass string) error {
	conn, err := ldap.DialTLS("tcp", auth.Address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	return conn.Bind(auth.BindPrefix+ldap.EscapeFilter(user)+auth.BindSuffix, pass)
}

func (auth LDAPConnector) ChangePass(user, oldpass, newpass string) error {
	conn, err := ldap.DialTLS("tcp", auth.Address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	err = conn.Bind(user, oldpass)
	if err != nil {
		return err
	}
	pmr := ldap.NewPasswordModifyRequest(user, oldpass, newpass)
	_, err = conn.PasswordModify(pmr)
	return err
}

var wlm WhiteListManager

type WhiteListManager interface {
	Add(net.IP, string, Entry, bool) error // fails with wrong user
	Check(net.IP, Site) (bool, bool)
	RecentBlocks(net.IP, int) []Site
	Current(ip net.IP) []Entry
}

var tmpl *template.Template

type Entry struct {
	Host            string
	MatchSubdomains bool
	Path            string
	KeepTLS         bool // if true, will not to tear down the TLS connection for Referrer tag validity
	Creator         string
	Created         time.Time
	Expires         time.Time
}

func NewEntry(host string, subdomains bool, path, creator string, duration time.Duration) Entry {
	if !strings.Contains(host, ".") { // don't allow root domains be wildcarded, but allow "internal" hosts
		subdomains = false
	}
	now := time.Now()
	return Entry{
		Host:            host,
		MatchSubdomains: subdomains,
		Path:            path,
		Creator:         creator,
		Created:         now,
		Expires:         now.Add(duration),
	}
}

func (e Entry) Supercedes(f Entry) bool {
	return e.timeSupercedes(f) && e.pathSupercedes(f)
}

func (e Entry) Expired(now time.Time) bool {
	if e.Expires.Equal(e.Created) {
		return false
	}
	if e.Expires.Before(now) {
		return true
	}
	return false
}

func (e Entry) timeSupercedes(f Entry) bool {
	if e.Created.Equal(e.Expires) { // e does not expire
		return true
	}
	if f.Created.Equal(f.Expires) { // f does not expire
		return false
	}
	if !e.Expires.Before(f.Expires) {
		return true
	}
	return false
}

func (e Entry) pathSupercedes(f Entry) bool {
	if e.Host == f.Host {
		if e.MatchSubdomains == f.MatchSubdomains {
			if e.MatchSubdomains {
				return true // they're the same, paths won't exist when matching subdomains
			}
			// neither entry matches a path
			if strings.HasPrefix(f.Path+"/", e.Path+"/") {
				return true
			}
			return false
		}
		// e.MatchSubdomains != f.MatchSubdomains
		if e.MatchSubdomains {
			return true
		}
	} else if e.MatchSubdomains && strings.HasSuffix(f.Host, "."+e.Host) {
		return true
	}
	return false
}

var durations = []struct {
	N string
	D string
	S string
}{
	{"5Min", "5m", "primary"},
	{"Hour", "1h", "success"},
	{"Day", "24h", "info"},
	{"Week", "168h", "warning"},
	{"Forever", "0s", "danger"},
}

func makeWhitelistArgs(path, host string, u *url.URL, redirect bool) map[string]interface{} {
	return map[string]interface{}{
		"Path":      path,
		"Host":      host,
		"URL":       u,
		"Redirect":  redirect,
		"Durations": durations,
	}
}

var whiteListHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		panic(fmt.Sprintf("userip: %q is not IP:port", req.RemoteAddr))
	}
	userIP := net.ParseIP(ip)
	if userIP == nil {
		panic(fmt.Sprintf("userip: %q is not IP", ip))
	}

	buf := bytes.Buffer{}
	if ok, _ := wlm.Check(userIP, Site{
		URL:     req.URL,
		Referer: req.Referer(),
	}); ok {
		log.Printf("IP %s visited - %v - referred from - %v", ip, req.URL, req.Referer())
		return req, nil
	}
	log.Printf("IP %s was blocked visiting - %v - referred from - %v", ip, req.URL, req.Referer())
	err = tmpl.ExecuteTemplate(&buf, "deny", map[string]interface{}{
		"Request": req,
	})
	if err != nil {
		buf.WriteString(fmt.Sprintf("<html><body>Requested destination not in whitelist, error writing template - %v", err))
	}

	return nil, &http.Response{
		StatusCode:    400,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       ctx.Req,
		Header:        http.Header{"Cache-Control": []string{"no-cache"}},
		Body:          ioutil.NopCloser(&buf),
		ContentLength: int64(buf.Len()),
	}
}

func responseFromResponseRecorder(req *http.Request, w *httptest.ResponseRecorder) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "", w.Code, w.Body.String())
	resp.Header = make(http.Header)
	for key, vals := range w.HeaderMap {
		for _, val := range vals {
			resp.Header.Add(key, val)
		}
	}
	return req, resp
}

type firewallLine struct {
	proto   string // TCP, UDP, or "" if none found
	dstip   net.IP
	srcip   net.IP
	dstport int
}

func (fl firewallLine) String() string {
	return strings.Join(fl.Strings(), "\n")
}

func (fl firewallLine) Strings() []string {
	mask := net.IPv4Mask(0xff, 0xff, 0xff, 0) // class C
	ipnet := &net.IPNet{
		IP:   fl.srcip.Mask(mask),
		Mask: mask,
	}
	return []string{
		fmt.Sprintf("-A fw-interfaces -s %s -d %s -p %s -m %s --dport %d -j ACCEPT", fl.srcip, fl.dstip, fl.proto, fl.proto, fl.dstport),
		fmt.Sprintf("-A fw-interfaces -s %s -d %s -p %s -m %s --dport %d -j ACCEPT", ipnet, fl.dstip, fl.proto, fl.proto, fl.dstport),
	}
}

func parseFirewallLine(s string) (fl firewallLine, err error) {
	t := strings.Split(s, " ")
	for _, u := range t {
		switch {
		case strings.HasPrefix(u, "DST="):
			fl.dstip = net.ParseIP(u[4:])
		case strings.HasPrefix(u, "SRC="):
			fl.srcip = net.ParseIP(u[4:])
		case strings.HasPrefix(u, "DPT="):
			fl.dstport, err = strconv.Atoi(u[4:])
			if err != nil {
				return
			}
		case strings.HasPrefix(u, "PROTO="):
			fl.proto = strings.ToLower(u[6:])
		}
	}
	if fl.dstip == nil || fl.srcip == nil || fl.dstport == 0 || fl.proto == "" {
		err = fmt.Errorf("Error parsing firewall line from %s - %s", s, fl)
		return
	}
	return
}

func whitelistService(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		panic(fmt.Sprintf("userip: %q is not IP:port", r.RemoteAddr))
	}
	userIP := net.ParseIP(ip)
	if userIP == nil {
		panic(fmt.Sprintf("userip: %q is not IP", ip))
	}

	w := httptest.NewRecorder()
	if strings.HasPrefix(r.URL.Path, "/js") {
		staticFile(w, r)
		return responseFromResponseRecorder(r, w)
	}
	w.Header().Add("Cache-Control", "no-cache")
	switch r.URL.Path {
	case "/auth":
		r.ParseForm()
		err := ldc.Authenticate(r.Form.Get("user"), r.Form.Get("pass"))
		if err != nil {
			log.Printf("Unsuccessful authentication as %s from %s", r.Form.Get("user"), ip)
			w.Write([]byte(fmt.Sprintf("Error authenticating - %v", err)))
			return responseFromResponseRecorder(r, w)
		}
		log.Printf("User %s authenticated successfully from %s", r.Form.Get("user"), ip)
		session, _ := store.Get(r, "session")
		session.Values["user"] = r.Form.Get("user")
		err = session.Save(r, w)
		if err != nil {
			log.Printf("Authenticated successfully but could not save the cookie - %v", err)
		}
		fallthrough
	case "/add":
		r.ParseForm()
		decURL, err := url.QueryUnescape(r.Form.Get("url"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return responseFromResponseRecorder(r, w)
		}
		decHost, err := url.QueryUnescape(r.Form.Get("host"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return responseFromResponseRecorder(r, w)
		}
		decPath, err := url.QueryUnescape(r.Form.Get("path"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return responseFromResponseRecorder(r, w)
		}
		decDuration, err := url.QueryUnescape(r.Form.Get("duration"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return responseFromResponseRecorder(r, w)
		}
		duration, _ := time.ParseDuration(decDuration)
		user := ""
		redirectToURL := r.Form.Get("redirect") == "true"
		if ldc.Address != "" {
			session, err := store.Get(r, "session")
			if err == nil {
				user, _ = session.Values["user"].(string)
			}
		} else {
			user = ip
		}
		entry := NewEntry(decHost, r.Form.Get("match") == "true", decPath, user, duration)
		err = wlm.Add(userIP, user, entry, ldc.Address != "") // wait till host is added, otherwise we might get blocked again on redirect
		if err != nil {
			err = tmpl.ExecuteTemplate(w, "/auth", map[string]interface{}{
				"URL":            r.Form.Get("url"),
				"Path":           r.Form.Get("path"),
				"Host":           r.Form.Get("host"),
				"MatchSubstring": r.Form.Get("match"),
				"Duration":       r.Form.Get("duration"),
				"Redirect":       r.Form.Get("redirect"),
				"Error":          err,
			})
			return responseFromResponseRecorder(r, w)
		}
		log.Printf("User %s from %s added site - %#v", user, ip, entry)
		if redirectToURL {
			http.Redirect(w, r, decURL, http.StatusMovedPermanently)
		} else {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
		}
		return responseFromResponseRecorder(r, w)
	default: // case: "/list"
		list := wlm.RecentBlocks(userIP, 50) // get up to the last 50
		type rg struct {
			Referer string
			Sites   []*url.URL
		}
		referers := make([]*rg, 0, len(list))
	outer:
		for _, site := range list {
			for _, x := range referers {
				if x.Referer == site.Referer {
					x.Sites = append(x.Sites, site.URL)
					continue outer
				}
			}
			referers = append(referers, &rg{
				Referer: site.Referer,
				Sites:   []*url.URL{site.URL},
			})
		}
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, "/list", map[string]interface{}{"List": referers,
			"Durations": durations,
		})
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error fetching recently blocked sites - %v", err)))
		} else {
			io.Copy(w, &buf)
		}
		return responseFromResponseRecorder(r, w)
	case "/current":
		currentList := make(chan Entry)
		done := make(chan struct{})
		defer func() {
			done <- struct{}{}
		}()
		go func() {
			now := time.Now()
			for _, e := range wlm.Current(userIP) {
				if e.Expired(now) {
					continue
				}
				select {
				case currentList <- e:
				case <-done:
					return
				}
			}
			close(currentList)
			<-done
		}()
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, "/current", map[string]interface{}{"List": currentList})
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error fetching current whitelist - %v", err)))
		} else {
			io.Copy(w, &buf)
		}
		return responseFromResponseRecorder(r, w)
	case "/network":
		header := ""                               // any overarching message to show to the user
		currentList := make([]firewallLine, 0, 10) // a decent estimate on starting lines
		cmd := exec.Command(
			"/usr/bin/sudo",
			"/usr/bin/journalctl",
			"-r", // reverse, newest first
			"-o", "short",
			"--no-pager",
			"-n", "50", // only show the first 1000 matches
			"-k", // only kernel messages
		)
		output, err := cmd.CombinedOutput()
		if err != nil {
			header = fmt.Sprintf("Error getting output - %v - %s", err, output)
		} else {
			lines := bufio.NewScanner(bytes.NewReader(output))
			zm, ok := wlm.(ZoneManager)
			var zone *Zone
			if ok {
				zone = zm.Find(userIP)
				if zone == nil {
					header = fmt.Sprintf("Zone not found for IP %s, no data", userIP)
				}
			}
			if zone != nil {
			NextLine:
				for lines.Scan() {
					line := lines.Text()
					//					 only show items that are in the zone
					//					 filter by IP
					fl, err := parseFirewallLine(line)
					if err != nil {
						log.Print(err)
						continue
					}
					if zone.contains(fl.srcip) || zone.contains(fl.dstip) {
						for _, tmpfl := range currentList {
							if fl.String() == tmpfl.String() {
								continue NextLine
							}
						}
						currentList = append(currentList, fl)
					}
				}
			} else {
				log.Printf("No zone configured for ip - %s", userIP)
			}
		}

		var buf bytes.Buffer
		err = tmpl.ExecuteTemplate(&buf, "/network", map[string]interface{}{"Header": header, "List": currentList})
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error fetching latest Network Traffic - %v", err)))
		} else {
			io.Copy(w, &buf)
		}
		return responseFromResponseRecorder(r, w)
	}
}

func staticFile(w http.ResponseWriter, r *http.Request) {
	buf, ok := staticFiles[path.Base(r.URL.Path)]
	if ok {
		w.Write(buf)
	} else {
		log.Printf("Error locating static file - %s", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}
}

var staticFiles map[string][]byte

func init() {
	staticFiles = make(map[string][]byte)
	files, err := ioutil.ReadDir("js")
	if err != nil {
		log.Fatalf("Error reading js dir - %v", err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		buf, err := ioutil.ReadFile("js" + string(os.PathSeparator) + f.Name())
		if err != nil {
			log.Fatalf("Error reading file - %v", f.Name())
		}
		log.Printf("Loaded filename into buffer - %s", f.Name())
		staticFiles[f.Name()] = buf
	}
	cookie_pass := flag.String("cookiepass", "defaultpassword", "the encryptionkey used to manage session cookies")
	ldap_address := flag.String("ldapaddress", "", "the address and port (addr:port) of the LDAP server")
	ldap_bind_prefix := flag.String("ldapprefix", "uid=", "the prefix used before the userid in an LDAP bind")
	ldap_bind_suffix := flag.String("ldapsuffix", ",ou=People,ou=whitelistproxy,ou=com", "the suffix used after the userid in an LDAP bind")
	whitelist_filename := flag.String("whitelistfile", "", "The path/name of the file where the whitelist will be read/written to")
	zones_filename := flag.String("zonesfile", "", "The path/name of the file where the configuration of zones will be read from")
	verbose = flag.Bool("v", false, "should every proxy request be logged to stdout")
	http_addr = flag.String("httpaddr", ":3129", "proxy http listen address")
	https_addr = flag.String("httpsaddr", ":3128", "proxy https listen address")
	proxy_hostname = flag.String("hostname", "whitelistproxy", "The hostname of the whitelistproxy in order to manipulate the whitelist")
	flag.Parse()

	// initialize the gorilla session store
	store = sessions.NewCookieStore([]byte(*cookie_pass))
	store.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 86400, // one day
	}

	ldc = LDAPConnector{
		Address:    *ldap_address,
		BindPrefix: *ldap_bind_prefix,
		BindSuffix: *ldap_bind_suffix,
	}

	switch {
	case *zones_filename != "" && *whitelist_filename != "":
		panic(fmt.Sprintf("Cannot use both zonesfile and whitelistfile options - %s - %s", *zones_filename, *whitelist_filename))
	case *zones_filename != "":
		wlm, err = NewZoneManager(*zones_filename)
	case *whitelist_filename != "":
		wlm, err = NewMemoryWhitelistManager(*whitelist_filename)
	default:
		wlm, err = NewMemoryWhitelistManager("whitelist.json") // legacy default
	}
	if err != nil {
		log.Fatalf("Error loading Whitelist - %v", err)
	}
	tmpl, err = template.New("default").Funcs(template.FuncMap{
		"paths":             paths,
		"rootDomains":       rootDomains,
		"makeWhitelistArgs": makeWhitelistArgs,
		"proxyHostname": func() string {
			return *proxy_hostname
		},
	}).ParseFiles("template.html")
	if err != nil {
		log.Fatalf("Error parsing template - %v", err)
	}
}

var preTLSReferrer = "pressl"

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	if proxy.Verbose {
		log.Printf("Server starting up! - configured to listen on http interface %s and https interface %s with hostname %s", *http_addr, *https_addr, *proxy_hostname)
	}

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})
	cert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		log.Fatalf("Unable to load certificate - %v", err)
	}
	tlsConfig := goproxy.TLSConfigFromCA(&cert)

	proxy.OnRequest(goproxy.DstHostIs(*proxy_hostname)).DoFunc(whitelistService)
	proxy.OnRequest().DoFunc(whiteListHandler)
	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		ip, _, err := net.SplitHostPort(ctx.Req.RemoteAddr)
		if err != nil {
			panic(fmt.Sprintf("userip: %q is not IP:port", ctx.Req.RemoteAddr))
		}
		userIP := net.ParseIP(ip)
		if userIP == nil {
			panic(fmt.Sprintf("userip: %q is not IP", ip))
		}
		log.Printf("Handled connect from ip - %s - for host %s", ip, host)
		if host == *proxy_hostname {
			// tear down the connection for the proxy itself
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: goproxy.TLSConfigFromCA(&cert),
			}, host + ":443"
		}
		res, skiptls := wlm.Check(userIP, Site{
			URL:     ctx.Req.URL,
			Referer: preTLSReferrer,
		})
		if res && skiptls {
			// don't tear down the SSL session
			return goproxy.OkConnect, host + ":443"
		}
		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: tlsConfig,
		}, host + ":443"
	})

	go func() {
		log.Fatalln(http.ListenAndServe(*http_addr, proxy))
	}()

	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", *https_addr)
	if err != nil {
		log.Fatalf("Error listening for https connections - %v", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting new connection - %v", err)
			continue
		}
		go func(c net.Conn) {
			tlsConn, err := vhost.TLS(c)
			if err != nil {
				log.Printf("Error accepting new connection - %v", err)
			}
			host := tlsConn.Host()
			if host == "" {
				log.Printf("Cannot support non-SNI enabled clients, attempting to make an educated guess")
				// TODO: add other options than dnsmasq through journald
				cmd := exec.Command(
					"/usr/bin/sudo",
					"/usr/bin/journalctl",
					"-n", "20",
					"-u", "dnsmasq",
				)
				output, err := cmd.CombinedOutput()
				if err != nil {
					log.Printf("Could not find a recent DNS lookup in the dnsmasq logs - %v", err)
				} else {
					lines := bufio.NewScanner(bytes.NewReader(output))
					requestor, _, _ := net.SplitHostPort(c.RemoteAddr().String())
					for lines.Scan() {
						if strings.Contains(lines.Text(), requestor) {
							split := strings.Split(lines.Text(), " ")
							if len(split) >= 7 {
								host = split[6]
								break
							}
						}
					}
				}
				if host == "" {
					// At this point we're going to error, give the client a hint as to why
					host = "yourclientdoesnotsuppportsni"
				}
				log.Printf("Guessing with %s", host)
			}
			connectReq := &http.Request{
				RemoteAddr: c.RemoteAddr().String(),
				Method:     "CONNECT",
				URL: &url.URL{
					Opaque: host,
					Host:   host,
				},
				Host:   host,
				Header: make(http.Header),
			}
			log.Printf("Making faux CONNECT request with URL - %s", connectReq.URL)
			log.Printf("Request.URL.Host - %v", connectReq.URL.Host)
			resp := dumbResponseWriter{tlsConn}
			proxy.ServeHTTP(resp, connectReq)
		}(c)
	}
}

func paths(path string) []string {
	data := strings.Split(path, "/")
	response := make([]string, 0)
	if path == "/" {
		return response
	}
	if len(path) < 1 {
		return response
	}
	if path[0] != '/' {
		return response
	}
	for i := 1; i < len(data); i++ {
		response = append([]string{"/" + strings.Join(data[1:i+1], "/")}, response...)
	}
	return response
}

func rootDomains(host string) []string {
	data := strings.Split(host, ".")
	response := make([]string, 0)
	if len(data) <= 1 {
		return response
	}
	for i := 0; i < len(data)-1; i++ {
		response = append(response, strings.Join(data[i:], "."))
	}
	return response
}

// copied/converted from https.go
func dial(proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.Tr.Dial != nil {
		return proxy.Tr.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

// copied/converted from https.go
func connectDial(proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDial == nil {
		return dial(proxy, network, addr)
	}
	return proxy.ConnectDial(network, addr)
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}
