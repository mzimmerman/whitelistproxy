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
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	vhost "github.com/inconshreveable/go-vhost"
	ldap "github.com/mzimmerman/ldap"
)

var store *sessions.CookieStore

var ldc LDAPConnector

type LDAPConnector struct {
	BindPrefix string
	BindSuffix string
	Address    string
}

func (auth LDAPConnector) Authenticate(user, pass string) error {
	conn, err := ldap.Dial("tcp", auth.Address)
	if err != nil {
		return err
	}
	return conn.Bind(auth.BindPrefix+ldap.EscapeFilter(user)+auth.BindSuffix, pass)
}

func (auth LDAPConnector) ChangePass(user, oldpass, newpass string) error {
	conn, err := ldap.Dial("tcp", auth.Address)
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
	Add(e Entry)
	Check(Site) bool
	RecentBlocks(int) []Site
	Current() []Entry
}

var tmpl *template.Template

type Entry struct {
	Host            string
	MatchSubdomains bool
	Path            string
	Creator         string
	Created         time.Time
}

func (e Entry) CSV() []string {
	return []string{e.Host, fmt.Sprintf("%t", e.MatchSubdomains), e.Path, e.Creator, e.Created.Format(time.ANSIC)}
}

func (e Entry) Map() map[string]interface{} {
	return map[string]interface{}{
		"Host":            e.Host,
		"MatchSubdomains": e.MatchSubdomains,
		"Path":            e.Path,
		"Creator":         e.Creator,
		"Created":         e.Created,
	}
}

func NewEntry(host string, subdomains bool, path, creator string) Entry {
	if !strings.Contains(host, ".") { // don't root domains be wildcarded, but allow "internal" hosts
		subdomains = false
	}
	return Entry{
		Host:            host,
		MatchSubdomains: subdomains,
		Path:            path,
		Creator:         creator,
		Created:         time.Now(),
	}
}

var whiteListHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	buf := bytes.Buffer{}
	if ok := wlm.Check(Site{
		URL:     req.URL,
		Referer: req.Referer(),
	}); ok {
		return req, nil
	}
	err := tmpl.ExecuteTemplate(&buf, "deny", map[string]*http.Request{"Request": req})
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

var whitelistService = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache")
	switch r.URL.Path {
	case "/auth":
		r.ParseForm()
		err := ldc.Authenticate(r.Form.Get("user"), r.Form.Get("pass"))
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Error authenticating - %v", err)))
			return
		}
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
			return
		}
		decHost, err := url.QueryUnescape(r.Form.Get("host"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return
		}
		decPath, err := url.QueryUnescape(r.Form.Get("path"))
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return
		}
		user := ""
		if ldc.Address != "" {
			session, err := store.Get(r, "session")
			if err == nil {
				user, _ = session.Values["user"].(string)
			}
			if user == "" {
				err = tmpl.ExecuteTemplate(w, "/auth", map[string]interface{}{
					"URL":            r.Form.Get("url"),
					"Path":           r.Form.Get("path"),
					"Host":           r.Form.Get("host"),
					"MatchSubstring": r.Form.Get("match"),
				})
				// TODO: prompt the user to authenticate
				return
			}
		} else {
			user = strings.Split(r.RemoteAddr, ":")[0]
		}
		entry := NewEntry(decHost, r.Form.Get("match") == "true", decPath, user)
		wlm.Add(entry) // wait till host is added, otherwise we might get blocked again on redirect
		http.Redirect(w, r, decURL, 301)
	case "/list":
		list := wlm.RecentBlocks(20) // get up to the last 20
		refererMap := make(map[string][]*url.URL)
		for _, site := range list {
			refererMap[site.Referer] = append(refererMap[site.Referer], site.URL)
		}
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, r.URL.Path, map[string]interface{}{"List": refererMap})
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error fetching recently blocked sites - %v", err)))
		} else {
			io.Copy(w, &buf)
		}
	case "/current":
		var buf bytes.Buffer
		err := tmpl.ExecuteTemplate(&buf, r.URL.Path, map[string]interface{}{"List": wlm.Current()})
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Error fetching current whitelist - %v", err)))
		} else {
			io.Copy(w, &buf)
		}
	default:
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("Unable to handle path - %s", r.URL.Path)))
	}
})

func init() {
	cookie_pass := flag.String("cookiepass", "defaultpassword", "the encryptionkey used to manage session cookies")
	ldap_address := flag.String("ldapaddress", "", "the address and port (addr:port) of the LDAP server")
	ldap_bind_prefix := flag.String("ldapprefix", "uid=", "the prefix used before the userid in an LDAP bind")
	ldap_bind_suffix := flag.String("ldapsuffix", ",ou=People,ou=whitelistproxy,ou=com", "the suffix used after the userid in an LDAP bind")
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

	var err error
	wlm, err = NewMemoryWhitelistManager("whitelist.csv")
	if err != nil {
		log.Fatalf("Error loading RegexWhitelist - %v", err)
	}
	tmpl, err = template.New("default").Funcs(template.FuncMap{
		"paths":       paths,
		"rootDomains": rootDomains,
	}).ParseFiles("template.html")
	if err != nil {
		log.Fatalf("Error parsing template - %v", err)
	}
}

func main() {
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	http_addr := flag.String("httpaddr", ":3129", "proxy http listen address")
	https_addr := flag.String("httpsaddr", ":3128", "proxy https listen address")
	go func() {
		err := http.ListenAndServe(":9000", context.ClearHandler(whitelistService))
		log.Fatalf("Error starting whitelist service - %v", err)
	}()
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose
	if proxy.Verbose {
		log.Printf("Server starting up! - configured to listen on http interface %s and https interface %s", *http_addr, *https_addr)
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

	proxy.OnRequest().DoFunc(whiteListHandler)

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: goproxy.TLSConfigFromCA(&cert),
		}, host
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
					"-n 20",
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
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: host,
					Host:   net.JoinHostPort(host, "443"),
				},
				Host:   host,
				Header: make(http.Header),
			}
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
