package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/HouzuoGuo/tiedot/db"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

var wlm WhiteListManager

type WhiteListManager interface {
	Add(e Entry)
	Check(*url.URL) bool
	RecentBlocks(int) []*url.URL
}

type MemoryWhitelistManager struct {
	sync.RWMutex
	entries []Entry
	stack   *Stack
}

func NewMemoryWhitelistManager() *MemoryWhitelistManager {
	twm := &MemoryWhitelistManager{}
	twm.stack = &Stack{
		Max: 50,
	}
	return twm
}

func (twm *MemoryWhitelistManager) Add(entry Entry) {
	twm.Lock()
	defer twm.Unlock()
	twm.entries = append(twm.entries, entry)
	log.Printf("MWLM added entry %#v", entry)
}

func (twm *MemoryWhitelistManager) Check(u *url.URL) bool {
	twm.RLock()
	defer twm.RUnlock()
	for _, x := range twm.entries {
		if u.Host == x.Host {
			if x.Path == "" {
				return true
			}
			if strings.HasPrefix(u.Path, x.Path) {
				if len(u.Path) == len(x.Path) { // exact same path since prefix passes
					return true
				}
				// u.Path must be at least one character longer since prefix passes and they're not equal
				if u.Path[len(x.Path)] == '?' || u.Path[len(x.Path)] == '/' {
					return true
				}
			}
		}
		if x.MatchSubdomains && strings.HasSuffix(u.Host, "."+x.Host) {
			return true
		}
	}
	twm.stack.Push(u)
	return false
}

func (twm *MemoryWhitelistManager) RecentBlocks(limit int) []*url.URL {
	list := make([]*url.URL, 0, twm.stack.Len())
	for {
		if len(list) == limit {
			break
		}
		elem := twm.stack.Pop()
		if elem == nil {
			break
		}
		list = append(list, elem)
	}
	return list
}

type RegexWhitelistManager struct {
	sync.RWMutex
	myDB    *db.DB
	entries *db.Col
	stack   *Stack
	match   []*regexp.Regexp
}

func NewRegexWhitelistManager(dbname string) (*RegexWhitelistManager, error) {
	rwm := &RegexWhitelistManager{}
	var err error
	rwm.myDB, err = db.OpenDB(dbname)
	if err != nil {
		return nil, fmt.Errorf("Unable to open database directory - %v", err)
	}
	rwm.myDB.Create("Regex")
	rwm.entries = rwm.myDB.Use("Regex")
	rwm.entries.ForEachDoc(func(id int, doc []byte) bool {
		entry := Entry{}
		err = json.Unmarshal(doc, &entry)
		if err != nil {
			log.Printf("Unable to load data (%s) from tiedot - %v", doc, err)
			return false
		}
		if !rwm.loadRegex(entry.Regex()) {
			err = fmt.Errorf("Unable to load regex - %s", entry.Regex())
			log.Println(err)
			return false
		}
		return true
	})
	rwm.stack = &Stack{
		Max: 50,
	}
	return rwm, err
}

func (rwm *RegexWhitelistManager) loadRegex(exp string) bool {
	rx, err := regexp.Compile(exp)
	if err != nil {
		log.Printf("Error parsing regexp - %v", err)
		return false
	}
	rwm.match = append(rwm.match, rx)
	return true
}

func (rwm *RegexWhitelistManager) Add(entry Entry) {
	regex := entry.Regex()
	rwm.Lock()
	defer rwm.Unlock()
	if _, err := rwm.entries.Insert(map[string]interface{}{
		"data": regex,
	}); err != nil {
		log.Printf("Error adding Entry - %v", err)
	} else {
		if rwm.loadRegex(regex) {
			log.Printf("RWM added entry %#v", entry)
		}
	}
}

func (rwm *RegexWhitelistManager) Check(u *url.URL) bool {
	rwm.RLock()
	defer rwm.RUnlock()
	for _, exp := range rwm.match {
		if exp.MatchString(u.String()) {
			return true
		}
	}
	rwm.stack.Push(u)
	return false
}

func (rwm *RegexWhitelistManager) RecentBlocks(limit int) []*url.URL {
	list := make([]*url.URL, 0, rwm.stack.Len())
	for {
		if len(list) == limit {
			break
		}
		elem := rwm.stack.Pop()
		if elem == nil {
			break
		}
		list = append(list, elem)
	}
	return list
}

var tmpl *template.Template

type Entry struct {
	Host            string
	MatchSubdomains bool
	Path            string
	Creator         string
	Created         time.Time
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

func (e Entry) Regex() string {
	var buf bytes.Buffer
	buf.WriteString(`https??://`)
	if e.MatchSubdomains {
		buf.WriteString(`.*\.??`)
	}
	buf.WriteString(e.Host)
	if e.Path != "" {
		buf.WriteString(e.Path)
		buf.WriteString(`([/\?]|$)`)
	} else {
		buf.WriteString(`([/\?].*|$)`)
	}
	return buf.String()
}

func queryURL(url *url.URL) []interface{} { // returns a query for tiedot
	query := []interface{}{
		map[string]interface{}{
			"n": []interface{}{
				map[string]interface{}{
					"c": []interface{}{
						map[string]interface{}{
							"eq":    url.Host,
							"in":    []interface{}{"Host"},
							"limit": 1,
						},
						map[string]interface{}{
							"has":   []interface{}{"Path"},
							"limit": 1,
						},
						map[string]interface{}{
							"has":   []interface{}{"Path"},
							"limit": 1,
						},
					},
				},
				//map[string]interface{}{
				//	"n": []interface{}{
				//		map[string]interface{}{
				//			"eq":    url.Host,
				//			"in":    []interface{}{"Host"},
				//			"limit": 1,
				//		},
				//		map[string]interface{}{
				//			"eq":    "",
				//			"in":    []interface{}{"Path"},
				//			"limit": 1,
				//		},
				//	},
				//},
			},
		},
	}
	for _, host := range rootDomains(url.Host) {
		query = append(query, map[string]interface{}{
			"n": []interface{}{
				map[string]interface{}{
					"eq":    host,
					"in":    []interface{}{"Host"},
					"limit": 1,
				}, map[string]interface{}{
					"eq":    "true",
					"in":    []interface{}{"MatchSubdomains"},
					"limit": 1,
				},
			},
		})
	}
	for _, paths := range paths(url.Path) {
		query = append(query, map[string]interface{}{
			"n": []interface{}{
				map[string]interface{}{
					"eq":    url.Host,
					"in":    []interface{}{"Host"},
					"limit": 1,
				},
				map[string]interface{}{
					"eq":    paths,
					"in":    []interface{}{"Path"},
					"limit": 1,
				},
			},
		})
	}
	return query
}

var whiteListHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	buf := bytes.Buffer{}
	if ok := wlm.Check(req.URL); ok {
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
		Header:        http.Header{},
		Body:          ioutil.NopCloser(&buf),
		ContentLength: int64(buf.Len()),
	}
}

var whitelistService = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/add":
		r.ParseForm()
		URL := r.Form.Get("url")
		decURL, err := url.QueryUnescape(URL)
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return
		}
		entry := NewEntry(r.Form.Get("host"), r.Form.Get("match") == "true", r.Form.Get("path"), r.RemoteAddr)
		wlm.Add(entry) // wait till host is added, otherwise we might get blocked again on redirect
		http.Redirect(w, r, decURL, 301)
	case "/list":
		list := wlm.RecentBlocks(20) // get up to the last 20
		err := tmpl.ExecuteTemplate(w, r.URL.Path, map[string]interface{}{"List": list})
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Error fetching recently blocked sites - %v", err)))
		}
	default:
		w.Write([]byte(fmt.Sprintf("Unable to handle path - %s", r.URL.Path)))
	}
})

func main() {
	var err error
	wlm, err = NewRegexWhitelistManager("database")
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
	go func() {
		err := http.ListenAndServe(":9000", whitelistService)
		log.Fatalf("Error starting whitelist service - %v", err)
	}()
	verbose := flag.Bool("v", true, "should every proxy request be logged to stdout")
	http_addr := flag.String("httpaddr", ":3129", "proxy http listen address")
	https_addr := flag.String("httpsaddr", ":3128", "proxy https listen address")
	flag.Parse()

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
			TlsConfig: &tls.Config{},
			Ca:        &cert,
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
			if tlsConn.Host() == "" {
				log.Printf("Cannot support non-SNI enabled clients")
				return
			}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: tlsConn.Host(),
					Host:   net.JoinHostPort(tlsConn.Host(), "443"),
				},
				Host:   tlsConn.Host(),
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
