package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HouzuoGuo/tiedot/db"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

var whitelistAddChan = make(chan Entry)
var whitelistCheckChan = make(chan *http.Request)
var whitelistOkayChan = make(chan bool)
var whitelistBlockedChan = make(chan []*url.URL)
var whitelistRequestBlockedChan = make(chan int)

var tmpl *template.Template

type Entry map[string]interface{}

func NewEntry(host string, subdomains bool, path, creator string) Entry {
	return map[string]interface{}{
		"Host":            host,
		"MatchSubdomains": subdomains,
		"Path":            path,
		"Creator":         creator,
		"Created":         time.Now(),
	}
}

func (e Entry) Host() string {
	return e["Host"].(string)
}

func (e Entry) MatchSubdomains() bool {
	return e["MatchSubdomains"].(bool)
}

func (e Entry) Path() string {
	return e["Path"].(string)
}

func (e Entry) Creator() string {
	return e["Creator"].(string)
}

func (e Entry) Created() time.Time {
	return e["Created"].(time.Time)
}

func queryURL(url *url.URL) []interface{} { // returns a query for tiedot
	query := []interface{}{
		map[string]interface{}{
			"eq":    url.Host,
			"in":    []interface{}{"Host"},
			"limit": 1,
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
					"eq": url.Host,
					"in": []interface{}{"Host"},
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

func manageWhitelist() {
	myDB, err := db.OpenDB("database")
	if err != nil {
		log.Fatalf("Unable to open database directory - %v", err)
	}
	myDB.Create("Entries")
	entries := myDB.Use("Entries")
	entries.Index([]string{"Host"})
	entries.Index([]string{"MatchSubdomains"})
	entries.Index([]string{"Path"})
	stack := &Stack{
		Max: 50,
	}
	for {
		select {
		case add := <-whitelistAddChan:
			if _, err := entries.Insert(add); err != nil {
				log.Printf("Error adding Entry - %v", err)
			} else {
				log.Printf("Added entry %#v", add)
			}
		case check := <-whitelistCheckChan:
			query := queryURL(check.URL)
			result := make(map[int]struct{})
			err := db.EvalQuery(query, entries, &result)
			if err != nil {
				log.Printf("Error doing tiedot query - %v", err)
			}
			if len(result) == 0 {
				stack.Push(check.URL)
			}
			whitelistOkayChan <- len(result) > 0
		case num := <-whitelistRequestBlockedChan:
			list := make([]*url.URL, 0, stack.Len())
			for {
				if len(list) == num {
					break
				}
				elem := stack.Pop()
				if elem == nil {
					break
				}
				list = append(list, elem)
			}
			whitelistBlockedChan <- list
		}
	}
}

var whiteListHandler goproxy.FuncReqHandler = func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	buf := bytes.Buffer{}
	whitelistCheckChan <- req
	if <-whitelistOkayChan {
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
		go func() {
			whitelistAddChan <- entry
		}()
		http.Redirect(w, r, decURL, 301)
	case "/list":
		whitelistRequestBlockedChan <- 20 // get up to the last 20
		list := <-whitelistBlockedChan
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
	tmpl, err = template.New("default").Funcs(template.FuncMap{
		"paths":       paths,
		"rootDomains": rootDomains,
	}).ParseFiles("template.html")
	if err != nil {
		log.Fatalf("Error parsing template - %v", err)
	}
	go manageWhitelist()
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
