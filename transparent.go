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

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
)

var whitelistAddChan = make(chan *url.URL)
var whitelistCheckChan = make(chan *http.Request)
var whitelistOkayChan = make(chan bool)
var whitelistBlockedChan = make(chan []*url.URL)
var whitelistRequestBlockedChan = make(chan int)

var tmpl *template.Template

func manageWhitelist() {
	whitelistedHosts := make(map[string]struct{})
	stack := &Stack{
		Max: 50,
	}
	for {
		select {
		case add := <-whitelistAddChan:
			whitelistedHosts[add.Host] = struct{}{}
			log.Printf("Added %s", add.Host)
		case check := <-whitelistCheckChan:
			_, ok := whitelistedHosts[check.Host]
			if !ok {
				stack.Push(check.URL)
			}
			whitelistOkayChan <- ok
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
		URL := r.FormValue("url")
		decURL, err := url.QueryUnescape(URL)
		var realURL *url.URL
		if err == nil {
			realURL, err = url.Parse(decURL)
		}
		if err != nil {
			w.WriteHeader(400)
			err = tmpl.ExecuteTemplate(w, "error", map[string]interface{}{"Error": err})
			if err != nil {
				w.Write([]byte(fmt.Sprintf("Error adding site to whitelist, error writing template - %v", err)))
			}
			return
		}
		go func(r *url.URL) {
			whitelistAddChan <- r
		}(realURL)
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
	tmpl, err = template.ParseFiles("template.html")
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
