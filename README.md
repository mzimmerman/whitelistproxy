[![Build Status](https://travis-ci.org/mzimmerman/whitelistproxy.svg)](https://travis-ci.org/mzimmerman/whitelistproxy) [![Coverage](http://gocover.io/_badge/github.com/mzimmerman/whitelistproxy)](http://gocover.io/github.com/mzimmerman/whitelistproxy)

# Whitelist Proxy

This transparent proxy does a man-in-the-middle on all http and https (when not whitelisted) connections.  It requires that it sees all the packets in the route to the destination.  Linux iptables rules deal with changing the source/destination IPs to act transparently, but you do need to setup your network configuration in a way so that the proxy is a mandatory stop on the outgoing route.  Primarily you can do this by placing the proxy inline.  This is required since whitelistproxy does not have any WCCP support itself; patches welcome.

# Features
- Transparent
- HTTPS proxying through MITM (Need to provide a CA certificate)
- Tunnels HTTPS when endpoints are whitelisted
- Supports non-SNI enabled clients (when host running proxy also serves dns through dnsmasq)
- LDAP authentication required to add site to the whitelist (Optional)
- Suggestions and pull requests welcomed

## Whitelist modifications

Since this proxy by definition blocks anything that is not in the whitelist, this proxy includes a method by which users on the system can add sites to the whitelist.  This is a manual step so that only those explicitly authorized sites are reachable by clients on your network.

## Why not explicit?

Transparent proxies are more difficult to maintain and setup from a server and network side, but they require no configuration on the client(s) which could be in unmanaged systems or systems that don't support a proxy configuration.

## Potential Issues

- Support for very old clients using HTTPS will fail.  Clients need to send the SNI value in the TLS ClientHello which most modern clients do these days, but old clients will break.  Run dnsmasq on the proxy and this issue is mostly mitigated.

- If you're routing table allows for it, an explicit http request to goproxy will cause it to fail in an endless loop since it will try to request resources from itself repeatedly.  This could be solved in the goproxy code by looking up the hostnames, but it adds a delay that is much easier/faster to handle on the routing side.

## Routing Rules

Example routing rules are included in [proxy.sh](https://github.com/elazarl/goproxy/blob/master/examples/transparent/proxy.sh) but are best when setup using your distribution's configuration.

## Support
Create issues for any questions on usage.
