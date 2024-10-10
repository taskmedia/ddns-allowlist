# DDNS allowlist - Traefik plugin

Dynamic DNS allowlist plugin for Traefik: Add your dynamic hostname (your homenetwork router) to the allow list

## About

The `ddns-allowlist` plugin for Traefik allows you to add dynamic DNS (DDNS) hosts to the allowed requesters.
Requests from IP addresses that do not resolve to the specified DDNS hosts will be denied.

This idea was created to add your router with a floating ips to an allowlist.
This is not limited to your DDNS supporting router - you can add any host.
It is more an hostname allowlist which will do a DNS lookup.
Because server typically have a static IP, you should add its static IPs to the allowlist.

The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io/plugins/66fef7d4573cd7803d65cb12/ddns-allowlist).

## Installation

To install the `ddns-allowlist` plugin, add the following configuration to your Traefik static configuration:

```yaml
experimental:
  plugins:
    ddns-allowlist:
      moduleName: "github.com/taskmedia/ddns-allowlist"
      version: v1.5.2
```

## Configuration

Add the `ddns-allowlist` middleware to your Traefik dynamic configuration:

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - ddns-allowlist-router

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ddns-allowlist-router:
      plugin:
        ddns-allowlist:
          # optional: log level for the plugin (allowed: ERROR, INFO, DEBUG, default: ERROR)
          logLevel: ERROR
          # hosts to dynamically add to allowlist via DNS lookup
          sourceRangeHosts:
            - my.router.ddns.tld
          # optional: IP addresses to allowlist
          sourceRangeIps:
            - 1.2.3.4
          # optional: IP strategy to determine the client IP address (default: RemoteAddr)
          # also see: https://doc.traefik.io/traefik/middlewares/http/ipwhitelist/#ipstrategy
          ipStrategy:
            depth: 1
            cloudflareDepth: 1
            excludedIPs:
              - 4.3.2.1
          # optional: allow IPv6 interface identifier based on given prefix
          # this will skip the interface identifier validation (default: disabled)
          allowedIPv6NetworkPrefix: 64
          # optional: lookup interval for DNS hosts in seconds (default: 5 min)
          lookupInterval: 60
```
