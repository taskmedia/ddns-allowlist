# DDNS allowlist - Traefik plugin

Dynamic DNS allowlist plugin for Traefik.

## About

The `ddns-allowlist` plugin for Traefik allows you to allowlist dynamic DNS (DDNS) hosts. Requests from IP addresses that do not resolve to the specified DDNS hosts will be denied.

The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io/plugins/66fbe453573cd7803d65cb10/ddns-allowlist).

## Installation

To install the `ddns-allowlist` plugin, add the following configuration to your Traefik static configuration:

```yaml
experimental:
  plugins:
    ddns-allowlist:
      moduleName: "github.com/taskmedia/ddns-allowlist"
      version: v1.2.1
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
          logLevel: ERROR
          hostList: # hosts to dynamically allowlist via DNS lookup
            - my.router.ddns.tld
          ipList: # optional IP addresses to allowlist
            - 1.2.3.4
```
