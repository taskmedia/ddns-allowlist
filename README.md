# DDNS whitelist - Traefik plugin

Dynamic DNS whitelist plugin for Traefik.

## About

The `ddns-whitelist` plugin for Traefik allows you to whitelist dynamic DNS (DDNS) hosts. Requests from IP addresses that do not resolve to the specified DDNS hosts will be denied.

The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io/plugins/66fbe453573cd7803d65cb10/ddns-whitelist).

## Installation

To install the `ddns-whitelist` plugin, add the following configuration to your Traefik static configuration:

```yaml
experimental:
  plugins:
    ddns-whitelist:
      moduleName: "github.com/taskmedia/ddns-whitelist"
      version: v1.0.0 # TODO: use main for this example?
```

## Configuration

Add the `ddns-whitelist` middleware to your Traefik dynamic configuration:

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
        - ddns-whitelist-router

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ddns-whitelist-router:
      plugin:
        ddns-whitelist:
          hostList:
            - my.router.ddns.tld
```
