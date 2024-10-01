# DDNSwhitelist - Traefik plugin

Dynamic DNS whitelist plugin for Traefik.

## About

The `DDNSwhitelist` plugin for Traefik allows you to whitelist dynamic DNS (DDNS) hosts. Requests from IP addresses that do not resolve to the specified DDNS hosts will be denied.

The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io).

## Installation

To install the `DDNSwhitelist` plugin, add the following configuration to your Traefik static configuration:

```yaml
experimental:
  plugins:
    ddnswhitelist:
      moduleName: "github.com/taskmedia/DDNSwhitelist"
      version: v1.0.0
```

## Configuration

Add the `DDNSwhitelist` middleware to your Traefik dynamic configuration:

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
        - ddnswhitelist-router

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    ddnswhitelist-router:
      plugin:
        ddnswhitelist:
          DdnsHostList:
            - my.router.ddns.tld
```
