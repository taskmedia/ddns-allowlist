# DDNS allowlist - Traefik plugin

Dynamic DNS allowlist plugin for [Traefik](https://doc.traefik.io/traefik): Add your dynamic hostname (your homenetwork router) to the allow list.

Have a look at the official [Traefik Plugin Catalog](https://plugins.traefik.io/plugins/66fef7d4573cd7803d65cb12/ddns-allowlist).
We would love if you leave a star on this repository.

## About

The `ddns-allowlist` plugin for Traefik allows you to add dynamic DNS (DDNS) hosts to the allowed requesters.
Requests from IP addresses that do not resolve to the specified DDNS hosts will be denied.
You might also know this as [whitelist](https://inclusivenaming.org/word-lists/tier-1/whitelist/) instead of allowlist.

The initial idea is that you can add your home router with a floating (non-static) IP address to an allowed list of addresses.
You are not limited to your DDNS supporting router - you can add any host you like.
If you want so it is more likely a hostname allowlist.

The basic concept is to periodically resolve the hostname to an IP address and add it to the allowlist.
Because server typically have a static IP, you should add its static IPs to the allowlist (`sourceRangeIps`).

:warning: IPv6 is supported but e.g. with FritzBox router you maybe have some issues because the IPv6 address your router provides is not the same as the network prefix of your network.

## Installation

The installation of a [Traefik plugin](https://doc.traefik.io/traefik/plugins/) is pretty simple.
To install the `ddns-allowlist` plugin follow one of the following methods.

### Traefik CLI

First way to add the plugin is to add the following CLI options to your Traefik setup:

```bash
--experimental.plugins.ddns-allowlist.modulename=github.com/taskmedia/ddns-allowlist
--experimental.plugins.ddns-allowlist.version=v1.6.1
```

### yaml / Traefik Helm chart

Another way to add the plugin is to add the following configuration to your Traefik static configuration / Helm chart:

```yaml
experimental:
  plugins:
    ddns-allowlist:
      moduleName: "github.com/taskmedia/ddns-allowlist"
      version: v1.6.1
```

## Configuration

You also need to create a middleware and add it to one of your routes.
There are multiple ways to do this - this document will show you how to configure the plugin with [dynamic configuration](#dynamic-configuration) and [Kubernetes CRD](#kubernetes-crd).

But first we will have a look about the configuration options available for the plugin.

### Available options

Only mandatory option is `sourceRangeHosts` - all other options are optional.

- **`sourceRangeHosts`** (required)<br />
  Hosts to dynamically add to allowlist via DNS lookup
- **`sourceRangeIps`**<br />
  Additional IP addresses to add to allowlist
- **`ipStrategy.*`**<br />
  Strategy to determine the client IP address - see configurations below.
  If no strategy is specified (or value is zero), the plugin will use the `RemoteAddr` as default.
- **`ipStrategy.cloudflareDepth`**<br />
  Use Cloudflare headers (`Cf-Connecting-Ip`) to determine the client IP address.
  The cloudflareDepth option expects an integer to determ which IP address should be used (starting from the right).
- **`ipStrategy.depth`**<br />
  Use headers (`X-Forwarded-For`) to determine the client IP address.
  The depth option expects an integer to determ which IP address should be used (starting from the right).
- **`ipStrategy.excludedIPs`**<br />
  Will return the first IP address that is not in the excluded list (also uses `X-Forwarded-For` header).
- **`rejectStatusCode`**<br />
  Status code to return if the request is rejected (default: 403)
- **`logLevel`**<br />
  Log level for the plugin (allowed: ERROR, INFO, DEBUG, TRACE - default: ERROR)
- **`lookupInterval`**<br />
  Lookup interval for DNS hosts in seconds (default: 5 min)
- **`allowedIPv6NetworkPrefix`**<br />
  Allow any interface identifier based on given prefix from the looked up sourceRangeHosts IPv6 addresses (default: disabled)

_Hint: You can only choose one of the ip strategy options. It is not possible to combine multiple.
The strategies are similar to the one provided with middleware [IPWhiteList](https://doc.traefik.io/traefik/middlewares/http/ipwhitelist/#ipstrategydepth)._

### Configuration examples

#### Dynamic configuration

Add the `ddns-allowlist` middleware to your Traefik dynamic configuration:

<details open>
<summary>dynamic configuration</summary>

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
        my-ddnswl:
          # optional: log level for the plugin (allowed: ERROR, INFO, DEBUG, TRACE - default: ERROR)
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

</details>

#### Kubernetes CRD

<details open>
<summary>Kubernetes CRD configuration</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: my-ddnswl
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      # see other options in dynamic configuration or in section 'Available options'
```

Also see more detailed in the [examples section](#examples).

</details>

## Examples

This section contains example configurations for the `ddns-allowlist` plugin.
The examples are provided as in Kubernetes CRD but also can be defined in other formats.
You need to expand the configuration example in each section on the triangle.

It shows different common configuration options.
Keep note that the IP strategies can not be combined with each other.

The following examples are alphabetically sorted and not according to the frequency of use.

### Allowed IPv6 network prefix

When using IPv6 your home router will report its full address to the DDNS provider.
This address contains the network prefix and the interface identifier.
When an device inside your network tries to access your service it will be rejected because the interface identifier is not the same as the one from your router.
With this option you can allow any interface identifier based on the given prefix from the looked up sourceRangeHosts IPv6 addresses.

The common value used for that is `64`.
This is the common value which splits the address into network prefix and interface identifier.
If your routers DNS lookup resolves in IP address `aaaa:bbbb:cccc:dddd:1111:2222:3333:4444`, the addresses in network `aaaa:bbbb:cccc:dddd::/64` will be allowed.

<details>
<summary>example: Allowed IPv6 network prefix</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      allowedIPv6NetworkPrefix: 64
```

</details>

### Cloudflare - DNS only

If you are using [Cloudflare](https://cloudflare.com) as DNS nameserver ([without proxy](https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/)), you need to use the default configuration using `RemoteAddr` (no IP strategy required in plugin config).

Also see [RemoteAddr](#remoteaddr) example.

<details>
<summary>example: Cloudflare - DNS only</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-cloudflare-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
```

</details>

### Cloudflare - proxy

If you are using [Cloudflare](https://cloudflare.com) as DNS nameserver ([with proxy](https://developers.cloudflare.com/dns/manage-dns-records/reference/proxied-dns-records/)), you need to get the IP address of the client from the `Cf-Connecting-Ip` header.
Therefore use the `cloudflareDepth` configuration option.

Usually the header only contains one IP address - so you can use `1` as value.
To ensure the same implementation as in `ipStrategy.depth` you are allowed to specify a higher value.
But this configuration should not be necessary.

<details>
<summary>example: Cloudflare - proxy</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-cloudflare-proxy
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      ipStrategy:
        cloudflareDepth: 1
```

</details>

### Excluded IPs

If you want to get the client IP address from the `X-Forwarded-For` header but exclude some IPs from the list (eg. your reverse proxies), you can use the `excludedIPs` option.
This will allow you to exclude some IPs from the list and return the first IP address that is not in the excluded list.

<details>
<summary>example: Excluded IPs</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-excludeips
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      ipStrategy:
        excludedIPs:
          - 1.2.3.4
```

</details>

### Log level

If you want to see more logs from the plugin, you can set the log level to a more detailed level.
The allowed values are `ERROR` (default), `INFO`, `DEBUG`, `TRACE`.

<details>
<summary>example: Log level</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      logLevel: DEBUG
```

</details>

### Lookup interval

If you want to change the lookup interval for DNS hosts, you can set the `lookupInterval` option.
The default value is `300` seconds (5 minutes).

The lookup will only happen if the middleware is triggered from a new client request.

<details>
<summary>example: Lookup interval</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      lookupInterval: 30 # seconds
```

</details>

### Rejection code

If you feel more like a [tea pot](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/418) feel free to change the rejection code:

<details>
<summary>example: Rejection code</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      rejectStatusCode: 418
```

</details>

### RemoteAddr

If you are not using any proxy in front of your Traefik instance, you can just use the `RemoteAddr` as default IP strategy.
You only need to specify a host to be allowlisted.

<details>
<summary>example: RemoteAddr</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
```

</details>

### Sourcerange IPs

If you want to add additional IP addresses to the allowlist (e.g. a server), you can use the `sourceRangeIps` option.
This might also be interesting to add your static IPv6 address (network prefix).

You are not only able to add IPv4 addresses but also IPv6 addresses.
Also it is possible to add an IP range (CIDR notation) to the list.

Keep note that you always need to specify a source range host.

<details>
<summary>example: Sourcerange IPs</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      sourceRangeIps:
        - "1.2.3.4"
        - "192.168.1.0/24"
        - "2a02:aaaa:bbbb:cccc::/64"
```

</details>

### X-Forwarded-For

If you are using a reverse proxy in front of your Traefik instance, you can use the `X-Forwarded-For` header to determine the client IP address.
You can specify the depth of the IP address in the header to use.
The default value is `1` and will select the first IP address from the header (position starting from the right).

You are not able to specify a depth of 0 - otherwise the RemoteAddr method (default) will be used.

<details>
<summary>example: X-Forwarded-For</summary>

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: ddnswl-dnsonly
spec:
  plugin:
    ddns-allowlist:
      sourceRangeHosts:
        - my.router.ddns.tld
      ipStrategy:
        depth: 1
```

</details>
