# ngx_security_headers

This NGINX module adds security headers and removes insecure headers, *the right way* (c). 

[![Test Build](https://github.com/GetPageSpeed/ngx_security_headers/actions/workflows/build.yml/badge.svg?event=push)](https://github.com/GetPageSpeed/ngx_security_headers/actions/workflows/build.yml)

## Synopsis

```nginx
http {
    security_headers on;
    ...
}
```

Running `curl -IL https://example.com/` will yield the added security headers:

<pre>
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 21 May 2019 16:15:46 GMT
Content-Type: text/html; charset=UTF-8
Vary: Accept-Encoding
Accept-Ranges: bytes
Connection: keep-alive
<b>X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cross-Origin-Resource-Policy: same-site
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</b>
</pre>

In general, the module features sending security HTTP headers in a way that better conforms to the standards.
For instance, `Strict-Transport-Security` header should *not* be sent for plain HTTP requests.
The module follows this recommendation.

## Important note on `Strict-Transport-Security`

The module adds several security headers, including `Strinct-Transport-Security`.
Note that `preload` is sent in the value of this header, by default.
This means Chrome may and will include your websites to its preload list of domains which are HTTPS only.

It is *usually* what you want anyway, but bear in mind that in some edge cases you want to access
a subdomain via plan unencrypted connection.

If you absolutely sure that all your domains and subdomains used with the module will ever primarily operate
on HTTPs, proceed without any extra step.

If you are *not sure* if you have or will have a need to access your websites or any of its subdomains over
plain insecure HTTP protocol, ensure `security_headers_hsts_preload off;` in your config before you ever
start NGINX with the module to avoid having your domain preloaded by Chrome.

## Key Features

*   Plug-n-Play: the default set of security headers can be enabled with `security_headers on;` in your NGINX configuration
*   Sends HTML-only security headers for relevant types only, not sending for others, e.g. `X-Frame-Options` is useless for CSS
*   Plays well with conditional `GET` requests: the security headers are not included there unnecessarily
*   Does not suffer the `add_header` directive's pitfalls
*   Hides `X-Powered-By` and other headers which often leak software version information
*   Hides `Server` header altogether, not just the version information

## Configuration directives

### `security_headers`

- **syntax**: `security_headers on | off`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables or disables applying security headers. The default set includes:

* `X-Frame-Options: SAMEORIGIN`
* `Referrer-Policy: strict-origin-when-cross-origin`
* `X-Content-Type-Options: nosniff`
* `Cross-Origin-Resource-Policy: same-site`

The deprecated `X-XSS-Protection` header is actively removed by default.

The values of these headers (or their inclusion) can be controlled with other `security_headers_*` directives below.

### `hide_server_tokens`

- **syntax**: `hide_server_tokens on | off`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables hiding headers which leak software information:

*   `Server`
*   `X-Powered-By`
*   `X-Page-Speed`
*   `X-Varnish`

It's worth noting that some of those headers bear functional use, e.g. [`X-Page-Speed` docs](https://www.modpagespeed.com/doc/configuration#XHeaderValue) mention:

> ... it is used to prevent infinite loops and unnecessary rewrites when PageSpeed 
> fetches resources from an origin that also uses PageSpeed

So it's best to specify `hide_server_tokens on;` in a front-facing NGINX instances, e.g.
the one being accessed by actual browsers, and not the ones consumed by Varnish or other software.

In most cases you will be just fine with `security_headers on;` and `hide_server_tokens on;`, without any adjustments.

For fine-tuning, use the header-specific directives below. 
A special value `omit` disables sending a particular header by the module (useful if you want to let your backend app to send it). 

### `security_headers_xss`

- **syntax**: `security_headers_xss off | on | block | omit | unset`
- **default**: `unset`
- **context**: `http`, `server`, `location`

Controls `X-XSS-Protection` header.

* `unset` (default): Actively removes the header from responses, including any set by upstream servers. This is the recommended setting because the header is deprecated and [introduces XSS vulnerabilities](https://github.com/nicosalm/security-lab-xss-filter) in browsers that support it.
* `omit`: Does not add or remove the header; allows upstream headers through unchanged.
* `off`: Sends `X-XSS-Protection: 0` to explicitly disable browser XSS filtering.
* `on`: Sends `X-XSS-Protection: 1`.
* `block`: Sends `X-XSS-Protection: 1; mode=block`.

### `security_headers_frame`

- **syntax**: `security_headers_frame sameorigin | deny | omit`
- **default**: `sameorigin`
- **context**: `http`, `server`, `location`

Controls inclusion and value of `X-Frame-Options` header. 
Special `omit` value will disable sending the header by the module. 


### `security_headers_referrer_policy`

- **syntax**: `security_headers_referrer_policy no-referrer | no-referrer-when-downgrade | same-origin | origin 
| strict-origin | origin-when-cross-origin | strict-origin-when-cross-origin | unsafe-url | omit`
- **default**: `strict-origin-when-cross-origin`
- **context**: `http`, `server`, `location`

Controls inclusion and value of [`Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) header.
Special `omit` value will disable sending the header by the module.

### `security_headers_corp`

- **syntax**: `security_headers_corp same-site | same-origin | cross-origin | omit`
- **default**: `same-site`
- **context**: `http`, `server`, `location`

Controls inclusion and value of [`Cross-Origin-Resource-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy) header.
This header controls how your resources can be embedded by other origins.
Special `omit` value will disable sending the header by the module.

The default `same-site` is a safe choice that prevents cross-site embedding while allowing same-site requests.

### `security_headers_coop`

- **syntax**: `security_headers_coop same-origin | same-origin-allow-popups | unsafe-none | omit`
- **default**: `omit`
- **context**: `http`, `server`, `location`

Controls inclusion and value of [`Cross-Origin-Opener-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy) header.
This header controls window opener relationships across origins.
Special `omit` value will disable sending the header by the module.

The default is `omit` because enabling this header can break popup/window.opener communication patterns.
Enable explicitly only if you understand the implications.

### `security_headers_coep`

- **syntax**: `security_headers_coep require-corp | credentialless | unsafe-none | omit`
- **default**: `omit`
- **context**: `http`, `server`, `location`

Controls inclusion and value of [`Cross-Origin-Embedder-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy) header.
This header controls embedding of cross-origin resources.
Special `omit` value will disable sending the header by the module.

The default is `omit` because enabling this header can break sites that load third-party resources
(analytics, CDN assets, ads) without proper CORS headers.

### Cross-Origin Isolation

To enable [cross-origin isolation](https://web.dev/cross-origin-isolation-guide/) (required for `SharedArrayBuffer` and high-resolution timers),
configure all three cross-origin headers:

```nginx
security_headers on;
security_headers_corp same-origin;
security_headers_coop same-origin;
security_headers_coep require-corp;
```

**Warning**: This configuration will break loading of any cross-origin resources that don't explicitly allow it via CORS.

## Install

We highly recommend installing using packages, where available,
instead of compiling.

### Ubuntu and Debian packages

It's easy to install the module package for these operating systems.

`ngx_security headers` is part of the APT NGINX Extras collection, so you can install
it alongside [any modules](https://apt-nginx-extras.getpagespeed.com/modules/), 
including Brotli.

First, [set up the repository](https://apt-nginx-extras.getpagespeed.com/apt-setup/), then:

```bash
sudo apt-get update
sudo apt-get install nginx-module-security-headers
```

### CentOS/RHEL, Amazon Linux and Fedora packages

It's easy to install the module package for these operating systems.

`ngx_security headers` is part of the NGINX Extras collection, so you can install
it alongside [any modules](https://nginx-extras.getpagespeed.com/), 
including PageSpeed and Brotli.

```bash
sudo yum -y install https://extras.getpagespeed.com/release-latest.rpm
sudo yum -y install nginx-module-security-headers
```


Then add it at the top of your `nginx.conf`:

```nginx
load_module modules/ngx_http_security_headers_module.so;
```
    
In case you use ModSecurity NGINX module, make sure it's loaded last, like so:

```nginx
load_module modules/ngx_http_security_headers_module.so;
load_module modules/ngx_http_modsecurity_module.so;
```

### Other platforms

Compiling NGINX modules is [prone to many problems](https://www.getpagespeed.com/server-setup/where-compilation-went-wrong), 
including making your website insecure. Be sure to keep your NGINX and modules updated, if you go that route.

To compile the module into NGINX, run:

```bash
./configure --with-compat --add-module=../ngx_security_headers
make 
make install
```

Or you can compile it as dynamic module. In that case, use `--add-dynamic-module` instead, and load the module after 
compilation by adding to `nginx.conf`:

```nginx
load_module /path/to/ngx_http_security_headers_module.so;
```
