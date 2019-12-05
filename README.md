# ngx_security_headers

This NGINX module adds security headers and removes insecure headers easily. 

## Synopsis

```
http {
    security_headers on;
    ...
}
```

Running `curl -IL http://example.com/` will yield additional headers:

```
HTTP/1.1 200 OK
Server: nginx
Date: Tue, 21 May 2019 16:15:46 GMT
Content-Type: text/html; charset=UTF-8
Vary: Accept-Encoding
Accept-Ranges: bytes
Connection: keep-alive
X-Frame-Options: SAMEORIGIN  <-----------
X-XSS-Protection: 1; mode=block <-----------
Referrer-Policy: no-referrer-when-downgrade <-----------
```

Running `curl -IL http://example.com/some.css` (or `some.js`) will yield *additional* security header:

```
HTTP/1.1 200 OK
...
X-Content-Type-Options: nosniff <-----------
```


## Key Features

* Plug-n-Play: the default set of security headers can be enabled with `security_headers on;` in your NGINX configuration
* Sends `X-Content-Type-Options` only for appropriate MIME types, preserving unnecessary bits from being transferred for non-JS and non-CSS resources
* Plays well with conditional `GET` requests: the security headers are not included there unnecessarily
* Does not suffer the `add_header` directive's pitfalls
* Hides `X-Powered-By`, which often leaks PHP version information
* Hides `Server` header altogether, not just the version information

## Configuration directives

### `security_headers`

- **syntax**: `security_headers on | off`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables or disables applying security headers. The default set includes:

* `X-Frame-Options: SAMEORIGIN`
* `X-XSS-Protection: 1; mode=block`
* `Referrer-Policy: strict-origin-when-cross-origin`
* `X-Content-Type-Options: nosniff` (for CSS and Javascript)

The values of these headers (or their inclusion) can be controlled with other `security_headers_*` directives below.

### `hide_server_tokens`

- **syntax**: `hide_server_tokens on | off`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables hiding headers which leak software information:

* `Server`
* `X-Powered-By`

Next are the common security headers being set. It's worth noting that special value of `omit` for directives below
will disable sending a particular header by the module (useful if you want to let your backend app to send it). 

### `security_headers_xss`

- **syntax**: `security_headers off | on | block | omit`
- **default**: `block`
- **context**: `http`, `server`, `location`

Controls `X-XSS-Protection` header. 
Special `omit` value will disable sending the header by the module. 
The `off` value is for disabling XSS protection: `X-XSS-Protection: 0`.

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

### `security_headers_nosniff_types`

- **syntax**: `security_headers_nosniff_types <mime_type> [..]`
- **default**: `text/css text/javascript application/javascript`
- **context**: `http`, `server`, `location`

Defines MIME types, for which `X-Content-Type-Options: nosniff` is sent.

## Install

### CentOS 7

It's easy to install the module in your stable nginx instance dynamically:

    yum -y install https://extras.getpagespeed.com/release-el7-latest.rpm
    yum -y install nginx-module-security-headers

Then add it at the top of your `nginx.conf`:

    load_module modules/ngx_http_security_headers_module.so;
    
In case you use ModSecurity NGINX module, make sure it's loaded last, like so:

    load_module modules/ngx_http_security_headers_module.so;
    load_module modules/ngx_http_modsecurity_module.so;

### Other platforms

To compile the module into NGINX, run:

    ./configure --add-module=../ngx_security_headers
    make 
    make install

Or you can compile it as dynamic module. In that case, use `--add-dynamic-module` instead, and load the module after compilation via:

    load_module modules/ngx_http_security_headers_module.so;
