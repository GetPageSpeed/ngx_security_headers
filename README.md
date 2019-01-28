# ngx_security_headers

This NGINX module adds security headers and removes insecure headers easily. 

## Synopsis

```
http {
    security_headers on;
    ...
}
```

## Key Features

* Plug-n-Play: the default set of security headers can be enabled with `security_headers on;` in your NGINX configuration
* Sends `X-Content-Type-Options` only for appropriate MIME types, preserving unnecessary bits from being transferred for non-JS and non-CSS resources
* Plays well with conditional `GET` requests: the security headers are not included there unnecessarily
* Hides `X-Powered-By`, which often leaks PHP version information
* Does not suffer the `add_header` directive's pitfalls
* Hides `Server` header altogether, not just the version information

## Configuration directives

### `security_headers`

- **syntax**: `security_headers on | off`
- **default**: `off`
- **context**: `http`, `server`, `location`

Enables or disables applying security headers. The default set includes:

* `X-Frame-Options: SAMEORIGIN`
* `X-XSS-Protection: 1; mode=block`
* `X-Content-Type-Options: nosniff` (for CSS and Javascript)

Headers which are hidden:

* `X-Powered-By`
* `Server`

### `security_headers_xss`

- **syntax**: `security_headers off | on | block | omit`
- **default**: `block`
- **context**: `http`, `server`, `location`

Controls `X-XSS-Protection` header. 
Special `omit` value will disable sending the header. 
The `off` value is for disabling XSS protection: `X-XSS-Protection: 0`.

### `security_headers_frame`

- **syntax**: `security_headers_frames sameorigin | deny | omit`
- **default**: `sameorigin`
- **context**: `http`, `server`, `location`

Controls inclusion and value of `X-Frame-Options` header. 
Special `omit` value will disable sending the header. 

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

### Other platforms

To compile the module into NGINX, run:

    ./configure --add-module=../ngx_security_headers
    make 
    make install

Or you can compile it as dynamic module. In that case, use `--add-dynamic-module` instead, and load the module after compilation via:

    load_module modules/ngx_http_security_headers_module.so;