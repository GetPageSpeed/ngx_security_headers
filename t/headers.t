use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: server is hidden
--- config
    security_headers on;
    hide_server_tokens on;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
!Server



=== TEST 2: basic security headers (default xss is unset)
--- config
    security_headers on;
    charset utf-8;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
content-type: text/plain; charset=utf-8
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
!x-xss-protection



=== TEST 3: nosniff for css
--- config
    security_headers on;
    location = /hello.css {
        default_type text/css;
        return 200 "hello world\n";
    }
--- request
    GET /hello.css
--- response_body
hello world
--- response_headers
content-type: text/css
x-content-type-options: nosniff



=== TEST 4: proxied ok
--- config
    location = /hello {
        add_header x-frame-options SAMEORIGIN1;
        return 200 "hello world\n";
    }
    location = /hello-proxied {
        security_headers on;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/hello;
    }
--- request
    GET /hello-proxied
--- response_body
hello world
--- response_headers
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
!server



=== TEST 5: simple failure
--- config
    hide_server_tokens on;
    location = /hello {
        security_headers on;
        add_header via fakeengine;

        return 200 "hello world\n";
    }
    location = /hello-proxied {
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/hello;
    }
--- request
    GET /hello-proxied
--- response_body
hello world
--- response_headers
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
!Server
!Via
Referrer-Policy: strict-origin-when-cross-origin



=== TEST 6: custom referrer-policy
--- config
    security_headers on;
    security_headers_referrer_policy unsafe-url;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
!x-xss-protection
referrer-policy: unsafe-url



=== TEST 7: co-exist with add header for custom referrer-policy
--- config
    security_headers on;
    security_headers_referrer_policy omit;

    location = /hello {
        return 200 "hello world\n";
        add_header 'Referrer-Policy' 'origin';
    }
    location = /hello-proxied {
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/hello;
    }
--- request
    GET /hello-proxied
--- response_body
hello world
--- response_headers
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
!x-xss-protection
referrer-policy: origin



=== TEST 8: X-Frame-Options should not be sent for CSS (even when encoding specified)
--- config
    security_headers on;
    charset utf-8;
    charset_types text/css;
    location = /hello.css {
        default_type "text/css";
        return 200 "hello world\n";
    }
--- request
    GET /hello.css
--- response_body
hello world
--- response_headers
content-type: text/css; charset=utf-8
!x-frame-options



=== TEST 9: hides common powered-by headers
--- config
    location = /hello {
        security_headers on;

        add_header X-Powered-By "PHP/8.2";
        add_header X-Generator "WordPress 6.5";
        add_header X-Jenkins "2.440";
        add_header X-Something-Custom "Visible";
        return 200 "hello world\n";
    }
--- request
GET /hello
--- response_body
hello world
--- response_headers
!x-powered-by
!x-generator
!x-jenkins
x-something-custom: Visible



=== TEST 10: headers are visible when security_headers is off
--- config
    location = /hello {
        # security_headers off (по умолчанию)
        add_header X-Powered-By "PHP/8.2";
        add_header X-Generator "WordPress";
        return 200 "hello world\n";
    }
--- request
GET /hello
--- response_body
hello world
--- response_headers
x-powered-by: PHP/8.2
x-generator: WordPress



=== TEST 11: only hide server header
--- config
    hide_server_tokens on;
    location = /hello {
        add_header Server "nginx";
        add_header X-Powered-By "PHP";
        add_header X-Generator "Drupal";
        return 200 "hello world\n";
    }
--- request
GET /hello
--- response_body
hello world
--- response_headers
!server
x-powered-by: PHP
x-generator: Drupal



=== TEST 12: CORP default is same-site when security_headers on
--- config
    security_headers on;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Resource-Policy: same-site



=== TEST 13: CORP same-origin
--- config
    security_headers on;
    security_headers_corp same-origin;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Resource-Policy: same-origin



=== TEST 14: CORP cross-origin
--- config
    security_headers on;
    security_headers_corp cross-origin;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Resource-Policy: cross-origin



=== TEST 15: CORP omit
--- config
    security_headers on;
    security_headers_corp omit;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
!Cross-Origin-Resource-Policy



=== TEST 16: COOP default is omit
--- config
    security_headers on;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
!Cross-Origin-Opener-Policy



=== TEST 17: COOP same-origin
--- config
    security_headers on;
    security_headers_coop same-origin;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Opener-Policy: same-origin



=== TEST 18: COOP same-origin-allow-popups
--- config
    security_headers on;
    security_headers_coop same-origin-allow-popups;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Opener-Policy: same-origin-allow-popups



=== TEST 19: COOP unsafe-none
--- config
    security_headers on;
    security_headers_coop unsafe-none;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Opener-Policy: unsafe-none



=== TEST 20: COEP default is omit
--- config
    security_headers on;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
!Cross-Origin-Embedder-Policy



=== TEST 21: COEP require-corp
--- config
    security_headers on;
    security_headers_coep require-corp;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Embedder-Policy: require-corp



=== TEST 22: COEP credentialless
--- config
    security_headers on;
    security_headers_coep credentialless;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Embedder-Policy: credentialless



=== TEST 23: COEP unsafe-none
--- config
    security_headers on;
    security_headers_coep unsafe-none;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Embedder-Policy: unsafe-none



=== TEST 24: Full cross-origin isolation
--- config
    security_headers on;
    security_headers_corp same-origin;
    security_headers_coop same-origin;
    security_headers_coep require-corp;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp



=== TEST 25: XSS unset removes header from upstream
--- config
    location = /hello {
        add_header X-XSS-Protection "1; mode=block";
        return 200 "hello world\n";
    }
    location = /hello-proxied {
        security_headers on;
        security_headers_xss unset;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/hello;
    }
--- request
    GET /hello-proxied
--- response_body
hello world
--- response_headers
!x-xss-protection



=== TEST 26: XSS omit allows upstream header through
--- config
    location = /hello {
        add_header X-XSS-Protection "1; mode=block";
        return 200 "hello world\n";
    }
    location = /hello-proxied {
        security_headers on;
        security_headers_xss omit;
        proxy_buffering off;
        proxy_pass http://127.0.0.1:$TEST_NGINX_SERVER_PORT/hello;
    }
--- request
    GET /hello-proxied
--- response_body
hello world
--- response_headers
x-xss-protection: 1; mode=block



=== TEST 27: XSS off still sends header value 0
--- config
    security_headers on;
    security_headers_xss off;
    location = /hello {
        return 200 "hello world\n";
    }
--- request
    GET /hello
--- response_body
hello world
--- response_headers
x-xss-protection: 0