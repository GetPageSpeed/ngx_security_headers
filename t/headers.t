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



=== TEST 2: no nosniff for html
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
x-xss-protection: 0



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
x-xss-protection: 0
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
x-xss-protection: 0
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