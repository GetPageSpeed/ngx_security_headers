use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: server is hidden
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
!Server


=== TEST 2: x-xss-protection added
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
X-XSS-Protection: 1; mode=block