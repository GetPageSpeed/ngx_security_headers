use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: dying on bad config
--- http_config
    security_headers bad;
--- config
--- must_die
--- error_log
invalid value "bad" in "security_headers" directive, it must be "on" or "off"