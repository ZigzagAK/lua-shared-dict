# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(2);

plan tests => repeat_each() * (blocks() * 3 + 0);

#no_diff();
no_long_string();
#master_on();
#workers(2);

run_tests();

__DATA__


=== TEST 1: ttl
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location /test {
        content_by_lua_block {
          local dogs = ngx.shared.dogs
          dogs:set("x", 1, 10)
          ngx.say(dogs:ttl("x"))
          dogs:expire("x", 0)
          ngx.say(dogs:ttl("x"))
          dogs:expire("x", 10.5)
          ngx.say(dogs:ttl("x"))
          dogs:expire("x", 0)
          ngx.say(dogs:ttl("x"))
        }
    }
--- request
    GET /test
--- response_body
10
0
10.5
0
--- no_error_log
[error]
