# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

env_to_nginx("SHDICT_RWLOCK");

#worker_connections(1014);
#master_process_enabled(1);
#log_level('warn');

repeat_each(1);

plan tests => repeat_each() * (blocks() * 3 + 0);

#no_diff();
no_long_string();
#master_on();
#workers(2);

run_tests();

__DATA__

=== TEST 1: fun exptime + get_stale
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local val, flags = dogs:fun("foo", function(val, flags)
              return "hello", 999 
            end, 0.1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end
            
            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            ngx.sleep(1)

            local val, flags = dogs:get_stale("foo")
            if val then
                 ngx.say("ok")
            else
                 ngx.say("error")
            end

            local val, flags = dogs:get("foo")
            if val then
                 ngx.say("ok")
            else
                 ngx.say("error")
            end
        }
    }
--- request
GET /test
--- response_body
val=hello flags=999
val=hello flags=999
ok
ok
--- no_error_log
[error]


=== TEST 2: fun replace value
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local val, flags = dogs:fun("foo", function(val, flags)
              return "hello", 999 
            end, 1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end
            
            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            local val, flags = dogs:fun("foo", function(val, flags)
              return "hellohello", 999999 
            end, 1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end

            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            local val, flags = dogs:fun("foo", function(val, flags)
              return 123456, 654321 
            end, 1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end

            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            local val, flags = dogs:fun("foo", function(val, flags)
              return true, 9 
            end, 1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end

            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            local val, flags = dogs:fun("foo", function(val, flags)
              return "hello", 999 
            end, 1)
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("fun err: ", flags)
            end
            
            local val, flags = dogs:get("foo")
            if val then
                ngx.say("val=", val, " flags=", flags)
            else
                ngx.say("get err: ", flags)
            end

            dogs:delete("foo");
        }
    }
--- request
GET /test
--- response_body
val=hello flags=999
val=hello flags=999
val=hellohello flags=999999
val=hellohello flags=999999
val=123456 flags=654321
val=123456 flags=654321
val=true flags=9
val=true flags=9
val=hello flags=999
val=hello flags=999
--- no_error_log
[error]


=== TEST 3: fun nil
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            dogs:fun("foo", function(val, flags)
              return nil, 0
            end, 0.1)

            dogs:fun("foo", function(val, flags)
              return nil, 0
            end, 0.1)

            dogs:fun("foo", function(val, flags)
              return "ok", 0
            end, 0.1)

            local v = dogs:get("foo")
            ngx.say(v)
        }
    }
--- request
GET /test
--- response_body
ok
--- no_error_log
[error]