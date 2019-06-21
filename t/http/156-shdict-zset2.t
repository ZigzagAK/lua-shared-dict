# vim:set ft= ts=4 sw=4 et fdm=marker:
use Test::Nginx::Socket::Lua;

env_to_nginx("SHDICT_RWLOCK");

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

=== TEST 1: zset -> set -> expire -> zset -> delete same key
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local space = dogs:free_space()

            local ok, err = dogs:zset("foo", "bar", "hello")
            if not ok then
               ngx.say("zset err: ", err)
            end
            
            local zkey, val = dogs:zget("foo", "bar")
            if zkey then
               ngx.say(val)
            else
               ngx.say("zget err: ", val)
            end

            local ok, err = dogs:set("foo", "hellohello")
            if not ok then
               ngx.say("set err: ", err)
            end

            local val, flags = dogs:get("foo")
            if val then
               ngx.say(val)
            else
               ngx.say("get err: ", flags)
            end

            local ok, err = dogs:expire("foo", 0.1)
            if not ok then
               ngx.say("expire err: ", err)
            end
            
            ngx.sleep(1)

            local ok, err = dogs:zset("foo", "bar", "hello")
            if not ok then
               ngx.say("zset err: ", err)
            end
            
            local zkey, val = dogs:zget("foo", "bar")
            if zkey then
               ngx.say(val)
            else
               ngx.say("zget err: ", val)
            end

            dogs:delete("foo")

            ngx.say(space - dogs:free_space())
        }
    }
--- request
GET /test
--- response_body
hello
hellohello
hello
0
--- no_error_log
[error]


=== TEST 2: zset with fun
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            for i=1,10 do
              local ok, err = dogs:zset("foo", "bar", function(old)
                old = old or 0
                return old + 1
              end, 0.5)
              if not ok then
                 ngx.say("zset err: ", err)
              end
              local zkey, val = dogs:zget("foo", "bar")
              if zkey then
                 ngx.say(val)
              else
                 ngx.say("zget err: ", val)
              end
            end

            ngx.sleep(1)

            if not dogs:zget("foo", "bar") then
               ngx.say("ok")
            else
               ngx.say("zget exists")
            end
        }
    }
--- request
GET /test
--- response_body
1
2
3
4
5
6
7
8
9
10
ok
--- no_error_log
[error]


=== TEST 3: zset ngx.null
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local ok, err = dogs:zset("foo", "bar", ngx.null, 0.5)
            if ok then
               ngx.say("ok")
            else
               ngx.say("zset err: ", err)
            end
            local zkey, val = dogs:zget("foo", "bar")
            if zkey and val == ngx.null then
               ngx.say("ok")
            else
               ngx.say("zget err: ", val)
            end

            ngx.sleep(1)

            if not dogs:zget("foo", "bar") then
               ngx.say("ok")
            else
               ngx.say("zget exists")
            end
        }
    }
--- request
GET /test
--- response_body
ok
ok
ok
--- no_error_log
[error]


=== TEST 4: delete with zset
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local ok, err = dogs:zset("foo", "bar", ngx.null)
            if ok then
               ngx.say("ok")
            else
               ngx.say("zset err: ", err)
            end
            local zkey, val = dogs:zget("foo", "bar")
            if zkey and val == ngx.null then
               ngx.say("ok")
            else
               ngx.say("zget err: ", val)
            end
            local ok, err = dogs:zset("foo", "bar", function(old)
              return nil
            end)
            if ok then
               ngx.say("ok")
            else
               ngx.say("zset err: ", err)
            end
            local zkey, val = dogs:zget("foo", "bar")
            if not zkey and not val then
               ngx.say("ok")
            else
               ngx.say("zget err: ", zkey, " ", val)
            end
        }
    }
--- request
GET /test
--- response_body
ok
ok
ok
ok
--- no_error_log
[error]


=== TEST 5: try delete from zset with fun not existing key
--- http_config
    lua_shared_dict dogs 1m;
--- config
    location = /test {
        content_by_lua_block {
            local dogs = ngx.shared.dogs

            local ok, err = dogs:zset("foo", "bar", function(old)
              return nil
            end)
            if ok then
               ngx.say("ok")
            else
               ngx.say("zset err: ", err)
            end
        }
    }
--- request
GET /test
--- response_body
ok
--- no_error_log
[error]