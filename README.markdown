Name
====

lua-shared-dict - replacement for lua_shared_dict standart openresty module.

Status
======

This library is production ready.

Description
===========

This module replaces internal representation and operations lua shared dictionary.  
Shared dictionary LUA C api fully rewrited and extended with ZSET operations and function callbacks.

Important notice
================

Structure `ngx_lua_shm_zone_ctx_t` MUST be absolutely matched to standard structure ngx_http_lua_shm_zone_ctx_t (ngx_stream_lua_shm_zone_ctx_t).

For FFI compatibility next structures in `ngx_lua_shdict_defs.h` MUST be matched to structures defined in standard lua-nginx-module (stream-lua-nginx-module):

- ngx_lua_shdict_node_t
- ngx_lua_shdict_list_node_t
- ngx_lua_shdict_shctx_t (head fields)

Additional API
==============

zset
----
**syntax:** `ok, err = ngx.shared.DICT:zset(key, zkey, val, exptime)`  
**syntax:** `ok, err = ngx.shared.DICT:zset(key, zkey, fun(old_val), exptime)`

Parameter `fun` must return new value or nil to remove zkey.  
Returns true on success, or nil and a string describing an error otherwise.

zadd
----
**syntax:** `ok, err = ngx.shared.DICT:zadd(key, zkey, val, exptime)`  
**syntax:** `ok, err = ngx.shared.DICT:zadd(key, zkey, fun(), exptime)`s

Parameter `fun` must return new value.  
Returns true on success, or nil and a string describing an error otherwise.

zrem
----
**syntax:** `val, err = ngx.shared.DICT:zrem(key, zkey)`
 
Returns removed value on success, or nil and a string describing an error otherwise.

zget
----
**syntax:** `val, err = ngx.shared.DICT:zget(key, zkey)`

Returns value on success, or nil and a string describing an error otherwise.

zgetall
-------
**syntax:** `tab, err = ngx.shared.DICT:zgetall(key)`

Returns table with { key, val } on success, or nil and a string describing an error otherwise.

zcard
-----
**syntax:** `count, err = ngx.shared.DICT:zcard(key)`

Returns zset items count, or nil and a string describing an error otherwise.

zscan
-----
**syntax:** `ok, err = ngx.shared.DICT:zscan(key, fun(zkey, val))`  
**syntax:** `ok, err = ngx.shared.DICT:zscan(key, fun(zkey, val), lbound)`

Scans zset key.  
On every step function callback MUST returns boolean flag. If zscan must be stopped return value must be `true`.  

Example:
```
ngx.shared.DICT:zscan("key", function(k,v)
  if not k:match("^a") then
    return true
  end
  ...
  return false
end, "a")
```

Scan started from zkey begins from symbol 'a' and stops if callback returns true.  

Returns true on success, or nil and a string describing an error otherwise.

fun
---
**syntax:** `new_val, new_flags = ngx.shared.DICT:fun(key, fun(zkey, val), exptime, flags)`



Example:
```
local new_val, new_flags = ngx.shared.DICT:fun("key", function(old_val, old_flags)
  return new_val, new_flags
end)
```

If `new_val` is nil, then key is removed from dictionary.  

Returns new_val and new_flags on success, or nil and a string describing an error otherwise.
