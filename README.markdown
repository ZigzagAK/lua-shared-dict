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

Also this module export shared dictionary C API, which may be uset in C modules.

This module tested with:

- lua-nginx-module: v0.10.15rc1
- stream-lua-nginx-module: v0.0.7rc1

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

C API
=====

**ngx_lua_shdict.h:**

```
ngx_shm_zone_t *
ngx_http_lua_add_shared_dict(ngx_conf_t *cf,
    ngx_str_t name, ngx_str_t size);

ngx_shm_zone_t *
ngx_stream_lua_add_shared_dict(ngx_conf_t *cf,
    ngx_str_t name, ngx_str_t size);

ngx_shm_zone_t *ngx_lua_find_zone(u_char *name_data, size_t name_len);

ngx_shm_zone_t *
ngx_lua_ffi_shdict_udata_to_zone(void *zone_udata);

void ngx_lua_shdict_lock(ngx_shm_zone_t *shm_zone);

void ngx_lua_shdict_unlock(ngx_shm_zone_t *shm_zone);

int
ngx_lua_shdict_expire_items(ngx_shm_zone_t *shm_zone, ngx_uint_t n);

ngx_int_t ngx_lua_shdict_api_used(ngx_shm_zone_t *shm_zone);

typedef ngx_int_t (*ngx_lua_get_fun_t)(ngx_lua_value_t *value,
    int stale, void *userctx);

ngx_int_t ngx_lua_shdict_api_fun(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_get_fun_t fun, int64_t exptime,
        void *userctx);

ngx_int_t ngx_lua_shdict_api_fun_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_get_fun_t fun, int64_t exptime,
        void *userctx);

/* copying structure into value */
ngx_int_t ngx_lua_shdict_api_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

/* value contents the reference (string/userdata) to data */
ngx_int_t ngx_lua_shdict_api_get_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

lua_Number ngx_lua_shdict_api_incr(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime);

lua_Number ngx_lua_shdict_api_incr_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime);

ngx_int_t ngx_lua_shdict_api_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_safe_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_safe_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_safe_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_safe_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_replace(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_replace_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime);

ngx_int_t ngx_lua_shdict_api_delete(ngx_shm_zone_t *shm_zone,
    ngx_str_t key);

ngx_int_t ngx_lua_shdict_api_delete_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key);

ngx_int_t ngx_lua_shdict_api_expire(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime);

ngx_int_t ngx_lua_shdict_api_expire_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime);

ngx_int_t ngx_lua_shdict_api_ttl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl);

ngx_int_t ngx_lua_shdict_api_ttl_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl);

ngx_int_t ngx_lua_shdict_api_rps(ngx_shm_zone_t *shm_zone,
    uint32_t *count, uint32_t *rps);

/* zset */

typedef void (*ngx_lua_zset_destructor_t)(void *p, size_t len);

ngx_int_t ngx_lua_shdict_api_zset(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t value, int exptime,
        ngx_lua_zset_destructor_t onfree);

ngx_int_t ngx_lua_shdict_api_zset_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t value, int exptime,
        ngx_lua_zset_destructor_t onfree);

/* copying structure into value */
ngx_int_t ngx_lua_shdict_api_zget(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t *value);

/* value contents the reference (string/userdata) to data */
ngx_int_t ngx_lua_shdict_api_zget_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t *value);

ngx_int_t ngx_lua_shdict_api_zadd(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t value, int exptime,
        ngx_lua_zset_destructor_t onfree);

ngx_int_t ngx_lua_shdict_api_zadd_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t value, int exptime,
        ngx_lua_zset_destructor_t onfree);

typedef ngx_int_t (*ngx_http_fun_t)(ngx_str_t zkey, ngx_lua_value_t *value,
    void *userctx);

ngx_int_t ngx_lua_shdict_api_zscan(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_fun_t fun, ngx_str_t lbound, void *userctx);

ngx_int_t ngx_lua_shdict_api_zscan_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_fun_t fun, ngx_str_t lbound, void *userctx);

ngx_int_t ngx_lua_shdict_api_zrem(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey);

ngx_int_t ngx_lua_shdict_api_zrem_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey);

ngx_int_t ngx_lua_shdict_api_zcard(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

ngx_int_t ngx_lua_shdict_api_zcard_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

/* queue */

ngx_int_t ngx_lua_shdict_api_rpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value);

ngx_int_t ngx_lua_shdict_api_rpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value);

ngx_int_t ngx_lua_shdict_api_lpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value);

ngx_int_t ngx_lua_shdict_api_lpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value);

ngx_int_t ngx_lua_shdict_api_rpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

ngx_int_t ngx_lua_shdict_api_rpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

ngx_int_t ngx_lua_shdict_api_lpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

ngx_int_t ngx_lua_shdict_api_lpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value);

ngx_int_t ngx_lua_shdict_api_llen(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);

ngx_int_t ngx_lua_shdict_api_llen_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len);
```
