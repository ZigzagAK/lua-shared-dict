/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef _NGX_LUA_SHDICT_H_INCLUDED_
#define _NGX_LUA_SHDICT_H_INCLUDED_

#include <nginx.h>
#include <ngx_core.h>

#include <lua.h>
#include <stdint.h>


/* Public API for other Nginx modules */


#define SHDICT_TNIL      (LUA_TNIL)
#define SHDICT_TBOOLEAN  (LUA_TBOOLEAN)
#define SHDICT_TNUMBER   (LUA_TNUMBER)
#define SHDICT_TSTRING   (LUA_TSTRING)
#define SHDICT_TLIST     (5)
#define SHDICT_TZSET     (6)
#define SHDICT_TUSERDATA (LUA_TUSERDATA)
#define SHDICT_TNULL     (LUA_TLIGHTUSERDATA)


typedef struct {
    union {
        int         b; /* boolean */
        lua_Number  n; /* number */
        ngx_str_t   s; /* string or userdata */
    } value;

    int32_t  user_flags;
    uint8_t  type;
    u_char   valid;
} ngx_lua_value_t;


#ifndef MAX_SHDICT_QUEUE_VALUE_SIZE
#define MAX_SHDICT_QUEUE_VALUE_SIZE (32768)
#endif


ngx_shm_zone_t *
ngx_http_lua_add_shared_dict(ngx_conf_t *cf,
    ngx_str_t name, ngx_str_t size);

ngx_shm_zone_t *
ngx_stream_lua_add_shared_dict(ngx_conf_t *cf,
    ngx_str_t name, ngx_str_t size);


ngx_int_t ngx_lua_shared_dict_get(ngx_shm_zone_t *shm_zone,
    u_char *key_data, size_t key_len, ngx_lua_value_t *value);

ngx_shm_zone_t *ngx_lua_find_zone(u_char *name_data, size_t name_len);


/* shared dictionary api */

#define NGX_LUA_SHDICT_OK             (NGX_OK)
#define NGX_LUA_SHDICT_ZSCAN_STOP     (1)
#define NGX_LUA_SHDICT_ERROR          (NGX_ERROR)
#define NGX_LUA_SHDICT_NOT_FOUND      (NGX_DECLINED)
#define NGX_LUA_SHDICT_EXISTS         (NGX_DONE)
#define NGX_LUA_SHDICT_BAD_VALUE_TYPE (NGX_ABORT)
#define NGX_LUA_SHDICT_NO_MEMORY      (NGX_BUSY)

void ngx_lua_shdict_lock(ngx_shm_zone_t *shm_zone);

void ngx_lua_shdict_unlock(ngx_shm_zone_t *shm_zone);

int
ngx_lua_shdict_expire_items(ngx_shm_zone_t *shm_zone, ngx_uint_t n);

ngx_shm_zone_t *
ngx_lua_ffi_shdict_udata_to_zone(void *zone_udata);

#    if nginx_version >= 1011007

ngx_int_t ngx_lua_shdict_api_used(ngx_shm_zone_t *shm_zone);

#    endif

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


#endif /* _NGX_LUA_SHDICT_H_INCLUDED_ */
