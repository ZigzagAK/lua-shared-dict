/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#ifndef DDEBUG
#define DDEBUG 0
#endif

#if (DDEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "lua *** %s: ", __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static ngx_inline void
dd(const char *fmt, ...) {
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static ngx_inline void
dd(const char *fmt, ...) {
}

#   endif

#endif

#include <lauxlib.h>
#include <math.h>


#include "api/ngx_lua_shdict.h"
#include "ngx_lua_shdict_defs.h"

typedef void (*err_fun_t)(void *userctx, const char *fmt, ...);

static void
free_stub(void *p, size_t len)
{}

static ngx_int_t ngx_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data);

static int ngx_lua_shdict_set(lua_State *L);
static int ngx_lua_shdict_safe_set(lua_State *L);
static int ngx_lua_shdict_get(lua_State *L);
static int ngx_lua_shdict_get_stale(lua_State *L);
static int ngx_lua_shdict_get_helper(lua_State *L, int get_stale);
static int ngx_lua_shdict_expire(ngx_lua_shdict_ctx_t *ctx,
    ngx_uint_t n);
static ngx_int_t ngx_lua_shdict_lookup(ngx_shm_zone_t *shm_zone,
    ngx_uint_t hash, u_char *kdata, size_t klen,
    ngx_lua_shdict_node_t **sdp);
static int ngx_lua_shdict_lua_set_helper(lua_State *L, int flags);
static int ngx_lua_shdict_add(lua_State *L);
static int ngx_lua_shdict_safe_add(lua_State *L);
static int ngx_lua_shdict_replace(lua_State *L);
static int ngx_lua_shdict_incr(lua_State *L);
static int ngx_lua_shdict_delete(lua_State *L);
static int ngx_lua_shdict_flush_all(lua_State *L);
static int ngx_lua_shdict_flush_expired(lua_State *L);
static int ngx_lua_shdict_get_keys(lua_State *L);
static int ngx_lua_shdict_lpush(lua_State *L);
static int ngx_lua_shdict_rpush(lua_State *L);
static int ngx_lua_shdict_lpop(lua_State *L);
static int ngx_lua_shdict_rpop(lua_State *L);
static int ngx_lua_shdict_llen(lua_State *L);
static int ngx_lua_shdict_fun(lua_State *L);
static int ngx_lua_shared_dict_ttl(lua_State *L);
static int ngx_lua_shared_dict_expire(lua_State *L);
static int ngx_lua_shared_dict_capacity(lua_State *L);
#    if nginx_version >= 1011007
static int ngx_lua_shared_dict_free_space(lua_State *L);
#    endif
static int ngx_lua_shdict_zset(lua_State *L);
static int ngx_lua_shdict_zadd(lua_State *L);
static int ngx_lua_shdict_zrem(lua_State *L);
static int ngx_lua_shdict_zgetall(lua_State *L);
static int ngx_lua_shdict_zget(lua_State *L);
static int ngx_lua_shdict_zcard(lua_State *L);
static int ngx_lua_shdict_zscan(lua_State *L);

static ngx_inline ngx_shm_zone_t *ngx_lua_shdict_get_zone(lua_State *L,
                                                          int index);


#define NGX_HTTP_LUA_SHDICT_ADD         0x0001
#define NGX_HTTP_LUA_SHDICT_REPLACE     0x0002
#define NGX_HTTP_LUA_SHDICT_SAFE_STORE  0x0004


#define NGX_HTTP_LUA_SHDICT_LEFT        0x0001
#define NGX_HTTP_LUA_SHDICT_RIGHT       0x0002


enum {
    SHDICT_USERDATA_INDEX = 1
};


static void
ngx_lua_inject_shdict_mt(lua_State *L)
{
    luaL_Reg sFooRegs[] = {
        { "get",           ngx_lua_shdict_get },
        { "get_stale",     ngx_lua_shdict_get_stale },
        { "set",           ngx_lua_shdict_set },
        { "safe_set",      ngx_lua_shdict_safe_set },
        { "add",           ngx_lua_shdict_add },
        { "safe_add",      ngx_lua_shdict_safe_add },
        { "replace",       ngx_lua_shdict_replace },
        { "incr",          ngx_lua_shdict_incr },
        { "delete",        ngx_lua_shdict_delete },
        { "lpush",         ngx_lua_shdict_lpush },
        { "rpush",         ngx_lua_shdict_rpush },
        { "lpop",          ngx_lua_shdict_lpop },
        { "rpop",          ngx_lua_shdict_rpop },
        { "llen",          ngx_lua_shdict_llen },
        { "zset",          ngx_lua_shdict_zset },
        { "zadd",          ngx_lua_shdict_zadd },
        { "zrem",          ngx_lua_shdict_zrem },
        { "zget",          ngx_lua_shdict_zget },
        { "zgetall",       ngx_lua_shdict_zgetall },
        { "zcard",         ngx_lua_shdict_zcard },
        { "zscan",         ngx_lua_shdict_zscan },
        { "flush_all",     ngx_lua_shdict_flush_all },
        { "flush_expired", ngx_lua_shdict_flush_expired },
        { "get_keys",      ngx_lua_shdict_get_keys },
        { "fun",           ngx_lua_shdict_fun },
        { "ttl",           ngx_lua_shared_dict_ttl },
        { "expire",        ngx_lua_shared_dict_expire },
        { "capacity",      ngx_lua_shared_dict_capacity },
        { "free_space",    ngx_lua_shared_dict_free_space },
        { NULL, NULL }
    };

    luaL_newmetatable(L, "ngx_lua_shdict");

    luaL_register(L, NULL, sFooRegs);

    lua_pushvalue(L, -1);

    lua_setfield(L, -1, "__index");

    lua_pop(L, 1);
}


static void
ngx_lua_override_metatable(ngx_conf_t *cf, lua_State *L)
{
    ngx_lua_inject_shdict_mt(L);

    lua_getglobal(L, "ngx");
    lua_getfield(L, -1, "shared");

    lua_pushnil(L);

    while (lua_next(L, -2) != 0) {

        lua_pushvalue(L, -1);
        luaL_getmetatable(L, "ngx_lua_shdict");
        lua_setmetatable(L, -2);

        lua_pop(L, 2);
    }

    /* ngx & shared */
    lua_pop(L, 2);
}


static ngx_lua_shdict_ctx_t *
ngx_lua_shdict_new_ctx(ngx_conf_t *cf, ngx_shm_zone_t *zone)
{
    ngx_lua_shdict_ctx_t  *ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_lua_shdict_ctx_t));
    if (ctx == NULL)
        return NULL;

    ctx->name = zone->shm.name;
    ctx->log = &cf->cycle->new_log;

    return ctx;
}


ngx_int_t
ngx_lua_shdict_init(lua_State *L, ngx_conf_t *cf, void *tag)
{
    ngx_uint_t               i;
    ngx_shm_zone_t          *shm_zone;
    ngx_list_part_t         *part;
    ngx_lua_shm_zone_ctx_t  *ctx;

    if (L == NULL)
        return NGX_OK;

    part = (ngx_list_part_t *) &(cf->cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {

            if (part->next == NULL)
                break;

            part = part->next;
            shm_zone = part->elts;

            i = 0;
        }

        if (shm_zone[i].tag != tag)
            continue;

        ctx = (ngx_lua_shm_zone_ctx_t *) shm_zone[i].data;

        ctx->zone.data = ngx_lua_shdict_new_ctx(cf, shm_zone + i);
        if (ctx->zone.data == NULL)
            return NGX_ERROR;
        ctx->zone.init = ngx_lua_shdict_init_zone;
    }

    ngx_lua_override_metatable(cf, L);

    return NGX_OK;
}


void
ngx_lua_shdict_lock(ngx_shm_zone_t *shm_zone)
{
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;
    ngx_shmtx_lock(&ctx->shpool->mutex);
}


void
ngx_lua_shdict_unlock(ngx_shm_zone_t *shm_zone)
{
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;
    ngx_shmtx_unlock(&ctx->shpool->mutex);
}


int
ngx_lua_shdict_expire_items(ngx_shm_zone_t *shm_zone, ngx_uint_t n)
{
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;
    return ngx_lua_shdict_expire(ctx, n);
}


static void *
ngx_lua_shdict_alloc_locked(ngx_lua_shdict_ctx_t *ctx, int n)
{
    int   i;
    void *p = NULL;

    for (i = 0; p == NULL && i < 30; i++) {

        p = ngx_slab_alloc_locked(ctx->shpool, n);

        if (p == NULL) {

            if (ngx_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }
        }
    }

    return p;
}


static void *
ngx_lua_shdict_calloc_locked(ngx_lua_shdict_ctx_t *ctx, int n)
{
    void *p = ngx_lua_shdict_alloc_locked(ctx, n);
    if (p) {
        ngx_memzero(p, n);
    }
    return p;
}


#    if nginx_version >= 1011007

ngx_int_t
ngx_lua_shdict_api_used(ngx_shm_zone_t *shm_zone)
{
    size_t                  bytes;
    ngx_lua_shdict_ctx_t   *ctx;

    ctx = shm_zone->data;

    bytes = ctx->shpool->pfree * ngx_pagesize;

    return (shm_zone->shm.size - bytes) * 100 / shm_zone->shm.size;
}

#    endif

static ngx_inline ngx_str_t
ngx_lua_get_string(lua_State *L, int index)
{
    ngx_str_t s = { .data = NULL, .len = 0 };

    if (lua_touserdata(L, index) == NULL) {
        s.data = (u_char *) luaL_checklstring(L, index, &s.len);
        return s;
    }

    if (!luaL_callmeta(L, index, "__tostring")) {
        luaL_error(L, "userdata at #%d doesn't have tostring method", index);
        /* unreachable */
        return s;
    }

    s.data = (u_char *) lua_tolstring(L, -1, &s.len);

    return s;
}


static ngx_inline ngx_int_t
ngx_lua_shdict_check_required(lua_State *L,
    ngx_shm_zone_t **shm_zone, ngx_str_t *key,
    int args_min, int args_max)
{
    int n = lua_gettop(L);

    if (n < args_min || n > args_max) {
        return luaL_error(L, "number of args expecting [%d, %d], "
                          "but seen %d", args_min, args_max, n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    *shm_zone = ngx_lua_shdict_get_zone(L, 1);
    if (*shm_zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    if (key == NULL) {
        return NGX_OK;
    }

    if (lua_isnil(L, 2)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil key");
        return NGX_ERROR;
    }

    *key = ngx_lua_get_string(L, 2);

    if (key->len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty key");
        return NGX_ERROR;
    }

    if (key->len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "key too long");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_inline uint64_t
ngx_lua_get_expires(int64_t exptime /* ms */)
{
    uint64_t     expires = 0;
    ngx_time_t  *tp;

    if (exptime > 0) {
        tp = ngx_timeofday();
        expires = (uint64_t) tp->sec * 1000 + tp->msec
                      + exptime;

    } else {
        expires = 0;
    }

    return expires;
}


static ngx_inline ngx_str_t
ngx_lua_value_to_raw(ngx_lua_value_t *value)
{
    ngx_str_t s;

    switch (value->type) {
    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        s = value->value.s;
        break;

    case SHDICT_TNUMBER:

        s.data = (u_char *) &value->value.n;
        s.len = sizeof(lua_Number);
        break;

    case SHDICT_TBOOLEAN:

        s.data = (u_char *) &value->value.b;
        s.len = 1;
        break;

    default:
        ngx_str_null(&s);
        break;
    }

    return s;
}


static ngx_inline ngx_lua_value_t
ngx_lua_raw_to_value(ngx_str_t raw, uint8_t value_type)
{
    ngx_lua_value_t value;

    value.type = value_type;
    value.valid = 1;
    value.user_flags = 0;

    switch (value_type) {
    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        value.value.s = raw;
        break;

    case SHDICT_TNUMBER:

        value.value.n = *(lua_Number *) raw.data;
        break;

    case SHDICT_TBOOLEAN:

        value.value.b = raw.data[0];
        break;

    case SHDICT_TNULL:

        ngx_str_null(&value.value.s);
        break;

    default:

        value.valid = 0;
        ngx_str_null(&value.value.s);
        break;
    }

    return value;
}


static ngx_inline ngx_lua_value_t
ngx_lua_get_value(lua_State *L, int index)
{
    ngx_lua_value_t value = {
        .user_flags = 0,
        .type = SHDICT_TNIL,
        .valid = 1
    };

    switch (lua_type(L, index)) {

    case LUA_TSTRING:

        value.value.s.data = (u_char *) lua_tolstring(L, index,
            &value.value.s.len);
        value.type = SHDICT_TSTRING;
        break;

    case LUA_TNUMBER:

        value.value.n = lua_tonumber(L, index);
        value.type = SHDICT_TNUMBER;
        break;

    case LUA_TBOOLEAN:

        value.value.b = lua_toboolean(L, index);
        value.type = SHDICT_TBOOLEAN;
        break;

    case LUA_TLIGHTUSERDATA:

        if (lua_touserdata(L, index) == NULL) {

            /* ngx.null */
            value.type = SHDICT_TNULL;
            break;
        } else {

            value.type = SHDICT_TNIL;
            value.valid = 0;
        }

        break;

    case LUA_TUSERDATA:

        value.value.s = ngx_lua_get_string(L, index);
        value.type = SHDICT_TSTRING;

        break;

    case LUA_TNIL:

        ngx_memzero(&value.value, sizeof(value.value));
        break;

    default:

        value.valid = 0;
    }

    return value;
}


static ngx_inline ngx_int_t
ngx_lua_shdict_copy_value(ngx_lua_value_t *value,
                               ngx_lua_value_t *src)
{
    size_t len;

    if (!src->valid) {

        value->valid = 0;
        return NGX_LUA_SHDICT_ERROR;
    }

    value->valid = 1;
    value->type = src->type;
    value->user_flags = src->user_flags;

    switch (value->type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        len = src->value.s.len;

        if (value->value.s.data == NULL || value->value.s.len < len) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no string buffer "
                          "initialized or not enough space");
            return NGX_LUA_SHDICT_ERROR;
        }

        value->value.s.len = len;

        ngx_memcpy(value->value.s.data, src->value.s.data, len);

        break;

    case SHDICT_TBOOLEAN:

        value->value.b = src->value.b;
        break;

    case SHDICT_TNUMBER:

        value->value.n = src->value.n;
        break;

    case SHDICT_TNIL:
    case SHDICT_TNULL:

        ngx_memzero(&value->value, sizeof(value->value));
        break;

    default:

        break;
    }

    return NGX_LUA_SHDICT_OK;
}


static void
ngx_lua_shdict_value_push(lua_State *L,
    ngx_lua_value_t *value)
{
    if (value->valid) {

        switch (value->type) {

        case SHDICT_TSTRING:

            lua_pushlstring(L, (char *) value->value.s.data,
                value->value.s.len);
            break;

        case SHDICT_TNUMBER:

            lua_pushnumber(L, value->value.n);
            break;

        case SHDICT_TBOOLEAN:

            lua_pushboolean(L, value->value.b);
            break;

        case SHDICT_TNIL:

            lua_pushnil(L);
            break;

        case SHDICT_TNULL:

            lua_pushlightuserdata(L, NULL);
            break;

        }
    } else {

        lua_pushnil(L);
    }
}


static ngx_inline ngx_queue_t *
ngx_lua_shdict_list_get(ngx_lua_shdict_node_t *sd, size_t len)
{
    return (ngx_queue_t *) ngx_align_ptr(((u_char *) &sd->data + len),
                                         NGX_ALIGNMENT);
}


static ngx_inline void
ngx_lua_shdict_list_free(ngx_lua_shdict_ctx_t *ctx,
                              ngx_lua_shdict_node_t *sd)
{
    ngx_queue_t *queue, *q;
    u_char      *p;

    queue = ngx_lua_shdict_list_get(sd, sd->key_len);

    for (q = ngx_queue_head(queue);
         q != ngx_queue_sentinel(queue);
         q = ngx_queue_next(q))
    {
        p = (u_char *) ngx_queue_data(q,
                                      ngx_lua_shdict_list_node_t,
                                      queue);

        ngx_slab_free_locked(ctx->shpool, p);
    }
}


static ngx_inline ngx_lua_shdict_zset_t *
ngx_lua_shdict_zset_get(ngx_lua_shdict_node_t *sd, size_t len)
{
    return (ngx_lua_shdict_zset_t *)
        ngx_align_ptr(((u_char *) &sd->data + len), NGX_ALIGNMENT);
}


static ngx_inline ngx_lua_value_t
ngx_lua_shdict_zset_znode_value_get(ngx_lua_shdict_zset_node_t *zset_node)
{
    ngx_lua_value_t value;

    value.type = zset_node->value_type;
    value.valid = 1;

    if (zset_node->value.data) {

        switch (zset_node->value_type) {

        case SHDICT_TSTRING:
        case SHDICT_TUSERDATA:

            value.value.s = zset_node->value;
            break;

        case SHDICT_TNUMBER:

            value.value.n = *(lua_Number *) zset_node->value.data;
            break;

        case SHDICT_TBOOLEAN:

            value.value.b = zset_node->value.data[0];
            break;

        case SHDICT_TNIL:
        case SHDICT_TNULL:

            break;

        default:

            break;
        }
    } else {

        value.type = SHDICT_TNIL;
    }

    return value;
}


static ngx_inline void
ngx_lua_shdict_zset_znode_value_push(lua_State *L,
    ngx_lua_shdict_zset_node_t *zset_node)
{
    ngx_lua_value_t value;

    if (zset_node->value.data) {

        value = ngx_lua_raw_to_value(zset_node->value,
                                          zset_node->value_type);
        ngx_lua_shdict_value_push(L, &value);
    } else {

        lua_pushnil(L);
    }
}


void
ngx_lua_shdict_zset_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_lua_shdict_zset_node_t  *sdn, *sdnt;

    for ( ;; ) {

        sdn = (ngx_lua_shdict_zset_node_t *) &node->color;
        sdnt = (ngx_lua_shdict_zset_node_t *) &temp->color;

        p = ngx_strcmp(sdn->data, sdnt->data) < 0 ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_inline void
ngx_lua_shdict_rbtree_free(ngx_lua_shdict_ctx_t *ctx,
                                ngx_lua_shdict_node_t *sd)
{
    ngx_rbtree_node_t          *node;
    ngx_rbtree_node_t          *tmp;
    ngx_rbtree_node_t          *sentinel;
    ngx_lua_shdict_zset_t      *zset;
    ngx_lua_shdict_zset_node_t *zset_node;

    zset = ngx_lua_shdict_zset_get(sd, sd->key_len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    if (node != sentinel) {

        for (node = ngx_rbtree_min(node, sentinel);
             node;
             ngx_slab_free_locked(ctx->shpool, tmp))
        {
            zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

            if (zset_node->value.data) {
                (* (ngx_lua_zset_destructor_t) zset_node->free)
                    (zset_node->value.data, zset_node->value.len);
                ngx_slab_free_locked(ctx->shpool, zset_node->value.data);
            }

            tmp = node;

            node = ngx_rbtree_next(&zset->rbtree, node);
        }
    }
}

static ngx_inline void
ngx_lua_shdict_rbtree_delete_node(ngx_lua_shdict_ctx_t *ctx,
                                       ngx_lua_shdict_node_t *sd)
{
    ngx_rbtree_node_t  *node;

    if (sd->value_type == SHDICT_TLIST) {
        ngx_lua_shdict_list_free(ctx, sd);
    }

    if (sd->value_type == SHDICT_TZSET) {
        ngx_lua_shdict_rbtree_free(ctx, sd);
    }

    ngx_queue_remove(&sd->queue);

    node = (ngx_rbtree_node_t *)
               ((u_char *) sd - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    ngx_slab_free_locked(ctx->shpool, node);
}


static ngx_inline ngx_int_t
ngx_lua_shdict_rbtree_insert_node(ngx_lua_shdict_ctx_t *ctx,
                                       ngx_str_t key, ngx_str_t value,
                                       uint8_t value_type,
                                       uint64_t expires, uint32_t user_flags,
                                       int flags, int *forcible)
{
    ngx_rbtree_node_t       *node;
    ngx_lua_shdict_node_t   *sd;
    int                      n, i;
    ngx_uint_t               hash;
    u_char                  *p;

    hash = ngx_crc32_short(key.data, key.len);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict: creating a new entry");

    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_lua_shdict_node_t, data)
        + key.len
        + value.len;

    dd("overhead = %d", (int) (offsetof(ngx_rbtree_node_t, color)
       + offsetof(ngx_lua_shdict_node_t, data)));

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        if (flags & NGX_HTTP_LUA_SHDICT_SAFE_STORE) {

            return NGX_LUA_SHDICT_NO_MEMORY;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict: overriding non-expired items "
                       "due to memory shortage for entry \"%V\"", &key);

        for (i = 0; i < 30 && node == NULL; i++) {

            if (ngx_lua_shdict_expire(ctx, 0) == 0) {
                break;
            }

            if (forcible != NULL) {
                *forcible = 1;
            }

            node = ngx_slab_alloc_locked(ctx->shpool, n);
        }

        if (node == NULL) {

            return NGX_LUA_SHDICT_NO_MEMORY;
        }
    }

    sd = (ngx_lua_shdict_node_t *) &node->color;

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = expires;
    sd->user_flags = user_flags;

    sd->value_len = value.len;

    dd("setting value type to %d", value_type);

    sd->value_type = value_type;

    p = ngx_copy(sd->data, key.data, key.len);
    ngx_memcpy(p, value.data, value.len);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    return NGX_LUA_SHDICT_OK;
}


static ngx_inline void
ngx_lua_shdict_rbtree_replace_value(ngx_lua_shdict_ctx_t *ctx,
                                         ngx_lua_shdict_node_t *sd,
                                         u_char *value, uint8_t value_type,
                                         uint64_t expires, uint32_t user_flags)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict: found old entry and value "
                   "size matched, reusing it");

    ngx_queue_remove(&sd->queue);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    sd->expires = expires;

    sd->user_flags = user_flags;

    dd("setting value type to %d", sd->value_type);

    sd->value_type = value_type;

    ngx_memcpy(sd->data + sd->key_len, value, sd->value_len);
}


void
ngx_lua_shdict_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t      **p;
    ngx_lua_shdict_node_t   *sdn, *sdnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sdn = (ngx_lua_shdict_node_t *) &node->color;
            sdnt = (ngx_lua_shdict_node_t *) &temp->color;

            p = ngx_memn2cmp(sdn->data, sdnt->data, sdn->key_len,
                             sdnt->key_len) < 0 ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_lua_shdict_ctx_t  *octx = data;
    size_t                 len;
    ngx_lua_shdict_ctx_t  *ctx;

    dd("init zone");

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_lua_shdict_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_lua_shdict_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->lru_queue);

    len = sizeof(" in lua_shared_dict zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in lua_shared_dict zone \"%V\"%Z",
                &shm_zone->shm.name);

#if defined(nginx_version) && nginx_version >= 1005013
    ctx->shpool->log_nomem = 0;
#endif

    ctx->sh->last = ngx_current_msec;
    ctx->sh->count[0] = 0;
    ctx->sh->count[1] = 0;
    ctx->sh->rps = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_lua_shdict_lookup(ngx_shm_zone_t *shm_zone, ngx_uint_t hash,
    u_char *kdata, size_t klen, ngx_lua_shdict_node_t **sdp)
{
    ngx_int_t               rc;
    ngx_time_t             *tp;
    uint64_t                now;
    int64_t                 ms;
    ngx_rbtree_node_t      *node, *sentinel;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_lua_shdict_node_t  *sd;

    ctx = shm_zone->data;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    if (ngx_current_msec - ctx->sh->last > 1000) {
        ctx->sh->rps = 1000 * ctx->sh->count[0] /
            ngx_max(1000, ngx_current_msec - ctx->sh->last);
        ctx->sh->last = ngx_current_msec;
        ctx->sh->count[1] = ctx->sh->count[0];
        ctx->sh->count[0] = 0;
    }

    ++ctx->sh->count[0];

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sd = (ngx_lua_shdict_node_t *) &node->color;

        rc = ngx_memn2cmp(kdata, sd->data, klen, (size_t) sd->key_len);

        if (rc == 0) {
            ngx_queue_remove(&sd->queue);
            ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

            *sdp = sd;

            dd("node expires: %lld", (long long) sd->expires);

            if (sd->expires != 0) {
                tp = ngx_timeofday();

                now = (uint64_t) tp->sec * 1000 + tp->msec;
                ms = sd->expires - now;

                dd("time to live: %lld", (long long) ms);

                if (ms < 0) {
                    dd("node already expired");
                    return NGX_DONE;
                }
            }

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *sdp = NULL;

    return NGX_DECLINED;
}


static int
ngx_lua_shdict_expire(ngx_lua_shdict_ctx_t *ctx, ngx_uint_t n)
{
    ngx_time_t                 *tp;
    uint64_t                    now;
    ngx_queue_t                *q;
    int64_t                     ms;
    ngx_lua_shdict_node_t      *sd;
    int                         freed = 0;

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /*
     * n == 1 deletes one or two expired entries
     * n == 0 deletes oldest entry by force
     *        and one or two zero rate entries
     */

    while (n < 3) {

        if (ngx_queue_empty(&ctx->sh->lru_queue)) {
            return freed;
        }

        q = ngx_queue_last(&ctx->sh->lru_queue);

        sd = ngx_queue_data(q, ngx_lua_shdict_node_t, queue);

        if (n++ != 0) {

            if (sd->expires == 0) {
                return freed;
            }

            ms = sd->expires - now;
            if (ms > 0) {
                return freed;
            }
        }

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);

        freed++;
    }

    return freed;
}

static int
ngx_lua_shdict_get(lua_State *L)
{
    return ngx_lua_shdict_get_helper(L, 0 /* stale */);
}


static int
ngx_lua_shdict_get_stale(lua_State *L)
{
    return ngx_lua_shdict_get_helper(L, 1 /* stale */);
}


static ngx_inline ngx_shm_zone_t *
ngx_lua_shdict_get_zone(lua_State *L, int index)
{
    ngx_shm_zone_t      *zone;
    ngx_shm_zone_t     **zone_udata;

    lua_rawgeti(L, index, SHDICT_USERDATA_INDEX);
    zone_udata = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (zone_udata == NULL)
        return NULL;

    zone = *zone_udata;
    return zone;
}


static ngx_int_t
ngx_lua_shdict_api_fun_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_get_fun_t fun, err_fun_t err_handler,
    int get_stale,  uint64_t expires, void *userctx, int mutable,
    int *forcible)
{
    u_char                 *data = NULL;
    size_t                  len = 0;
    uint32_t                hash;
    ngx_int_t               rc, result;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_lua_shdict_node_t  *sd;
    ngx_lua_value_t         value;

    if (shm_zone == NULL) {

        return NGX_LUA_SHDICT_ERROR;
    }

    if (err_handler == NULL) {

        return NGX_LUA_SHDICT_ERROR;
    }

    hash = ngx_crc32_short(key.data, key.len);

    ctx = shm_zone->data;

#if 1
    if (!get_stale) {
        ngx_lua_shdict_expire(ctx, 1);
    }
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    value.valid = 0;

    if (rc == NGX_OK || (rc == NGX_DONE && get_stale)) {

        data = sd->data + sd->key_len;
        len = (size_t) sd->value_len;

        value.valid = 1;

        value.type = sd->value_type;

        dd("type: %d", (int) value.type);

        value.user_flags = sd->user_flags;

        switch (value.type) {

        case SHDICT_TSTRING:
        case SHDICT_TUSERDATA:

            value.value.s.len = len;
            value.value.s.data = data;
            break;

        case SHDICT_TNUMBER:

            value.value.n = *(lua_Number *) data;
            break;

        case SHDICT_TBOOLEAN:

            value.value.b = data[0];
            break;

        case SHDICT_TLIST:
        case SHDICT_TZSET:
            ngx_str_null(&value.value.s);
            break;

        case SHDICT_TNULL:

            ngx_memzero(&value.value, sizeof(value.value));
            break;

        default:
            err_handler(userctx, "bad lua value type "
                        "found for key %*s: %d", key.len, key.data,
                        (int) value.type);

            return NGX_LUA_SHDICT_ERROR;
        }

    } else {

        if (mutable == 0) {

            return NGX_LUA_SHDICT_NOT_FOUND;
        }

        ngx_memzero(&value, sizeof(ngx_lua_value_t));
    }

    result = fun(&value, rc == NGX_DONE, userctx);

    if (result != NGX_LUA_SHDICT_OK) {

        return result;
    }

    if (mutable == 0) {

        return NGX_LUA_SHDICT_OK;
    }

    /* store back */

    if (rc == NGX_DECLINED) {

            if (value.type != SHDICT_TNIL) {

                return ngx_lua_shdict_rbtree_insert_node(ctx,
                    key, ngx_lua_value_to_raw(&value),
                    value.type,
                    expires, value.user_flags,
                    0, forcible);
            }

            return NGX_LUA_SHDICT_OK;
    }

    if (value.type != sd->value_type) {

        /* node type has been changed on existing key  *
         * delete -> add                               */

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);

        if (value.type != SHDICT_TNIL) {

            return ngx_lua_shdict_rbtree_insert_node(ctx,
                key, ngx_lua_value_to_raw(&value),
                value.type,
                expires, value.user_flags,
                0, forcible);
        }

        /* node deleted */

        return NGX_LUA_SHDICT_OK;
    }

    /* try reuse node */

    rc = NGX_LUA_SHDICT_OK;

    sd->user_flags = value.user_flags;
    sd->expires = expires;

    data = sd->data + sd->key_len;

    switch (value.type) {
    case SHDICT_TBOOLEAN:

        data[0] = value.value.b;
        break;

    case SHDICT_TNUMBER:

        *((lua_Number*) data) = value.value.n;
        break;

    case SHDICT_TNIL:

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);
        break;

    case SHDICT_TNULL:

        ngx_memzero(&value.value, sizeof(value.value));
        break;

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        if (value.value.s.data == data) {

            /* memory pointer is not changed */

            if (value.value.s.len > sd->value_len) {

                /* memory buffer overrun */

                ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                              "value data memory pointer "
                              "is not changed and length is increased, "
                              "key %*s: %d aborting ...", key.len, key.data,
                              (int) value.type);

                ngx_abort();
            }
        } else {

            if (value.value.s.len == sd->value_len) {

                /* inplace replace */
                ngx_lua_shdict_rbtree_replace_value(ctx, sd,
                    value.value.s.data, value.type,
                    expires, value.user_flags);
            } else {

                /* remove old node and insert new one */
                ngx_lua_shdict_rbtree_delete_node(ctx, sd);

                rc = ngx_lua_shdict_rbtree_insert_node(ctx,
                    key, value.value.s, value.type,
                    expires, value.user_flags,
                    0, forcible);
            }
        }

        break;
    }

    return rc;
}


typedef struct {
    ngx_str_t key;
    ngx_str_t name;
    u_char err[NGX_MAX_ERROR_STR];
    lua_State *L;
    int get_stale;
    int index;
} ngx_lua_shdict_userctx_t;


static ngx_int_t
ngx_lua_shdict_get_helper_push_value(ngx_lua_value_t *value,
    int stale, void *userctx)
{
    ngx_lua_shdict_userctx_t *ctx = userctx;
    lua_State                *L = ctx->L;

    switch (value->type) {

    case SHDICT_TLIST:

        lua_pushnil(L);
        lua_pushliteral(L, "value is a list");
        break;

    case SHDICT_TZSET:

        lua_pushnil(L);
        lua_pushliteral(L, "value is a zset");
        break;

    case SHDICT_TUSERDATA:

        lua_pushnil(L);
        lua_pushliteral(L, "value is an userdata");
        break;

    default:

        ngx_lua_shdict_value_push(L, value);
    }

    if (ctx->get_stale) {

        /* always return value, flags, stale */

        if (value->user_flags) {
            lua_pushinteger(L, (lua_Integer) value->user_flags);

        } else {
            lua_pushnil(L);
        }

        lua_pushboolean(L, stale);
    }

    if (value->user_flags) {
        lua_pushinteger(L, (lua_Integer) value->user_flags);
    }

    return NGX_LUA_SHDICT_OK;
}


static void
ngx_lua_shdict_get_helper_err_handler(void *userctx, const char *fmt, ...)
{
    ngx_lua_shdict_userctx_t *ctx = userctx;
    va_list args;
    va_start(args, fmt);
    ngx_vslprintf(ctx->err, ctx->err + NGX_MAX_ERROR_STR, fmt, args);
    va_end(args);
}


static int
ngx_lua_shdict_get_helper(lua_State *L, int get_stale)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t      *ctx;
    ngx_shm_zone_t            *shm_zone = NULL;
    int                        n = lua_gettop(L);
    ngx_lua_shdict_userctx_t   userctx = {
        .L = L, .get_stale = get_stale
    };

    userctx.err[0] = 0;

    ngx_str_null(&userctx.key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &userctx.key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;
    userctx.name = ctx->name;

#if (NGX_DEBUG)
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &userctx.key,
                   &userctx.name);
#endif /* NGX_DEBUG */

    n = lua_gettop(L);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_fun_helper(shm_zone, userctx.key,
            ngx_lua_shdict_get_helper_push_value,
            ngx_lua_shdict_get_helper_err_handler,
            get_stale, 0, &userctx, 0, NULL);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        return lua_gettop(L) - n;

    case NGX_LUA_SHDICT_ERROR:

        return luaL_error(L, userctx.err[0] ? (const char *) userctx.err :
            "unexpected");

    default:

        break;
    }

    /* not found */

    lua_pushnil(L);

    return 1;
}


static int
ngx_lua_shdict_delete(lua_State *L)
{
    int n = lua_gettop(L);

    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments, "
                          "but only seen %d", n);
    }

    lua_pushnil(L);

    return ngx_lua_shdict_lua_set_helper(L, 0);
}


static int
ngx_lua_shdict_flush_all(lua_State *L)
{
    ngx_queue_t            *q;
    ngx_lua_shdict_node_t  *sd;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t         *zone;
    int                     n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting 1 argument, but seen %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    for (q = ngx_queue_head(&ctx->sh->lru_queue);
         q != ngx_queue_sentinel(&ctx->sh->lru_queue);
         q = ngx_queue_next(q))
    {
        sd = ngx_queue_data(q, ngx_lua_shdict_node_t, queue);
        sd->expires = 1;
    }

    ngx_lua_shdict_expire(ctx, 0);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 0;
}


static int
ngx_lua_shdict_flush_expired(lua_State *L)
{
    ngx_queue_t                *q, *prev;
    ngx_lua_shdict_node_t      *sd;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t             *zone;
    ngx_time_t                 *tp;
    int                         freed = 0;
    int                         attempts = 0;
    uint64_t                    now;
    int                         n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnumber(L, 0);
        return 1;
    }

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_lua_shdict_node_t, queue);

        if (sd->expires != 0 && sd->expires <= now) {

            ngx_lua_shdict_rbtree_delete_node(ctx, sd);

            freed++;

            if (attempts && freed == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, freed);
    return 1;
}


/*
 * This trades CPU for memory. This is potentially slow. O(2n)
 */

static int
ngx_lua_shdict_get_keys(lua_State *L)
{
    ngx_queue_t            *q, *prev;
    ngx_lua_shdict_node_t  *sd;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_shm_zone_t         *zone;
    ngx_time_t             *tp;
    int                     total = 0;
    int                     attempts = 1024;
    uint64_t                now;
    int                     n = lua_gettop(L);

    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 argument(s), "
                          "but saw %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    zone = ngx_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad user data for the ngx_shm_zone_t pointer");
    }

    if (n == 2) {
        attempts = luaL_checkint(L, 2);
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    if (ngx_queue_empty(&ctx->sh->lru_queue)) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_createtable(L, 0, 0);
        return 1;
    }

    tp = ngx_timeofday();

    now = (uint64_t) tp->sec * 1000 + tp->msec;

    /* first run through: get total number of elements we need to allocate */

    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            total++;
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    lua_createtable(L, total, 0);

    /* second run through: add keys to table */

    total = 0;
    q = ngx_queue_last(&ctx->sh->lru_queue);

    while (q != ngx_queue_sentinel(&ctx->sh->lru_queue)) {
        prev = ngx_queue_prev(q);

        sd = ngx_queue_data(q, ngx_lua_shdict_node_t, queue);

        if (sd->expires == 0 || sd->expires > now) {
            lua_pushlstring(L, (char *) sd->data, sd->key_len);
            lua_rawseti(L, -2, ++total);
            if (attempts && total == attempts) {
                break;
            }
        }

        q = prev;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    /* table is at top of stack */
    return 1;
}


static int
ngx_lua_shdict_set_helper(ngx_shm_zone_t *zone,
    ngx_str_t key,
    ngx_str_t value, uint8_t value_type,
    int64_t exptime, int32_t user_flags, int flags, int *forcible)
{
    uint32_t                hash;
    ngx_int_t               rc;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_lua_shdict_node_t  *sd;

    ctx = zone->data;

    if (forcible != NULL) {
        *forcible = 0;
    }

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (flags & NGX_HTTP_LUA_SHDICT_REPLACE) {

        if (rc == NGX_DECLINED || rc == NGX_DONE) {

            return NGX_LUA_SHDICT_NOT_FOUND;
        }

        /* rc == NGX_OK */

        goto replace;
    }

    if (flags & NGX_HTTP_LUA_SHDICT_ADD) {

        if (rc == NGX_OK) {

            return NGX_LUA_SHDICT_EXISTS;
        }

        if (rc == NGX_DONE) {
            /* exists but expired */

            dd("go to replace");
            goto replace;
        }

        /* rc == NGX_DECLINED */

        dd("go to insert");
        goto insert;
    }

    if (rc == NGX_OK || rc == NGX_DONE) {

        if (value_type == LUA_TNIL) {
            goto remove;
        }

replace:

        if (value.data
            && value.len == (size_t) sd->value_len
            && sd->value_type != SHDICT_TLIST
            && sd->value_type != SHDICT_TZSET)
        {

            ngx_lua_shdict_rbtree_replace_value(ctx, sd,
                value.data, value_type,
                ngx_lua_get_expires(exptime), user_flags);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return NGX_LUA_SHDICT_OK;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict: found old entry but value size "
                       "NOT matched, removing it first");

remove:

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);
    }

insert:

    /* rc == NGX_DECLINED or value size unmatch */

    if (value.data == NULL) {
        return NGX_LUA_SHDICT_OK;
    }

    rc = ngx_lua_shdict_rbtree_insert_node(ctx,
        key, value, value_type,
        ngx_lua_get_expires(exptime), user_flags,
        flags, forcible);

    return rc;
}


static ngx_int_t
ngx_lua_shdict_api_set_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime,
    int flags)
{
    ngx_str_t val;
    u_char    c;

    switch (value.type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        val = value.value.s;
        break;

    case SHDICT_TNUMBER:

        val.len = sizeof(lua_Number);
        val.data = (u_char *) &value.value.n;
        break;

    case SHDICT_TBOOLEAN:

        c = (u_char) value.value.b;
        val.len = sizeof(u_char);
        val.data = &c;
        break;

    case SHDICT_TNULL:

        ngx_str_null(&val);
        break;

    default:

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    return ngx_lua_shdict_set_helper(shm_zone, key, val, value.type,
            (int64_t) (exptime * 1000), value.user_flags, flags, NULL);
}


typedef struct {
  ngx_lua_value_t value;
  ngx_str_t key;
} ngx_lua_shared_dict_get_getter_ctx_t;


static ngx_int_t
ngx_lua_shared_dict_get_getter(ngx_lua_value_t *src,
    int stale, void *userctx)
{
    ngx_lua_shared_dict_get_getter_ctx_t *ctx = userctx;

    switch (src->type) {

    case SHDICT_TSTRING:
    case SHDICT_TNUMBER:
    case SHDICT_TBOOLEAN:
    case SHDICT_TUSERDATA:
    case SHDICT_TNULL:
    case SHDICT_TNIL:

        ctx->value = *src;
        break;

    default:

        ctx->value.valid = 0;

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "bad lua value type "
                      "found for key %*s: %d", ctx->key.len, ctx->key.data,
                      (int) src->type);
        return NGX_LUA_SHDICT_ERROR;
    }

    return NGX_LUA_SHDICT_OK;
}


static void
ngx_lua_shdict_api_errlog(void *userctx, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    ngx_log_error_core(NGX_LOG_ERR, ngx_cycle->log, 0, fmt, args);
    va_end(args);
}


ngx_int_t
ngx_lua_shdict_api_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    ngx_lua_shared_dict_get_getter_ctx_t userctx = { .key = key };
    ngx_int_t                            rc;
    ngx_lua_shdict_ctx_t                *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_fun_helper(shm_zone, key,
        ngx_lua_shared_dict_get_getter,
        ngx_lua_shdict_api_errlog, 0, 0, &userctx, 0, NULL);

    if (rc == NGX_LUA_SHDICT_OK && value) {

        rc = ngx_lua_shdict_copy_value(value, &userctx.value);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_get_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    ngx_lua_shared_dict_get_getter_ctx_t userctx = { .key = key };
    ngx_int_t                            rc;

    value->valid = 0;

    rc = ngx_lua_shdict_api_fun_helper(shm_zone, key,
        ngx_lua_shared_dict_get_getter,
        ngx_lua_shdict_api_errlog, 0, 0, &userctx, 0, NULL);

    if (rc == NGX_LUA_SHDICT_OK && value) {

        ngx_memcpy(value, &userctx.value, sizeof(ngx_lua_value_t));
    }

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_fun_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_get_fun_t fun, int64_t exptime, void *userctx)
{
    uint64_t expires = ngx_lua_get_expires(exptime);
    return ngx_lua_shdict_api_fun_helper(shm_zone, key, fun,
            ngx_lua_shdict_api_errlog, 0, expires, userctx, 1, NULL);
}


ngx_int_t
ngx_lua_shdict_api_fun(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_get_fun_t fun, int64_t exptime, void *userctx)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_fun_locked(shm_zone,
        key, fun, exptime, userctx);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


typedef struct {
    lua_Number inc;
    lua_Number val;
} ngx_lua_shdict_incr_ctx_t;


static ngx_int_t
ngx_lua_shdict_incr_getter(ngx_lua_value_t *value,
    int stale, void *userctx)
{
    ngx_lua_shdict_incr_ctx_t *ctx = userctx;

    if (value->type != SHDICT_TNUMBER) {

        if (value->type == SHDICT_TNIL) {

            if (!isnan(ctx->val)) {

                value->type = SHDICT_TNUMBER;
                value->value.n = ctx->val;
                value->valid = 1;
            } else {

                return NGX_LUA_SHDICT_NOT_FOUND;
            }
        } else {

            return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
        }
    }

    value->value.n = value->value.n + ctx->inc;
    ctx->val = value->value.n;

    return NGX_LUA_SHDICT_OK;
}


lua_Number
ngx_lua_shdict_api_incr_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime)
{
    ngx_lua_shdict_incr_ctx_t userctx = { .val = def, .inc = inc };
    return ngx_lua_shdict_api_fun_locked(shm_zone,
        key, ngx_lua_shdict_incr_getter, exptime, &userctx)
            == NGX_LUA_SHDICT_OK ? userctx.val : nan("NaN");
}


lua_Number
ngx_lua_shdict_api_incr(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, lua_Number inc, lua_Number def, int exptime)
{
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;
    lua_Number            value;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    value = ngx_lua_shdict_api_incr_locked(shm_zone,
        key, inc, def, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return value;
}


ngx_int_t
ngx_lua_shdict_api_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    return ngx_lua_shdict_api_set_helper(shm_zone,
        key, value, exptime, 0);
}


ngx_int_t
ngx_lua_shdict_api_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_set_locked(shm_zone,
        key, value, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_safe_set_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    return ngx_lua_shdict_api_set_helper(shm_zone, key, value, exptime,
        NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


ngx_int_t
ngx_lua_shdict_api_safe_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_safe_set_locked(shm_zone,
        key, value, exptime);


    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    return ngx_lua_shdict_api_set_helper(shm_zone, key, value, exptime,
        NGX_HTTP_LUA_SHDICT_ADD);
}


ngx_int_t
ngx_lua_shdict_api_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_add_locked(shm_zone,
        key, value, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_safe_add_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    return ngx_lua_shdict_api_set_helper(shm_zone, key, value, exptime,
        NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


ngx_int_t
ngx_lua_shdict_api_safe_add(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_safe_add_locked(shm_zone,
        key, value, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_replace_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    return ngx_lua_shdict_api_set_helper(shm_zone, key, value, exptime,
        NGX_HTTP_LUA_SHDICT_REPLACE);
}


ngx_int_t
ngx_lua_shdict_api_replace(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_replace_locked(shm_zone,
        key, value, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_delete_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key)
{
    ngx_str_t value;
    ngx_str_null(&value);
    return ngx_lua_shdict_set_helper(shm_zone, key, value, 0, 0, 0, 0, 0);
}


ngx_int_t
ngx_lua_shdict_api_delete(ngx_shm_zone_t *shm_zone,
    ngx_str_t key)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_delete_locked(shm_zone, key);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_add(lua_State *L)
{
    return ngx_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_ADD);
}


static int
ngx_lua_shdict_safe_add(lua_State *L)
{
    return ngx_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_ADD
                                              |NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


static int
ngx_lua_shdict_replace(lua_State *L)
{
    return ngx_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_REPLACE);
}


static int
ngx_lua_shdict_set(lua_State *L)
{
    return ngx_lua_shdict_lua_set_helper(L, 0);
}


static int
ngx_lua_shdict_safe_set(lua_State *L)
{
    return ngx_lua_shdict_lua_set_helper(L, NGX_HTTP_LUA_SHDICT_SAFE_STORE);
}


static int
ngx_lua_shdict_lua_set_helper(lua_State *L, int flags)
{
    ngx_str_t                    key;
    ngx_int_t                    rc;
    lua_Number                   exptime = 0;
    ngx_shm_zone_t              *shm_zone = NULL;
    ngx_lua_shdict_ctx_t        *ctx;
    ngx_lua_value_t              value;
    int                          forcible = 0;
    int                          n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 5) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    value = ngx_lua_get_value(L, 3);
    if (!value.valid) {
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    if (value.type == SHDICT_TNIL &&
        (flags & (NGX_HTTP_LUA_SHDICT_ADD|NGX_HTTP_LUA_SHDICT_REPLACE))) {
        lua_pushnil(L);
        lua_pushliteral(L, "attempt to add or replace nil values");
        return 2;
    }

    if (n >= 4 && !lua_isnil(L, 4)) {
        exptime = luaL_checknumber(L, 4);
        if (exptime < 0) {
            return luaL_error(L, "bad \"exptime\" argument");
        }
    }

    if (n == 5 && !lua_isnil(L, 5)) {
        value.user_flags = (uint32_t) luaL_checkinteger(L, 5);
    }

    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_set_helper(shm_zone, key,
        ngx_lua_value_to_raw(&value), value.type,
        (int64_t) (exptime * 1000), value.user_flags, flags, &forcible);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {
    case NGX_LUA_SHDICT_OK:
        break;

    case NGX_LUA_SHDICT_NOT_FOUND:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "not found");
        lua_pushboolean(L, 0);
        return 3;

    case NGX_LUA_SHDICT_EXISTS:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "exists");
        lua_pushboolean(L, 0);
        return 3;

    case NGX_LUA_SHDICT_NO_MEMORY:
        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        lua_pushboolean(L, forcible);
        return 3;

    default:
        break;
        /* not reachable */
    }

    lua_pushboolean(L, 1);
    lua_pushnil(L);
    lua_pushboolean(L, forcible);
    return 3;
}


static int
ngx_lua_shdict_incr(lua_State *L)
{
    ngx_str_t                      key;
    ngx_int_t                      rc;
    ngx_lua_shdict_ctx_t     *ctx;
    ngx_shm_zone_t                *shm_zone = NULL;
    int                            forcible = 0;
    int                            n = lua_gettop(L);

    ngx_lua_shdict_incr_ctx_t userctx = {
        .val = nan("NaN"),
        .inc = 1
    };

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 4) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    userctx.inc = luaL_checknumber(L, 3);

    if (n == 4 && !lua_isnil(L, 4)) {
        userctx.val = luaL_checknumber(L, 4);
    } else {
        n = 3;
    }

    dd("looking up key %.*s in shared dict %.*s", (int) key.len, key.data,
       (int) ctx->name.len, ctx->name.data);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_fun_helper(shm_zone, key,
        ngx_lua_shdict_incr_getter,
        ngx_lua_shdict_api_errlog, 0, 0, &userctx, 1, &forcible);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        lua_pushnumber(L, userctx.val);
        lua_pushnil(L);
        if (n == 4) {
            lua_pushboolean(L, forcible);
            return 3;
        }
        return 2;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "not a number");
        lua_pushboolean(L, forcible);
        return 3;

    case NGX_LUA_SHDICT_NO_MEMORY:

        lua_pushnil(L);
        lua_pushliteral(L, "no memory");
        lua_pushboolean(L, forcible);
        return 3;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        lua_pushliteral(L, "not found");
        return 2;

    default:

        break;
    }

    lua_pushnil(L);
    lua_pushliteral(L, "unexpected");

    return 2;
}


ngx_int_t
ngx_lua_shared_dict_get(ngx_shm_zone_t *zone, u_char *key_data,
    size_t key_len, ngx_lua_value_t *value)
{
    ngx_str_t key = { .data = key_data, .len = key_len };
    return ngx_lua_shdict_api_get(zone, key, value);
}


extern char *
ngx_lua_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


ngx_shm_zone_t *
ngx_lua_add_shared_dict(char *(*add)(ngx_conf_t *cf, ngx_conf_t *conf),
    lua_State *L, ngx_conf_t *cf, ngx_str_t name, ngx_str_t size)
{
    ngx_conf_t            *conf;
    ngx_str_t             *val;
    ngx_shm_zone_t        *zone;
    ngx_shm_zone_t       **zone_udata;
    volatile ngx_cycle_t  *saved;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_conf_t));
    if (conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no memory");
        return NULL;
    }

    ngx_memcpy(conf, cf, sizeof(ngx_conf_t));

    conf->args = ngx_array_create(cf->pool, 3, sizeof(ngx_str_t));
    if (conf->args == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no memory");
        return NULL;
    }

    val = conf->args->elts;

    ngx_str_set(&val[0], "lua_shared_dict");

    val[1].len = name.len;
    val[2].len = size.len;

    val[1].data = ngx_pcalloc(cf->pool, name.len + 1);
    val[2].data = ngx_pcalloc(cf->pool, size.len + 1);

    if (val[1].data == NULL || val[2].data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "no memory");
        return NULL;
    }

    ngx_memcpy(val[1].data, name.data, name.len);
    ngx_memcpy(val[2].data, size.data, size.len);

    if (add(cf, conf) == NGX_CONF_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
           "failed to add \"lua_shared_dict %V %V\"", &name, &size);
        return NULL;
    }

    saved = ngx_cycle;
    ngx_cycle = cf->cycle;
    zone = ngx_lua_find_zone(name.data, name.len);
    ngx_cycle = saved;

    if (L == NULL) {
        return zone;
    }

    lua_getglobal(L, "ngx");
    if (lua_isnil(L, -1)) {
        return zone;
    }

    lua_getfield(L, -1, "shared");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return zone;
    }

    /* shared mt key */
    lua_pushlstring(L, (char *) name.data, name.len);

    /* table of zone[i] */
    lua_createtable(L, 1 /* narr */, 0 /* nrec */);
    /* shared mt key ud */
    zone_udata = lua_newuserdata(L, sizeof(ngx_shm_zone_t *));
    *zone_udata = zone;
    /* {zone} */
    lua_rawseti(L, -2, SHDICT_USERDATA_INDEX);
    /* shared mt key ud mt */
    luaL_getmetatable(L, "ngx_lua_shdict");
    /* shared mt key ud */
    lua_setmetatable(L, -2);
    /* shared mt */
    lua_rawset(L, -3);

    lua_pop(L, 2);

    return zone;
}


static ngx_int_t
ngx_lua_shdict_push_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value, int flags, uint32_t *len)
{
    int                              n;
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t               *node;
    ngx_lua_shdict_list_node_t *lnode;
    ngx_queue_t                     *queue;
    ngx_str_t                        raw_value;

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

    switch (value.type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        if (value.value.s.len > MAX_SHDICT_QUEUE_VALUE_SIZE) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "queue push: value too big, "
                          "max: %d, provided: %d", MAX_SHDICT_QUEUE_VALUE_SIZE,
                          value.value.s.len);
            return NGX_LUA_SHDICT_ERROR;
        }
        break;

    default:

        break;
    }

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    /* exists but expired */

    if (rc == NGX_DONE) {

        if (sd->value_type != SHDICT_TLIST) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict push: found old entry and value "
                           "type not matched, remove it first");

            ngx_lua_shdict_rbtree_delete_node(ctx, sd);

            dd("go to init_list");
            goto init_list;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict push: found old entry and value "
                       "type matched, reusing it");

        sd->expires = 0;

        /* free list nodes */

        ngx_lua_shdict_list_free(ctx, sd);

        queue = ngx_lua_shdict_list_get(sd, key.len);

        ngx_queue_init(queue);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* exists and not expired */

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {

            return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
        }

        queue = ngx_lua_shdict_list_get(sd, key.len);

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        dd("go to push_node");
        goto push_node;
    }

    /* rc == NGX_DECLINED, not found */

init_list:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new entry");

    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_lua_shdict_node_t, data)
        + key.len
        + sizeof(ngx_queue_t);

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

    dd("length after aligned: %d", n);

    node = ngx_slab_alloc_locked(ctx->shpool, n);

    if (node == NULL) {

        return NGX_LUA_SHDICT_NO_MEMORY;
    }

    sd = (ngx_lua_shdict_node_t *) &node->color;

    queue = ngx_lua_shdict_list_get(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = 0;

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TLIST);

    sd->value_type = (uint8_t) SHDICT_TLIST;

    ngx_memcpy(sd->data, key.data, key.len);

    ngx_queue_init(queue);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

push_node:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict list: creating a new list node");

    raw_value = ngx_lua_value_to_raw(&value);

    n = offsetof(ngx_lua_shdict_list_node_t, data)
        + raw_value.len;

    dd("list node length: %d", n);

    lnode = ngx_slab_alloc_locked(ctx->shpool, n);

    if (lnode == NULL) {

        if (sd->value_len == 0) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict list: no memory for create"
                           " list node and list empty, remove it");

            ngx_lua_shdict_rbtree_delete_node(ctx, sd);
        }

        return NGX_LUA_SHDICT_NO_MEMORY;
    }

    dd("setting list length to %d", sd->value_len + 1);

    sd->value_len = sd->value_len + 1;

    dd("setting list node value length to %d", (int) raw_value.len);

    lnode->value_len = (uint32_t) raw_value.len;

    dd("setting list node value type to %d", value.type);

    lnode->value_type = (uint8_t) value.type;

    ngx_memcpy(lnode->data, raw_value.data, raw_value.len);

    if (flags == NGX_HTTP_LUA_SHDICT_LEFT) {
        ngx_queue_insert_head(queue, &lnode->queue);

    } else {

        ngx_queue_insert_tail(queue, &lnode->queue);
    }

    *len = sd->value_len;

    return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_rpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value)
{
    uint32_t len;
    return ngx_lua_shdict_push_helper(shm_zone,
        key, value, NGX_HTTP_LUA_SHDICT_RIGHT, &len);
}


ngx_int_t
ngx_lua_shdict_api_rpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_rpush_locked(shm_zone,
        key, value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t ngx_lua_shdict_api_lpush_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value)
{
    uint32_t len;
    return ngx_lua_shdict_push_helper(shm_zone,
        key, value, NGX_HTTP_LUA_SHDICT_LEFT, &len);
}


ngx_int_t ngx_lua_shdict_api_lpush(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t value)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_lpush_locked(shm_zone,
        key, value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_lua_push_helper(lua_State *L, int flags)
{
    ngx_int_t                        rc;
    ngx_shm_zone_t                  *shm_zone = NULL;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_str_t                        key;
    ngx_lua_value_t             value;
    uint32_t                         len = 0;
    int                              n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 3)
        != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    value = ngx_lua_get_value(L, 3);
    if (!value.valid) {
        lua_pushnil(L);
        lua_pushliteral(L, "bad value type");
        return 2;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_push_helper(shm_zone, key, value, flags, &len);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        lua_pushnumber(L, len);
        return 1;

    case NGX_LUA_SHDICT_NO_MEMORY:

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;

    default:

        break;
    }

    return luaL_error(L, "unexpected");
}


static int
ngx_lua_shdict_lpush(lua_State *L)
{
    return ngx_lua_shdict_lua_push_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


static int
ngx_lua_shdict_rpush(lua_State *L)
{
    return ngx_lua_shdict_lua_push_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


static ngx_int_t
ngx_lua_shdict_pop_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value, int flags)
{
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_queue_t                     *queue;
    ngx_lua_shdict_list_node_t *lnode;
    u_char                          *data;
    size_t                           len;

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TLIST) {

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    queue = ngx_lua_shdict_list_get(sd, key.len);

    queue = flags == NGX_HTTP_LUA_SHDICT_LEFT ?
            ngx_queue_head(queue) : ngx_queue_last(queue);

    lnode = ngx_queue_data(queue, ngx_lua_shdict_list_node_t, queue);

    value->type = lnode->value_type;

    dd("data: %p", lnode->data);
    dd("value len: %d", (int) sd->value_len);

    data = lnode->data;
    len = (size_t) lnode->value_len;

    switch (value->type) {

    case SHDICT_TSTRING:
    case SHDICT_TUSERDATA:

        if (value->value.s.data == NULL || value->value.s.len < len) {

            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "queue pop: value buffet too small, "
                          "required: %d, provided: %d", len, value->value.s.len);
            return NGX_LUA_SHDICT_ERROR;
        }

        value->value.s.len = len;
        ngx_memcpy(value->value.s.data, data, len);
        break;

    case SHDICT_TNUMBER:

        value->value.n = *(lua_Number *) data;
        break;

    case SHDICT_TBOOLEAN:

        value->value.b = data[0];
        break;

    case SHDICT_TNULL:

        ngx_memzero(&value->value, sizeof(value->value));
        break;

    default:

        /* is not possible because length was checked in push */

        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                      "bad list node value type found for key %s in "
                      "shared_dict %s: %d, aborting ...", key.data, ctx->name.data,
                      value->type);

        ngx_abort();
    }

    value->valid = 1;

    ngx_queue_remove(queue);

    ngx_slab_free_locked(ctx->shpool, lnode);

    if (sd->value_len == 1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict list: empty node after pop, "
                       "remove it");

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);

    } else {
        sd->value_len = sd->value_len - 1;

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_rpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    return ngx_lua_shdict_pop_helper(shm_zone,
        key, value, NGX_HTTP_LUA_SHDICT_RIGHT);
}


ngx_int_t
ngx_lua_shdict_api_rpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_rpop_locked(shm_zone,
        key, value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_lpop_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    return ngx_lua_shdict_pop_helper(shm_zone,
        key, value, NGX_HTTP_LUA_SHDICT_LEFT);
}


ngx_int_t
ngx_lua_shdict_api_lpop(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_lua_value_t *value)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_lpop_locked(shm_zone,
        key, value);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_lua_pop_helper(lua_State *L, int flags)
{
    ngx_str_t                        key;
    ngx_int_t                        rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t                  *shm_zone = NULL;
    u_char                           buf[MAX_SHDICT_QUEUE_VALUE_SIZE];
    ngx_lua_value_t             value;
    int                              n = lua_gettop(L);

    value.value.s.data = buf;
    value.value.s.len = sizeof(buf);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_pop_helper(shm_zone,
        key, &value, flags);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {
    case NGX_LUA_SHDICT_OK:

        ngx_lua_shdict_value_push(L, &value);
        return 1;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        return 1;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;

    default:

        /* unreachable */
        break;
    }

    return luaL_error(L, "unexpected");
}


static int
ngx_lua_shdict_lpop(lua_State *L)
{
    return ngx_lua_shdict_lua_pop_helper(L, NGX_HTTP_LUA_SHDICT_LEFT);
}


static int
ngx_lua_shdict_rpop(lua_State *L)
{
    return ngx_lua_shdict_lua_pop_helper(L, NGX_HTTP_LUA_SHDICT_RIGHT);
}


ngx_int_t
ngx_lua_shdict_api_llen_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len)
{
    uint32_t                     hash;
    ngx_int_t                    rc;
    ngx_lua_shdict_ctx_t   *ctx;
    ngx_lua_shdict_node_t  *sd;

    if (!len) {

        return NGX_LUA_SHDICT_ERROR;
    }

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TLIST) {

            return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
        }

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

        *len = sd->value_len;
        return NGX_LUA_SHDICT_OK;
    }

    *len = 0;
    return NGX_LUA_SHDICT_NOT_FOUND;
}


ngx_int_t
ngx_lua_shdict_api_llen(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_llen_locked(shm_zone,
        key, len);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_llen(lua_State *L)
{
    ngx_str_t                    key;
    ngx_shm_zone_t              *shm_zone = NULL;
    uint32_t                     len = 0;
    int                          n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    switch (ngx_lua_shdict_api_llen(shm_zone, key, &len)) {

    case NGX_LUA_SHDICT_OK:
    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnumber(L, len);
        return 1;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a list");
        return 2;

    case NGX_LUA_SHDICT_ERROR:

        /* unreachable */
        break;
    }

    return luaL_error(L, "unexpected");
}


static ngx_int_t
ngx_lua_shdict_fun_pcall(ngx_lua_value_t *value,
   int stale, void *userctx)
{
    ngx_lua_shdict_userctx_t *ctx = userctx;
    lua_State                *L = ctx->L;

    /* push lua clojure */
    lua_pushvalue(L, ctx->index);

    /* push value */
    switch (value->type) {

    case SHDICT_TNIL:
    case SHDICT_TSTRING:
    case SHDICT_TNUMBER:
    case SHDICT_TBOOLEAN:
    case SHDICT_TNULL:

        ngx_lua_shdict_value_push(L, value);
        break;

    default:

        ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR,
                     "bad value type found for key %s in "
                     "shared_dict %s: %d", ctx->key.data, ctx->name.data,
                     value->type);

        return NGX_LUA_SHDICT_ERROR;
    }

    lua_pushinteger(L, value->user_flags);

    if (lua_pcall(L, 2, 2, 0) != 0) {

        /*  error occurred when calling user code */
        ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR, "%s", lua_tostring(L, -1));
        return NGX_LUA_SHDICT_ERROR;
    }

    value->type = lua_type(L, -2);

    switch (value->type) {

    case SHDICT_TSTRING:

        value->value.s.data = (u_char *) lua_tolstring(L, -2, &value->value.s.len);
        break;

    case SHDICT_TNUMBER:

        value->value.n = lua_tonumber(L, -2);
        break;

    case SHDICT_TBOOLEAN:

        value->value.b = lua_toboolean(L, -2);
        break;

    case SHDICT_TNIL:

        ngx_str_null(&value->value.s);
        break;

    case SHDICT_TNULL:

        ngx_memzero(&value->value, sizeof(value->value));
        break;

    default:

        ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR, "bad value type");
        return NGX_LUA_SHDICT_ERROR;
    }

    value->user_flags = (uint32_t) lua_tointeger(L, -1);

    return NGX_LUA_SHDICT_OK;
}


static int
ngx_lua_shdict_fun(lua_State *L)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx;
    lua_Number                 exptime = 0;
    ngx_shm_zone_t            *shm_zone = NULL;
    int                        n = lua_gettop(L);
    ngx_lua_shdict_userctx_t   userctx = {
        .L = L, .get_stale = 0, .index = 3
    };

    userctx.err[0] = 0;

    ngx_str_null(&userctx.key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &userctx.key, 3, 4) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    if (lua_type(L, 3) != LUA_TFUNCTION) {
        return luaL_error(L, "bad \"callback\" argument");
    }

    ctx = shm_zone->data;
    userctx.name = ctx->name;

    if (n == 4 && !lua_isnil(L, 4)) {
        exptime = luaL_checknumber(L, 4);
        if (exptime < 0) {
            return luaL_error(L, "bad \"exptime\" argument");
        }
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_fun_helper(shm_zone, userctx.key,
        ngx_lua_shdict_fun_pcall,
        ngx_lua_shdict_get_helper_err_handler,
        0, ngx_lua_get_expires(exptime),
        &userctx, 1, NULL);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (rc == NGX_LUA_SHDICT_ERROR) {

        return luaL_error(L, userctx.err[0] ? (const char *) userctx.err :
            "unexpected");
    }

    return 2;
}


static int
ngx_lua_shared_dict_capacity(lua_State *L)
{
    ngx_shm_zone_t   *zone;
    int               n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting only zone argument, "
                          "but only seen %d", n);
    }

    if (lua_type(L, 1) != LUA_TTABLE) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    zone = ngx_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    lua_pushnumber(L, zone->shm.size);

    return 1;
}


#    if nginx_version >= 1011007
static int
ngx_lua_shared_dict_free_space(lua_State *L)
{
    ngx_shm_zone_t              *zone;
    size_t                       bytes;
    ngx_lua_shdict_ctx_t   *ctx;
    int                          n = lua_gettop(L);

    if (n != 1) {
        return luaL_error(L, "expecting only zone argument, "
                          "but only seen %d", n);
    }

    zone = ngx_lua_shdict_get_zone(L, 1);
    if (zone == NULL) {
        return luaL_error(L, "bad \"zone\" argument");
    }

    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);
    bytes = ctx->shpool->pfree * ngx_pagesize;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushnumber(L, bytes);

    return 1;
}
#    endif /* nginx_version >= 1011007 */


ngx_int_t
ngx_lua_shdict_api_ttl_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl)
{
    uint32_t                     hash;
    uint64_t                     now;
    ngx_int_t                    rc;
    ngx_time_t                  *tp;
#if (NGX_DEBUG)
    ngx_lua_shdict_ctx_t   *ctx;
#endif
    ngx_lua_shdict_node_t  *sd;

    if (!ttl) {

        return NGX_LUA_SHDICT_ERROR;
    }

    hash = ngx_crc32_short(key.data, key.len);

#if (NGX_DEBUG)
    ctx = shm_zone->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &ctx->name);
#endif /* NGX_DEBUG */

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    if (sd->expires == 0) {
        *ttl = 0;
        return NGX_LUA_SHDICT_OK;
    }

    tp = ngx_timeofday();
    now = (uint64_t) tp->sec * 1000 + tp->msec;

      *ttl = sd->expires - now;

      return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_ttl(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t *ttl)
{
    ngx_int_t              rc;
    ngx_lua_shdict_ctx_t  *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_ttl_locked(shm_zone,
        key, ttl);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shared_dict_ttl(lua_State *L)
{
    ngx_str_t                    key;
    ngx_shm_zone_t              *shm_zone = NULL;
    int64_t                      ttl = 0;
    int                          n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    switch (ngx_lua_shdict_api_ttl(shm_zone, key, &ttl)) {

    case NGX_LUA_SHDICT_OK:

        lua_pushnumber(L, (lua_Number ) ttl / 1000);
        return 1;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        lua_pushliteral(L, "not found");
        return 2;

    default:

        /* unreachable */
        break;
    }

    return luaL_error(L, "unexpected");
}


ngx_int_t
ngx_lua_shdict_api_expire_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime)
{
    uint32_t                     hash;
    ngx_int_t                    rc;
#if (NGX_DEBUG)
    ngx_lua_shdict_ctx_t   *ctx;
#endif
    ngx_lua_shdict_node_t  *sd;

    hash = ngx_crc32_short(key.data, key.len);

#if (NGX_DEBUG)
    ctx = shm_zone->data;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "fetching key \"%V\" in shared dict \"%V\"", &key, &ctx->name);
#endif /* NGX_DEBUG */

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    sd->expires = ngx_lua_get_expires(exptime);

    return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_expire(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, int64_t exptime)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_expire_locked(shm_zone,
        key, exptime);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shared_dict_expire(lua_State *L)
{
    ngx_str_t                    key;
    ngx_shm_zone_t              *shm_zone = NULL;
    lua_Number                   exptime;
    int                          n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 3) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    if (lua_isnil(L, 3)) {
        lua_pushnil(L);
        lua_pushliteral(L, "nil exptime");
        return 2;
    }

    exptime = luaL_checknumber(L, 3);
    if (exptime < 0) {
        return luaL_error(L, "bad \"exptime\" argument");
    }

    switch (ngx_lua_shdict_api_expire(shm_zone, key, (int64_t) (exptime * 1000))) {

    case NGX_LUA_SHDICT_OK:

        lua_pushboolean(L, 1);
        return 1;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        lua_pushliteral(L, "not found");
        return 2;

    default:

        /* unreachable */
        break;
    }

    return luaL_error(L, "unexpected");
}


static ngx_int_t
ngx_lua_shdict_api_zset_zkey(lua_State *L, ngx_str_t *zkey)
{
    *zkey = ngx_lua_get_string(L, 3);

    if (zkey->len == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "empty zkey");
        return NGX_ERROR;
    }

    if (zkey->len > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "zkey too long");
        return NGX_ERROR;
    }

    return NGX_OK;
}


typedef ngx_int_t (*zset_helper_t)(ngx_lua_value_t old,
    ngx_lua_value_t *value, void *userctx);


static ngx_int_t
ngx_lua_shdict_api_zset_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey,
    ngx_lua_value_t value, int exptime,
    uint32_t *len, int flags,
    zset_helper_t fun, void *userctx,
    ngx_lua_zset_destructor_t onfree)
{
    int                         n;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_str_t                   raw_value;
    ngx_str_t                   old_value;
    ngx_rbtree_node_t          *node = NULL;
    ngx_rbtree_node_t          *znode = NULL;
    ngx_rbtree_node_t          *sentinel;
    ngx_lua_shdict_zset_t      *zset = NULL;
    ngx_lua_shdict_zset_node_t *zset_node = NULL;
    u_char                      exists = 0;

    if (onfree == NULL) {

        onfree = free_stub;
    }

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DONE) {

        /* exists but expired */

        if (sd->value_type != SHDICT_TZSET) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "lua shared dict zset: found old entry and value "
                           "type not matched, remove it first");

            ngx_lua_shdict_rbtree_delete_node(ctx, sd);

            dd("go to init_zset");
            goto init_zset;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: found old entry and value "
                       "type matched, reusing it");

        /* free rbtree */

        ngx_lua_shdict_rbtree_free(ctx, sd);

        zset = ngx_lua_shdict_zset_get(sd, key.len);

        ngx_rbtree_init(&zset->rbtree, &zset->sentinel,
                        ngx_lua_shdict_zset_insert_value);

        sd->expires = ngx_lua_get_expires(exptime);

        sd->value_len = 0;

        dd("go to add_node");
        goto add_node;
    }

    /* exists and not expired */

    if (rc == NGX_OK) {

        if (sd->value_type != SHDICT_TZSET) {

            return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
        }

        zset = ngx_lua_shdict_zset_get(sd, key.len);

        dd("go to add_node");
        goto add_node;
    }

    /* rc == NGX_DECLINED, not found */

init_zset:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "lua shared dict zset: creating a new entry");

    /* NOTICE: we assume the begin point aligned in slab, be careful */
    n = offsetof(ngx_rbtree_node_t, color)
        + offsetof(ngx_lua_shdict_node_t, data)
        + key.len
        + sizeof(ngx_lua_shdict_zset_t);

    dd("length before aligned: %d", n);

    n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

    dd("length after aligned: %d", n);

    node = ngx_lua_shdict_calloc_locked(ctx, n);

    if (node == NULL) {

        return NGX_LUA_SHDICT_NO_MEMORY;
    }

    sd = (ngx_lua_shdict_node_t *) &node->color;

    zset = ngx_lua_shdict_zset_get(sd, key.len);

    node->key = hash;
    sd->key_len = (u_short) key.len;

    sd->expires = ngx_lua_get_expires(exptime);

    sd->value_len = 0;

    dd("setting value type to %d", (int) SHDICT_TZSET);

    sd->value_type = (uint8_t) SHDICT_TZSET;

    ngx_memcpy(sd->data, key.data, key.len);

    ngx_rbtree_init(&zset->rbtree, &zset->sentinel,
                    ngx_lua_shdict_zset_insert_value);

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

add_node:

    /* touch LRU queue */

    ngx_queue_remove(&sd->queue);
    ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);

    /* search first */

    znode = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (znode != sentinel) {

        zset_node = (ngx_lua_shdict_zset_node_t *) &znode->color;

        rc = ngx_strncmp(zkey.data, zset_node->data, zkey.len);

        if (rc < 0 || (rc == 0 && zset_node->data[zkey.len] != 0)) {

            znode = znode->left;
            continue;

        } else if (rc > 0) {

            znode = znode->right;
            continue;

        }

        /* found */

        if (flags & NGX_HTTP_LUA_SHDICT_ADD) {

            return NGX_LUA_SHDICT_EXISTS;
        }

        exists = 1;
        break;
    }

    if (!exists) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: creating a new zset node");

        /* NOTICE: we assume the begin point aligned in slab, be careful */
        n = offsetof(ngx_rbtree_node_t, color)
            + offsetof(ngx_lua_shdict_zset_node_t, data)
            + zkey.len + 1 /* zero terminated string key */;

        dd("length before aligned: %d", n);

        n = (int) (uintptr_t) ngx_align_ptr(n, NGX_ALIGNMENT);

        dd("length after aligned: %d", n);

        znode = ngx_lua_shdict_calloc_locked(ctx, n);

        if (znode == NULL) {

            rc = NGX_LUA_SHDICT_NO_MEMORY;
            goto check;
        }
    }

    zset_node = (ngx_lua_shdict_zset_node_t *) &znode->color;

    old_value = zset_node->value;

    if (fun && userctx) {

        if (fun(ngx_lua_raw_to_value(old_value, zset_node->value_type),
                &value, userctx) != NGX_LUA_SHDICT_OK) {

            rc = NGX_LUA_SHDICT_ERROR;
            goto delete_znode;
        }

        if (!value.valid) {

            rc = NGX_LUA_SHDICT_OK;
            goto delete_znode;
        }
    }

    if (value.valid) {

        raw_value = ngx_lua_value_to_raw(&value);

        dd("setting zset node value length to %d", (int) raw_value.len);

        zset_node->value_type = value.type;
        zset_node->value.len = raw_value.len;
        zset_node->value.data = ngx_lua_shdict_calloc_locked(ctx,
            (uintptr_t) ngx_align_ptr(raw_value.len, NGX_ALIGNMENT));

        if (zset_node->value.data == NULL) {

            rc = NGX_LUA_SHDICT_NO_MEMORY;
            goto delete_znode;
        }

        ngx_memcpy(zset_node->value.data, raw_value.data, raw_value.len);
    } else {

        ngx_str_null(&zset_node->value);
        zset_node->value_type = SHDICT_TNIL;
    }

    if (old_value.data) {

        (* (ngx_lua_zset_destructor_t) zset_node->free)(old_value.data,
            old_value.len);
        ngx_slab_free_locked(ctx->shpool, old_value.data);
    }

    zset_node->free = onfree;

    if (!exists) {

        sd->value_len = sd->value_len + 1;
        dd("setting zset length to %d", sd->value_len);

        ngx_memcpy(zset_node->data, zkey.data, zkey.len);
        zset_node->data[zkey.len] = 0;

        ngx_rbtree_insert(&zset->rbtree, znode);
    }

    if (len) {

        *len = sd->value_len;
    }

    return NGX_LUA_SHDICT_OK;

delete_znode:

    if (znode != NULL) {

        if (exists) {

            ngx_rbtree_delete(&zset->rbtree, znode);
            sd->value_len = sd->value_len - 1;
        }

        zset_node = (ngx_lua_shdict_zset_node_t *) &znode->color;

        if (zset_node->value.data != NULL) {

            (* (ngx_lua_zset_destructor_t) zset_node->free)
                (zset_node->value.data, zset_node->value.len);
            ngx_slab_free_locked(ctx->shpool, zset_node->value.data);
        }

        ngx_slab_free_locked(ctx->shpool, znode);
    }

check:

       if (len) {

           *len = sd->value_len;
       }

    if (sd->value_len == 0) {

        /* delete shdict key */
        ngx_lua_shdict_rbtree_delete_node(ctx, sd);
    }

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_zset_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t value, int exptime,
    ngx_lua_zset_destructor_t onfree)
{
    return ngx_lua_shdict_api_zset_helper(shm_zone,
        key, zkey, value, exptime, NULL, 0, NULL, NULL, onfree);
}


ngx_int_t
ngx_lua_shdict_api_zset(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey,
    ngx_lua_value_t value, int exptime,
    ngx_lua_zset_destructor_t onfree)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zset_locked(shm_zone,
        key, zkey, value, exptime, onfree);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


ngx_int_t
ngx_lua_shdict_api_zadd_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey,
    ngx_lua_value_t value, int exptime,
    ngx_lua_zset_destructor_t onfree)
{
    return ngx_lua_shdict_api_zset_helper(shm_zone,
        key, zkey, value, exptime, NULL,
        NGX_HTTP_LUA_SHDICT_ADD, NULL, NULL, onfree);
}


ngx_int_t
ngx_lua_shdict_api_zadd(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey,
    ngx_lua_value_t value, int exptime,
    ngx_lua_zset_destructor_t onfree)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zadd_locked(shm_zone,
        key, zkey, value, exptime, onfree);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static ngx_int_t
ngx_lua_shdict_newval(ngx_lua_value_t old,
    ngx_lua_value_t *value, void *userctx)
{
    ngx_lua_shdict_userctx_t *ctx = userctx;
    lua_State                *L = ctx->L;

    /* callback */
    lua_pushvalue(L, ctx->index);

    /* push old value */
    ngx_lua_shdict_value_push(L, &old);

    if (lua_pcall(L, 1, 1, 0) != 0) {

        /*  error occurred when calling user code */
        ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR, "%s", lua_tostring(L, -1));
        return NGX_LUA_SHDICT_ERROR;
    }

    *value = ngx_lua_get_value(L, -1);

    if (value->type == SHDICT_TNIL) {

        value->valid = 0;
    }

    return NGX_LUA_SHDICT_OK;
}


static int
ngx_lua_shdict_zset_helper(lua_State *L, int flags)
{
    ngx_lua_value_t             value;
    ngx_shm_zone_t             *shm_zone = NULL;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_str_t                   zkey;
    lua_Number                  exptime = 0;
    uint32_t                    len = 0;
    ngx_int_t                   rc;
    zset_helper_t               fun = NULL;
    int                         n = lua_gettop(L);
    ngx_lua_shdict_userctx_t    userctx = {
        .L = L, .get_stale = 0, .index = 4
    };

    userctx.err[0] = 0;

    ngx_str_null(&userctx.key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &userctx.key, 3, 5)
            != NGX_OK
        ||  ngx_lua_shdict_api_zset_zkey(L, &zkey) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    value.valid = 0;

    if (n > 3) {

        if (lua_type(L, 4) != LUA_TFUNCTION) {

            value = ngx_lua_get_value(L, 4);

            if (!value.valid) {
                lua_pushnil(L);
                lua_pushliteral(L, "bad value type");
                return 2;
            }
        } else {

            fun = ngx_lua_shdict_newval;
        }

        if (n == 5 && !lua_isnil(L, 5)) {
            exptime = luaL_checknumber(L, 5);
            if (exptime < 0) {
                return luaL_error(L, "bad \"exptime\" argument");
            }
        }
    }

    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zset_helper(shm_zone, userctx.key, zkey, value,
        exptime * 1000, &len, flags, fun, &userctx, NULL);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        break;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;

    case NGX_LUA_SHDICT_NO_MEMORY:

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "no memory");
        return 2;


    case NGX_LUA_SHDICT_EXISTS:

        lua_pushboolean(L, 0);
        lua_pushliteral(L, "exists");
        return 2;

    case NGX_LUA_SHDICT_ERROR:

        lua_pushnil(L);
        lua_pushstring(L, userctx.err[0] ? (const char *) userctx.err :
                       "unknown");
        return 2;

    default:

        /* unreachable */
        break;
    }


    lua_pushnumber(L, len);

    return 1;
}


static int
ngx_lua_shdict_zset(lua_State *L)
{
    return ngx_lua_shdict_zset_helper(L, 0);
}


static int
ngx_lua_shdict_zadd(lua_State *L)
{
    return ngx_lua_shdict_zset_helper(L, NGX_HTTP_LUA_SHDICT_ADD);
}


static ngx_int_t
ngx_lua_shdict_api_zrem_helper(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, lua_State *L)
{
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t          *node;
    ngx_rbtree_node_t          *sentinel;
    ngx_lua_shdict_zset_t      *zset;
    ngx_lua_shdict_zset_node_t *zset_node;

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    zset = ngx_lua_shdict_zset_get(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (node != sentinel) {

        zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

        rc = ngx_strncmp(zkey.data, zset_node->data, zkey.len);

        if (rc < 0 || (rc == 0 && zset_node->data[zkey.len] != 0)) {

            node = node->left;
            continue;

        } else if (rc > 0) {

            node = node->right;
            continue;

        }

        /* found */

        if (L) {
            ngx_lua_shdict_zset_znode_value_push(L, zset_node);
        }

        if (zset_node->value.data) {

            (* (ngx_lua_zset_destructor_t) zset_node->free)
                (zset_node->value.data, zset_node->value.len);
            ngx_slab_free_locked(ctx->shpool, zset_node->value.data);
        }

        ngx_rbtree_delete(&zset->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);

        sd->value_len = sd->value_len - 1;

        goto ret;
    }

    return NGX_LUA_SHDICT_NOT_FOUND;

ret:

    dd("value len: %d", (int) sd->value_len);

    if (sd->value_len <= 0) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                       "lua shared dict zset: empty node after zrem, "
                       "remove it");

        ngx_lua_shdict_rbtree_delete_node(ctx, sd);
    } else {

        ngx_queue_remove(&sd->queue);
        ngx_queue_insert_head(&ctx->sh->lru_queue, &sd->queue);
    }

    return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_zrem_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey)
{
    return ngx_lua_shdict_api_zrem_helper(shm_zone, key, zkey, NULL);
}


ngx_int_t
ngx_lua_shdict_api_zrem(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zrem_locked(shm_zone, key, zkey);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_zrem(lua_State *L)
{
    ngx_str_t                   key;
    ngx_str_t                   zkey;
    ngx_shm_zone_t             *shm_zone = NULL;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_int_t                   rc;
    int                         n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 3) != NGX_OK ||
        ngx_lua_shdict_api_zset_zkey(L, &zkey) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    n = lua_gettop(L);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zrem_helper(shm_zone, key, zkey, L);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        return 1;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        return 1;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;

    default:

        /* unreachable */
        break;
    }

    return 0;
}


ngx_int_t
ngx_lua_shdict_api_zcard_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len)
{
    uint32_t                         hash;
    ngx_int_t                        rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;

    if (!len) {

        return NGX_LUA_SHDICT_ERROR;
    }

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        *len = 0;
        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    if (sd->value_type != SHDICT_TZSET) {

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    *len = sd->value_len;

    return NGX_LUA_SHDICT_OK;

}


ngx_int_t
ngx_lua_shdict_api_zcard(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, uint32_t *len)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zcard_locked(shm_zone, key, len);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_zcard(lua_State *L)
{
    ngx_str_t        key;
    ngx_shm_zone_t  *shm_zone = NULL;
    uint32_t         len = 0;
    int              n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    switch (ngx_lua_shdict_api_zcard(shm_zone, key, &len)) {

    case NGX_LUA_SHDICT_OK:
    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushinteger(L, len);
        return 1;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;

    default:

        /* unreachable */
        break;
    }

    return luaL_error(L, "unexpected");
}


ngx_int_t
ngx_lua_shdict_api_zget_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t *value)
{
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t          *node;
    ngx_rbtree_node_t          *sentinel;
    ngx_lua_shdict_zset_t      *zset;
    ngx_lua_shdict_zset_node_t *zset_node;

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    zset = ngx_lua_shdict_zset_get(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    while (node != sentinel) {

        zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

        rc = ngx_strncmp(zkey.data, zset_node->data, zkey.len);

        if (rc < 0 || (rc == 0 && zset_node->data[zkey.len] != 0)) {

            node = node->left;
            continue;

        } else if (rc > 0) {

            node = node->right;
            continue;

        }

        *value = ngx_lua_shdict_zset_znode_value_get(zset_node);

        return NGX_LUA_SHDICT_OK;
    }

    return NGX_LUA_SHDICT_NOT_FOUND;
}


ngx_int_t
ngx_lua_shdict_api_zget(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_str_t zkey, ngx_lua_value_t *value)
{
    ngx_int_t             rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;
    ngx_lua_value_t       tmp;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zget_locked(shm_zone,
        key, zkey, &tmp);

    if (rc == NGX_LUA_SHDICT_OK && value) {

        rc = ngx_lua_shdict_copy_value(value, &tmp);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}


static int
ngx_lua_shdict_zget(lua_State *L)
{
    ngx_str_t                   key;
    ngx_str_t                   zkey;
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t             *shm_zone = NULL;
    ngx_lua_value_t             value;
    int                         n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 3) != NGX_OK ||
        ngx_lua_shdict_api_zset_zkey(L, &zkey) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zget_locked(shm_zone,
        key, zkey, &value);

    n = lua_gettop(L);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        lua_pushlstring(L, (char *) zkey.data,  zkey.len);
        ngx_lua_shdict_value_push(L, &value);
        break;

    case NGX_LUA_SHDICT_NOT_FOUND:

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        break;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        break;

    default:

        lua_pushnil(L);
        lua_pushliteral(L, "unexpected");
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return lua_gettop(L) - n;
}


static int
ngx_lua_shdict_zgetall(lua_State *L)
{
    ngx_str_t                   key;
    uint32_t                    hash;
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_lua_shdict_node_t      *sd;
    ngx_rbtree_node_t          *node;
    ngx_rbtree_node_t          *sentinel;
    ngx_shm_zone_t             *shm_zone = NULL;
    ngx_lua_shdict_zset_t      *zset;
    ngx_lua_shdict_zset_node_t *zset_node;
    int                              n = lua_gettop(L);

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 2, 2) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    ctx = shm_zone->data;

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

#if 1
    ngx_lua_shdict_expire(ctx, 1);
#endif

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        lua_pushnil(L);
        return 1;
    }

    /* rc == NGX_OK */

    if (sd->value_type != SHDICT_TZSET) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;
    }

    zset = ngx_lua_shdict_zset_get(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    lua_createtable(L, sd->value_len, 0);

    if (node != sentinel) {
        n = 1;

        for (node = ngx_rbtree_min(node, sentinel);
             node;
             node = ngx_rbtree_next(&zset->rbtree, node))
        {
            zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

            lua_createtable(L, 2, 0);

            /* push zkey */
            lua_pushstring(L, (char *) zset_node->data);
            lua_rawseti(L, -2, 1);

            /* push zvalue */
            ngx_lua_shdict_zset_znode_value_push(L, zset_node);
            lua_rawseti(L, -2, 2);

            lua_rawseti(L, -2, n++);
        }
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


ngx_int_t
ngx_lua_shdict_api_zscan_locked(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_fun_t fun, ngx_str_t lbound, void *userctx)
{
    uint32_t                       hash;
    ngx_int_t                      rc;
    ngx_lua_shdict_node_t         *sd;
    ngx_rbtree_node_t             *node;
    ngx_rbtree_node_t             *tmp = NULL;
    ngx_rbtree_node_t             *sentinel;
    ngx_lua_shdict_zset_t         *zset;
    ngx_lua_shdict_zset_node_t    *zset_node;
    ngx_str_t                      zkey;
    ngx_lua_value_t                value;

    hash = ngx_crc32_short(key.data, key.len);

    rc = ngx_lua_shdict_lookup(shm_zone, hash, key.data, key.len, &sd);

    dd("shdict lookup returned %d", (int) rc);

    if (rc == NGX_DECLINED || rc == NGX_DONE) {

        return NGX_LUA_SHDICT_NOT_FOUND;
    }

    if (sd->value_type != SHDICT_TZSET) {

        return NGX_LUA_SHDICT_BAD_VALUE_TYPE;
    }

    zset = ngx_lua_shdict_zset_get(sd, key.len);

    node = zset->rbtree.root;
    sentinel = zset->rbtree.sentinel;

    if (node != sentinel) {

        if (lbound.data != NULL) {

            while (node != sentinel) {

                zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

                rc = ngx_strncmp(lbound.data, zset_node->data, lbound.len);

                if (rc <= 0) {

                    if (rc == 0) {
                        tmp = node;
                    }

                    node = node->left;

                    continue;

                } else if (rc > 0) {

                    node = node->right;
                    continue;

                }
            }

            if (tmp != NULL) {
                node = tmp;
            }
        } else {

            node = ngx_rbtree_min(node, sentinel);
        }

        if (node != sentinel) {

            for (; node; node = ngx_rbtree_next(&zset->rbtree, node))
            {
                zset_node = (ngx_lua_shdict_zset_node_t *) &node->color;

                zkey.data = zset_node->data;
                zkey.len = ngx_strlen(zkey.data);

                value = ngx_lua_shdict_zset_znode_value_get(zset_node);

                rc = fun(zkey, &value, userctx);

                if (rc != NGX_LUA_SHDICT_OK) {

                    if (rc == NGX_LUA_SHDICT_ZSCAN_STOP) {

                        break;
                    }

                    if (rc == NGX_LUA_SHDICT_ERROR) {

                        return NGX_LUA_SHDICT_ERROR;
                    }
                }
            }
        }
    }

    return NGX_LUA_SHDICT_OK;
}


ngx_int_t
ngx_lua_shdict_api_zscan(ngx_shm_zone_t *shm_zone,
    ngx_str_t key, ngx_http_fun_t fun, ngx_str_t lbound, void *userctx)
{
    ngx_int_t                  rc;
    ngx_lua_shdict_ctx_t *ctx = shm_zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_lua_shdict_api_zscan_locked(shm_zone,
        key, fun, lbound, userctx);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return rc;
}



ngx_int_t
ngx_lua_shdict_zscan_getter(ngx_str_t zkey, ngx_lua_value_t *value,
    void *userctx)
{
    ngx_lua_shdict_userctx_t *ctx = userctx;
    lua_State                *L = ctx->L;
    u_char                   *err_msg;
    int                       b;
    int                       n = lua_gettop(L);

    lua_pushvalue(L, ctx->index);

    /* push zkey */
    lua_pushlstring(L, (char *) zkey.data, zkey.len);

    /* push zvalue */
    ngx_lua_shdict_get_helper_push_value(value, 0, userctx);

    if (lua_pcall(L, lua_gettop(L) - n - 1, 1, 0) == 0) {

        b = lua_toboolean(L, -1);
    } else {

        /*  error occurred when calling user code */
        err_msg = (u_char *) lua_tostring(L, -1);

        if (err_msg == NULL) {
            err_msg = (u_char *) "unknown";
        }

        ngx_snprintf(ctx->err, NGX_MAX_ERROR_STR,
                     "user callback error shared_dict %s: %s",
                     ctx->name.data, err_msg);

        b = 1;
    }

    lua_settop(L, n);

    return b;
}


static int
ngx_lua_shdict_zscan(lua_State *L)
{
    ngx_int_t                   rc;
    ngx_lua_shdict_ctx_t       *ctx;
    ngx_shm_zone_t             *shm_zone = NULL;
    ngx_str_t                   key;
    ngx_str_t                   lbound;
    int                         n = lua_gettop(L);
    ngx_lua_shdict_userctx_t    userctx = {
        .L = L, .get_stale = 0, .index = 3
    };

    ngx_str_null(&key);

    if (ngx_lua_shdict_check_required(L, &shm_zone, &key, 3, 4) != NGX_OK) {
        return lua_gettop(L) - n;
    }

    if (lua_type(L, 3) != LUA_TFUNCTION) {
        return luaL_error(L, "bad \"callback\" argument");
    }

    ctx = shm_zone->data;
    userctx.name = ctx->name;

    if (n == 4) {
        lbound.data = (u_char *) lua_tolstring(L, 4, &lbound.len);
    } else {
        lbound.data = NULL;
    }

    rc = ngx_lua_shdict_api_zscan(shm_zone,
        key, ngx_lua_shdict_zscan_getter, lbound, &userctx);

    switch (rc) {

    case NGX_LUA_SHDICT_OK:

        lua_pushboolean(L, 1);
        break;

    case NGX_LUA_SHDICT_NOT_FOUND:

        lua_pushnil(L);
        break;

    case NGX_LUA_SHDICT_BAD_VALUE_TYPE:

        lua_pushnil(L);
        lua_pushliteral(L, "value not a zset");
        return 2;

    case NGX_LUA_SHDICT_ERROR:

        lua_pushnil(L);
        lua_pushstring(L, userctx.err[0] ? (const char *) userctx.err
            : "unknown");
        break;

    default:

        break;
    }

    return 1;
}


ngx_int_t
ngx_lua_shdict_api_rps(ngx_shm_zone_t *shm_zone,
    uint32_t *count, uint32_t *rps)
{
    ngx_lua_shm_zone_ctx_t *zone_ctx;
    ngx_lua_shdict_ctx_t   *ctx;

    zone_ctx = (ngx_lua_shm_zone_ctx_t *) shm_zone->data;
    shm_zone = &zone_ctx->zone;

    ctx = shm_zone->data;

    if (ngx_current_msec - ctx->sh->last > 1000) {
        ctx->sh->rps = 1000 * ctx->sh->count[0] /
            ngx_max(1000, ngx_current_msec - ctx->sh->last);
        ctx->sh->last = ngx_current_msec;
        ctx->sh->count[1] = ctx->sh->count[0];
        ctx->sh->count[0] = 0;
    }

    *count = ctx->sh->count[1];
    *rps = ctx->sh->rps;

    return NGX_LUA_SHDICT_OK;
}


ngx_shm_zone_t *
ngx_lua_find_zone(u_char *name_data, size_t name_len)
{
    ngx_str_t                       *name;
    ngx_uint_t                       i;
    ngx_shm_zone_t                  *zone;
    ngx_lua_shm_zone_ctx_t          *ctx;
    volatile ngx_list_part_t        *part;

    part = &ngx_cycle->shared_memory.part;
    zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            zone = part->elts;
            i = 0;
        }

        name = &zone[i].shm.name;

        dd("name: [%.*s] %d", (int) name->len, name->data, (int) name->len);
        dd("name2: [%.*s] %d", (int) name_len, name_data, (int) name_len);

        if (name->len == name_len
            && ngx_strncmp(name->data, name_data, name_len) == 0)
        {
            ctx = (ngx_lua_shm_zone_ctx_t *) zone[i].data;
            return &ctx->zone;
        }
    }

    return NULL;
}

ngx_shm_zone_t *
ngx_lua_ffi_shdict_udata_to_zone(void *zone_udata)
{
    if (zone_udata == NULL)
        return NULL;

    return *(ngx_shm_zone_t **) zone_udata;
}
