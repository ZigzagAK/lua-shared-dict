/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#ifndef NGX_LUA_SHDICT_DEFS_H
#define NGX_LUA_SHDICT_DEFS_H


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    u_char                       color;
    uint8_t                      value_type;
    u_short                      key_len;
    uint32_t                     value_len;
    uint64_t                     expires;
    ngx_queue_t                  queue;
    uint32_t                     user_flags;
    u_char                       data[1];
} ngx_lua_shdict_node_t;


typedef struct {
    ngx_queue_t                  queue;
    uint32_t                     value_len;
    uint8_t                      value_type;
    u_char                       data[1];
} ngx_lua_shdict_list_node_t;


typedef struct {
    u_char                       color;
    uint8_t                      value_type;
    ngx_str_t                    value;
    void                        *free;
    void                        *lua;
    u_char                       data[1];
} ngx_lua_shdict_zset_node_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
} ngx_lua_shdict_zset_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  lru_queue;

    /* additional fields */

    ngx_msec_t                   last;
    uint32_t                     count[2];
    uint32_t                     rps;
    ngx_atomic_t                 rwlock;
} ngx_lua_shdict_shctx_t;


typedef struct {
    ngx_lua_shdict_shctx_t       *sh;
    ngx_slab_pool_t              *shpool;
    ngx_str_t                     name;
    ngx_log_t                    *log;
} ngx_lua_shdict_ctx_t;


/* MUST BE MATCHED with ngx_xxx_lua_shm_zone_ctx_t */

typedef struct {
    ngx_log_t                    *log;
    void                         *lmcf;
    ngx_cycle_t                  *cycle;
    ngx_shm_zone_t                zone;
} ngx_lua_shm_zone_ctx_t;


#endif /* NGX_LUA_SHDICT_DEFS_H */
