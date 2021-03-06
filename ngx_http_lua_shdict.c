/*
 * Copyright (C) Aleksey Konovkin (alkon2000@mail.ru).
 */

#include <ngx_config.h>
#include <ngx_http.h>

#include <ngx_http_lua_api.h>

ngx_module_t ngx_http_lua_shdict_module;

static ngx_int_t ngx_http_lua_shdict_init(ngx_conf_t *cf);


static ngx_http_module_t ngx_http_lua_shdict_ctx = {
    NULL,                      /* preconfiguration */
    ngx_http_lua_shdict_init,  /* postconfiguration */
    NULL,                      /* create main configuration */
    NULL,                      /* init main configuration */
    NULL,                      /* create server configuration */
    NULL,                      /* merge server configuration */
    NULL,                      /* create location configuration */
    NULL                       /* merge location configuration */
};


ngx_module_t ngx_http_lua_shdict_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_shdict_ctx , /* module context */
    NULL,                      /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING
};


extern ngx_module_t ngx_http_lua_module;


extern ngx_int_t
ngx_lua_shdict_init(lua_State *L, ngx_conf_t *cf, void *tag);

extern ngx_shm_zone_t *
ngx_lua_add_shared_dict(char *(*add)(ngx_conf_t *cf, ngx_conf_t *conf),
    lua_State *L, ngx_conf_t *cf, ngx_str_t name, ngx_str_t size);

extern char *
ngx_http_lua_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_int_t
ngx_http_lua_shdict_init(ngx_conf_t *cf)
{
    return ngx_lua_shdict_init(ngx_http_lua_get_global_state(cf), cf,
        &ngx_http_lua_module);
}


static char *
lua_shared_dict(ngx_conf_t *cf, ngx_conf_t *conf)
{
    ngx_command_t  null_cmd = ngx_null_command;
    return ngx_http_lua_shared_dict(conf, &null_cmd,
        ngx_http_conf_get_module_main_conf(cf, ngx_http_lua_module));
}


ngx_shm_zone_t *
ngx_http_lua_add_shared_dict(ngx_conf_t *cf, ngx_str_t name, ngx_str_t size)
{
    return ngx_lua_add_shared_dict(lua_shared_dict,
        ngx_http_lua_get_global_state(cf), cf, name, size);
}
