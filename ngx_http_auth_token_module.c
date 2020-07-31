#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <string.h>
#include "hiredis/hiredis.h"

/* Forward declarations */
ngx_module_t ngx_http_auth_token_module;
static ngx_int_t lookup_user(ngx_str_t *auth_token, ngx_str_t *user_id);
static ngx_int_t redirect(ngx_http_request_t *r, ngx_str_t *location);
static void append_user_id(ngx_http_request_t *r, ngx_str_t *user_id);

/* auth_token_main_conf
 * a structure to hold all of the configuration options in one place
 */
typedef struct {
  ngx_str_t   redis_host;
  ngx_int_t   redis_port;
  ngx_str_t   cookie_name;
  ngx_str_t   redirect_location;
} auth_token_main_conf_t;

/* ngx_http_auth_token_commands
 * Static array that holds the directives and their configuration so the nginx engine knows how to store,
 * parse and locate them.
 */
static ngx_command_t ngx_http_auth_token_commands[] = {
  {
    ngx_string("auth_token_redis_host"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redis_host),
    NULL
  },
  {
    ngx_string("auth_token_redis_port"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redis_port),
    NULL
  },
  {
    ngx_string("auth_token_cookie_name"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, cookie_name),
    NULL
  },
  {
    ngx_string("auth_token_redirect_location"),
    NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_MAIN_CONF_OFFSET,
    offsetof(auth_token_main_conf_t, redirect_location),
    NULL
  },

  ngx_null_command
};

/*
 * ngx_auth_token_handler()
 * This is run when the request is processed.  It coordinates all the actions of the module.
 * It accepts the parsed request and then acts on it.
 * The internal flag indicates if this processing has happened already because there are cases
 * where the handler could be called multiple times and we want to avoid duplicate processing
 * in this case.
 *
 * In this case a new entry is made for response headers which is fairly simplistic.
 */

static ngx_int_t
ngx_http_auth_token_handler(ngx_http_request_t *r)
{
  /* avoid re-entry */
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  r->main->internal = 1;

  /* set up the variables we are going to need */
  ngx_str_t location = (ngx_str_t)ngx_string("http://google.com");
  ngx_str_t cookie = (ngx_str_t)ngx_string("auth_token");
  ngx_str_t auth_token;
  ngx_int_t lookup = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie, &auth_token);

  if (lookup == NGX_DECLINED) {
    return redirect(r, &location);
  }

  ngx_str_t user_id;
  ngx_int_t lookup_result = lookup_user(&auth_token, &user_id);

  if (lookup_result == NGX_DECLINED) {
    return redirect(r, &location);
  }

  append_user_id(r, &user_id);
  return NGX_DECLINED;

}

/*
 * ngx_http_auth_token_init()
 * The init function wires the handler to the proper phase in the nginx life-cycle.  It gets the core
 * nginxvconfiguration struct and creates an entry in the NGX_HTTP_ACCESS_PHASE.  Lastly, it sets
 * the function in the handler to the ngx_http_auth_token_handler function.
 */


static ngx_int_t
ngx_http_auth_token_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_token_handler;

  return NGX_OK;
}

/*
 * lookup_user
 * This function accepts an auth toekn value and a vairalbe to hold the user_id if it is found.
 * A connection is made to redis and passed in the redisCommand.  If it succeeds, a string will
 * be returned.  If it fails, the return object will be of type REDIS_REPLY_NIL.
 */
static ngx_int_t
lookup_user(ngx_str_t *auth_token, ngx_str_t *user_id)
{
  redisContext *context = redisConnect("localhost", 6379);
  redisReply *reply = redisCommand(context, "GET %s", auth_token->data);

  if (reply->type == REDIS_REPLY_NIL ) {
    return NGX_DECLINED;
  }
    
  ngx_str_set(user_id, reply->str);
  return NGX_OK;

}

/*
 * redirect
 * Simple function to set up a redirect
 */
static ngx_int_t
redirect(ngx_http_request_t *r, ngx_str_t *location)
{
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "location");
  h->value = *location;

  return NGX_HTTP_MOVED_TEMPORARILY;

}

/*
 * append_user_id
 * Append_user_id takes a user id and appends it as ahte value in a new header 'X-User-Id'
 */
static void
append_user_id(ngx_http_request_t *r, ngx_str_t *user_id)
{
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_in.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "X-User-Id");
  h->value = *user_id;
}

/*
 * ngx_http_auth_token_module_ctx
 * This controls how the module is invoked.  The init function is called during the
 * postconfiguration phase - essentially telling nginx to call this function when
 * loading the module.
 *
 * More will be added later...
 */
static ngx_http_module_t ngx_http_auth_token_module_ctx = {
  NULL,                                 /* preconfiguration */
  ngx_http_auth_token_init,             /* postconfiguration */
  NULL,                                 /* create main configuration */
  NULL,                                 /* init main configuration */
  NULL,                                 /* create server configuration */
  NULL,                                 /* merge server configuration */
  NULL,                                 /* create location configuration */
  NULL                                  /* merge location configuration */
};

/*
 * ngx_http_auth_token_module
 * This is the module declaration.  Not much is here right now but the module context address
 * is passed in this structure as well as the type.
 *
 * More will be added later...
 */
ngx_module_t ngx_http_auth_token_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_token_module_ctx, /* module context */
  NULL,                            /* module directives */
  NGX_HTTP_MODULE,                 /* module type */
  NULL,                            /* init master */
  NULL,                            /* init module */
  NULL,                            /* init process */
  NULL,                            /* init thread */
  NULL,                            /* exit thread */
  NULL,                            /* exit process */
  NULL,                            /* exit master */
  NGX_MODULE_V1_PADDING
};



