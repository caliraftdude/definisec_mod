#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_module_t ngx_http_auth_token_module;

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
  ngx_str_t cookie = (ngx_str_t)ngx_string("auth_token");
  ngx_str_t cookie_value;
  ngx_int_t location = ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &cookie, &cookie_value);

  /* This is the same no matter which branch we go through */
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;

  if (location == NGX_DECLINED) {
    ngx_str_set(&h->key, "location");
    ngx_str_set(&h->value, "http://google.com");
    return NGX_HTTP_MOVED_TEMPORARILY;

  } else {
    ngx_str_set(&h->key, "X-Auth-Token");
    h->value = cookie_value;

  }

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



