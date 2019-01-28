/*
 * Copyright (c) 2019 Danila Vershinin ( https://www.getpagespeed.com )
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SECURITY_HEADER_OMIT  0

#define NGX_HTTP_XSS_HEADER_OFF        1
#define NGX_HTTP_XSS_HEADER_ON         2
#define NGX_HTTP_XSS_HEADER_BLOCK      3

#define NGX_HTTP_FO_HEADER_SAME        1
#define NGX_HTTP_FO_HEADER_DENY        2


typedef struct {
    ngx_flag_t                 enable;
    
    ngx_uint_t                 xss;  
    ngx_uint_t                 fo; 
    
    ngx_hash_t                 nosniff_types;
    ngx_array_t                *types_keys;

} ngx_http_security_headers_loc_conf_t;

static ngx_conf_enum_t  ngx_http_xss_protection[] = {
    { ngx_string("off"),    NGX_HTTP_XSS_HEADER_OFF },
    { ngx_string("on"),     NGX_HTTP_XSS_HEADER_ON },
    { ngx_string("block"),  NGX_HTTP_XSS_HEADER_BLOCK },
    { ngx_string("omit"),   NGX_HTTP_SECURITY_HEADER_OMIT },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t  ngx_http_frame_options[] = {
    { ngx_string("sameorigin"),  NGX_HTTP_FO_HEADER_SAME },
    { ngx_string("deny"),        NGX_HTTP_FO_HEADER_DENY },
    { ngx_string("omit"),        NGX_HTTP_SECURITY_HEADER_OMIT },
    { ngx_null_string, 0 }
};

static ngx_int_t ngx_http_security_headers_filter(ngx_http_request_t *r);
static void *ngx_http_security_headers_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_security_headers_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_security_headers_init(ngx_conf_t *cf);

ngx_str_t  ngx_http_security_headers_default_nosniff_types[] = {
    ngx_string("text/css"),
    ngx_string("text/javascript"),
    ngx_string("application/javascript"),
    ngx_null_string
};

static ngx_command_t  ngx_http_security_headers_commands[] = {

    { ngx_string( "security_headers" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_security_headers_loc_conf_t, enable ),
      NULL },    
    
    { ngx_string("security_headers_nosniff_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, types_keys),
      &ngx_http_security_headers_default_nosniff_types[0] },      
      
    { ngx_string("security_headers_xss"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, xss),
      ngx_http_xss_protection },
      
     { ngx_string("security_headers_frame"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_security_headers_loc_conf_t, fo),
      ngx_http_frame_options },     
  
      ngx_null_command
};


static ngx_http_module_t  ngx_http_security_headers_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_security_headers_init,        /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_security_headers_create_loc_conf,   /* create location configuration */
    ngx_http_security_headers_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_security_headers_module = {
    NGX_MODULE_V1,
    &ngx_http_security_headers_module_ctx,       /* module context */
    ngx_http_security_headers_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* next header filter in chain */

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


/* header filter handler */

static ngx_int_t
ngx_http_security_headers_filter(ngx_http_request_t *r)
{
    ngx_table_elt_t                       *h_x_cto;
    ngx_table_elt_t                       *h_x_xss;
    ngx_table_elt_t                       *h_x_fo;
    ngx_http_security_headers_loc_conf_t  *slcf;

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_security_headers_module);

    if (1 != slcf->enable) {
        return ngx_http_next_header_filter(r);
    }
    
    /* add X-Content-Type-Options to output */
    if (r->headers_out.status == NGX_HTTP_OK 
            && ngx_http_test_content_type(r, &slcf->nosniff_types) != NULL) {
        h_x_cto = ngx_list_push(&r->headers_out.headers);
        if (h_x_cto == NULL) {
            return NGX_ERROR;
        }

        h_x_cto->hash = 1;
        ngx_str_set(&h_x_cto->key, "X-Content-Type-Options");
        ngx_str_set(&h_x_cto->value, "nosniff");
    }
    
    /* Add X-XSS-Protection */
    if (r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && NGX_HTTP_SECURITY_HEADER_OMIT != slcf->xss) {
        h_x_xss = ngx_list_push(&r->headers_out.headers);
        if (h_x_xss == NULL) {
            return NGX_ERROR;
        }

        h_x_xss->hash = 1;
        ngx_str_set(&h_x_xss->key, "X-XSS-Protection");
        if (NGX_HTTP_XSS_HEADER_ON == slcf->xss) {
            ngx_str_set(&h_x_xss->value, "1");
        } else if (NGX_HTTP_XSS_HEADER_BLOCK == slcf->xss) {
            ngx_str_set(&h_x_xss->value, "1; mode=block");
        } else if (NGX_HTTP_XSS_HEADER_OFF == slcf->xss) {
            ngx_str_set(&h_x_xss->value, "0");
        }
    }
    
     /* Add X-Frame-Options */
    if (r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && NGX_HTTP_SECURITY_HEADER_OMIT != slcf->fo) {
        h_x_fo = ngx_list_push(&r->headers_out.headers);
        if (h_x_fo == NULL) {
            return NGX_ERROR;
        }

        h_x_fo->hash = 1;
        ngx_str_set(&h_x_fo->key, "X-Frame-Options");
        if (NGX_HTTP_FO_HEADER_SAME == slcf->fo) {
            ngx_str_set(&h_x_fo->value, "SAMEORIGIN");
        } else if (NGX_HTTP_FO_HEADER_DENY == slcf->fo) {
            ngx_str_set(&h_x_fo->value, "DENY");
        } 
    }
    
    /* Deal with Server header */
    ngx_table_elt_t   *h_server;
    h_server = r->headers_out.server;
    if (h_server == NULL) {
        h_server = ngx_list_push(&r->headers_out.headers);
        if (h_server == NULL) {
            return NGX_ERROR;
        }     
        /*
         * h->key.data = (u_char *) "Server";
         * h->key.len = sizeof("Server") - 1;
         * h->value.data = (u_char *) "";
         * h->value.len = sizeof("") - 1;
         */
        
        r->headers_out.server = h_server;
    } 
    h_server->hash = 0;
    
    /* Find X-Powered-By header */
    ngx_list_part_t *part = NULL;
    ngx_table_elt_t *header = NULL;

    part = &r->headers_out.headers.part;
    header = part->elts;
    for (ngx_uint_t i = 0 ; ; i++ ) {
        if ( i >= part->nelts) {
            if ( part->next == NULL ) {
                    break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }
        if (header[i].hash == 0) {
             continue;
        }
        if ( ngx_strcasecmp(header[i].key.data, (u_char *)"x-powered-by") == 0 ) {
            header[i].hash = 0;
            break;
        }
    }
   
    /* proceed to the next handler in chain */

    return ngx_http_next_header_filter(r);
}


static void *
ngx_http_security_headers_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_security_headers_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_security_headers_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    
    conf->xss =    NGX_CONF_UNSET_UINT;
    conf->fo  =    NGX_CONF_UNSET_UINT;
    conf->enable = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_security_headers_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_security_headers_loc_conf_t *prev = parent;
    ngx_http_security_headers_loc_conf_t *conf = child;

    ngx_conf_merge_value( conf->enable, prev->enable, 0 );
    
    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->nosniff_types,
                             &prev->types_keys, &prev->nosniff_types,
                             ngx_http_security_headers_default_nosniff_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    
    ngx_conf_merge_uint_value(conf->xss, prev->xss,
                              NGX_HTTP_XSS_HEADER_BLOCK);

    ngx_conf_merge_uint_value(conf->fo, prev->fo,
                              NGX_HTTP_FO_HEADER_SAME);    

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_security_headers_init(ngx_conf_t *cf)
{
    /* install handler in header filter chain */

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_security_headers_filter;

    return NGX_OK;
}