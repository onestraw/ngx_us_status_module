
/*
 * Copyright (C) Xiaowei He (hexiaowei91@gmail.com)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_stream.h>


#define UPSTREAM_HEADER_CSV     "[non-backup]number,total_weight\n"
#define UPSTREAM_DATA_CSV       "%d,%d\n"
#define UPSTREAM_PEER_SEPARATOR "\n"
#define PEER_HEADER_CSV         "server,weight,max_fails,fail_timeout,"\
                                "backup,down,status\n"
#define PEER_DATA_CSV           "%s,%d,%d,%d,%d,%d,%d\n"
#define UINT_MAX_SIZE           5
#define FLAG_MAX_SIZE           1
#define PORT_MAX_SIZE           UINT_MAX_SIZE
#define IPV6_MAX_SIZE           45
#define US_STATUS_HEADER_SIZE   (sizeof(UPSTREAM_HEADER_CSV) +\
                                sizeof(UPSTREAM_PEER_SEPARATOR) +\
                                sizeof(PEER_HEADER_CSV))
#define UPSTREAM_RECORD_SIZE    (UINT_MAX_SIZE * 2 + 2)
#define PEER_RECORD_SIZE        (IPV6_MAX_SIZE + PORT_MAX_SIZE +\
                                UINT_MAX_SIZE * 4 + FLAG_MAX_SIZE * 2 + 8)


static ngx_str_t ngx_us_status_argument_name[] = {
    ngx_string("arg_type"),
    ngx_string("arg_upstream"),
};


typedef struct ngx_us_status_argument {
    ngx_str_t type;
    ngx_str_t upstream;
} ngx_us_status_argument_t;


static ngx_int_t ngx_us_status_handler(ngx_http_request_t *r);
static char *ngx_set_us_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_us_status_commands[] = {

    { ngx_string("us_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_set_us_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_us_status_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};


ngx_module_t  ngx_us_status_module = {
    NGX_MODULE_V1,
    &ngx_us_status_module_ctx,             /* module context */
    ngx_us_status_commands,                /* module directives */
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


static ngx_inline ngx_uint_t
ngx_http_check_peer_down(ngx_http_upstream_rr_peer_t *peer)
{
#if (NGX_HTTP_UPSTREAM_CHECK)
	return ngx_http_upstream_check_peer_down(peer->check_index);
#else
	return 2;
#endif
}


static ngx_inline ngx_uint_t
ngx_stream_check_peer_down(ngx_stream_upstream_rr_peer_t *peer)
{
#if (NGX_STREAM_UPSTREAM_CHECK)
	return ngx_stream_upstream_check_peer_down(peer->check_index);
#else
	return 2;
#endif
}


#if !(NGX_HTTP_UPSTREAM_CHECK)
/* refer to https://github.com/yaoweibin/nginx_upstream_check_module */
static ngx_shm_zone_t *
ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) &(cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len) != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            continue;
        }

        return &shm_zone[i];
    }

    return NULL;
}
#endif


#define FUNCTION_GENERATOR(typename)\
static ngx_##typename##_upstream_srv_conf_t *\
ngx_us_status_##typename##_get_uscf(ngx_str_t *upstream)\
{\
    ngx_uint_t                              i;\
    ngx_str_t                              *shm_name;\
    ngx_shm_zone_t                         *shm_zone;\
    ngx_##typename##_upstream_srv_conf_t  **uscfp;\
    ngx_##typename##_upstream_main_conf_t  *umcf;\
\
    shm_zone = ngx_shared_memory_find((ngx_cycle_t *) ngx_cycle,\
                                      upstream,\
                                      &ngx_##typename##_upstream_module);\
    if (!shm_zone) {    \
        return NULL;\
    }\
\
    umcf = shm_zone->data;\
    uscfp = umcf->upstreams.elts;\
\
    for (i = 0; i < umcf->upstreams.nelts; i++) {\
        if (uscfp[i]->shm_zone == NULL) {\
            continue;\
        }\
\
        shm_name = &(uscfp[i]->shm_zone->shm.name);\
        if (shm_name->len == upstream->len &&\
            ngx_strncmp(shm_name->data, upstream->data, upstream->len) == 0)\
        {\
            return uscfp[i];\
        }\
    }\
\
    return NULL;\
}\
\
\
static ngx_inline void \
ngx_us_status_##typename##_dump_peers(\
    ngx_##typename##_upstream_rr_peers_t *peers,\
    ngx_flag_t backup, ngx_buf_t *b)\
{\
    ngx_uint_t                            status;\
    ngx_##typename##_upstream_rr_peer_t  *peer;\
\
    for (peer = peers->peer; peer; peer = peer->next) {\
        if (backup || peer->down) {\
            status = 0;\
        } else {\
            status = 1 - ngx_##typename##_check_peer_down(peer);\
        }\
\
        b->last = ngx_snprintf(b->last, b->end - b->last, PEER_DATA_CSV,\
                               peer->name.data, peer->weight, peer->max_fails,\
                               peer->fail_timeout, backup, peer->down, status);\
    }\
}\
\
\
static ngx_int_t \
ngx_us_status_##typename##_create_csv_response(\
    ngx_##typename##_upstream_rr_peers_t *peers, ngx_buf_t *b)\
{\
    ngx_flag_t                       backup;\
\
    b->last = ngx_snprintf(b->last, b->end - b->last, UPSTREAM_HEADER_CSV);\
    b->last = ngx_snprintf(b->last, b->end - b->last, UPSTREAM_DATA_CSV,\
                           peers->number, peers->total_weight);\
\
    b->last = ngx_snprintf(b->last, b->end - b->last,\
                           UPSTREAM_PEER_SEPARATOR PEER_HEADER_CSV);\
\
    for (backup = 0; peers; peers = peers->next, backup++) {\
        ngx_us_status_##typename##_dump_peers(peers, backup, b);\
    }\
\
    return NGX_OK;\
}\
\
\
static ngx_int_t \
ngx_us_status_##typename##_create_response(ngx_http_request_t *r,\
    ngx_str_t *upstream_name, ngx_chain_t *out)\
{\
    size_t                                 size;\
    ngx_int_t                              rc;\
    ngx_buf_t                             *b;\
    ngx_##typename##_upstream_srv_conf_t  *uscf;\
    ngx_##typename##_upstream_rr_peers_t  *peers;\
\
    uscf = ngx_us_status_##typename##_get_uscf(upstream_name);\
    if (uscf == NULL) {\
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,\
                      "zone: %V is not found", upstream_name);\
        return NGX_HTTP_NOT_FOUND;\
    }\
\
    size = 0;\
    peers = (ngx_##typename##_upstream_rr_peers_t *)uscf->peer.data;\
    if (peers) {\
        size = peers->number;\
        if (peers->next) {\
            size += peers->next->number;\
        }\
    }\
\
    size = US_STATUS_HEADER_SIZE +\
           UPSTREAM_RECORD_SIZE +\
           size * PEER_RECORD_SIZE;\
\
    b = ngx_create_temp_buf(r->pool, size);\
    if (b == NULL) {\
        return NGX_HTTP_INTERNAL_SERVER_ERROR;\
    }\
\
    out->buf = b;\
    out->next = NULL;\
\
    rc = ngx_us_status_##typename##_create_csv_response(peers, b);\
\
    if (rc == NGX_ERROR) {\
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,\
                      "us_status: failed to create response");\
        return NGX_HTTP_INTERNAL_SERVER_ERROR;\
    }\
\
    r->headers_out.status = NGX_HTTP_OK;\
    r->headers_out.content_length_n = b->last - b->pos;\
\
    b->last_buf = (r == r->main) ? 1 : 0;\
    b->last_in_chain = 1;\
\
    return NGX_OK;\
}


FUNCTION_GENERATOR(http);
#if (NGX_STREAM_UPSTREAM_ZONE)
FUNCTION_GENERATOR(stream);
#endif
#undef FUNCTION_GENERATOR


static ngx_int_t
ngx_us_status_parse_args(ngx_http_request_t *r, ngx_us_status_argument_t *lbarg)
{
    u_char                           low[12];
    ngx_uint_t                       i, size, key;
    ngx_str_t                       *arg_name;
    ngx_http_variable_value_t       *var;

    size = sizeof(ngx_us_status_argument_name) / sizeof(ngx_str_t);
    for (i = 0; i < size; i++) {
        arg_name = &ngx_us_status_argument_name[i];
        key = ngx_hash_strlow(low, arg_name->data, arg_name->len);
        var = ngx_http_get_variable(r, arg_name, key);

        if (var->not_found) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "us_status: %V is not found", arg_name);
            return NGX_HTTP_NOT_FOUND;
        }

        if (ngx_strncmp(arg_name->data, "arg_type", 8) == 0) {
            lbarg->type.data = var->data;
            lbarg->type.len = var->len;
        } else if (ngx_strncmp(arg_name->data, "arg_upstream", 12) == 0) {
            lbarg->upstream.data = var->data;
            lbarg->upstream.len = var->len;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_us_status_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_chain_t                      out;
    ngx_us_status_argument_t         lbargs;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_us_status_parse_args(r, &lbargs);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_strncasecmp(lbargs.type.data, (u_char *) "http", 4) == 0) {
        rc = ngx_us_status_http_create_response(r, &lbargs.upstream, &out);
    } else if (ngx_strncasecmp(lbargs.type.data, (u_char *) "stream", 5) == 0) {
        rc = ngx_us_status_stream_create_response(r, &lbargs.upstream, &out);
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "us_status: unsupported type");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_set_us_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_us_status_handler;

    return NGX_CONF_OK;
}
