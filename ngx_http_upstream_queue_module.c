#include <ngx_http.h>
#include "ngx_http_upstream.c"
#include "queue.h"

ngx_module_t ngx_http_upstream_queue_module;

typedef struct {
    ngx_http_upstream_peer_t peer;
    ngx_msec_t timeout;
    ngx_uint_t max;
    queue_t queue;
} ngx_http_upstream_queue_srv_conf_t;

typedef struct {
    ngx_event_t timeout;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    queue_t queue;
} ngx_http_upstream_queue_data_t;

static void ngx_http_upstream_queue_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_http_upstream_queue_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    if (queue_empty(&qscf->queue)) return;
    queue_t *q = queue_head(&qscf->queue);
    queue_remove(q);
    d = queue_data(q, ngx_http_upstream_queue_data_t, queue);
    queue_init(&d->queue);
    r = d->request;
    u = r->upstream;
    ngx_connection_t *c = u->peer.connection;
    if (c->read->timer_set) ngx_del_timer(c->read);
    if (c->write->timer_set) ngx_del_timer(c->write);
    ngx_http_upstream_connect(r, u);
}

static void ngx_http_upstream_queue_cleanup_handler(void *data) {
    ngx_http_upstream_queue_data_t *d = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    if (!queue_empty(&d->queue)) queue_remove(&d->queue);
    if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
}

static void ngx_http_upstream_queue_timeout_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_http_request_t *r = e->data;
    if (!r->connection || r->connection->error) return;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
}

static ngx_int_t ngx_http_upstream_queue_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_http_upstream_queue_data_t *d = data;
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc);
    if (rc != NGX_BUSY) return rc;
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    if (queue_size(&qscf->queue) >= qscf->max) return rc;
    ngx_pool_cleanup_t *cln;
    if (!(cln = ngx_pool_cleanup_add(r->pool, 0))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add"); return NGX_ERROR; }
    cln->handler = ngx_http_upstream_queue_cleanup_handler;
    cln->data = d;
    d->timeout.data = r;
    d->timeout.handler = ngx_http_upstream_queue_timeout_handler;
    d->timeout.log = pc->log;
    ngx_add_timer(&d->timeout, qscf->timeout);
    queue_insert_tail(&qscf->queue, &d->queue);
    if (u->peer.connection) return NGX_AGAIN;
    if (!(u->peer.connection = ngx_pcalloc(r->pool, sizeof(*u->peer.connection)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    ngx_connection_t *c = u->peer.connection;
    if (!(c->read = ngx_pcalloc(r->pool, sizeof(*c->read)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    if (!(c->write = ngx_pcalloc(r->pool, sizeof(*c->write)))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pcalloc"); return NGX_ERROR; }
    c->read->data = c;
    c->read->log = pc->log;
    c->write->data = c;
    c->write->log = pc->log;
    return NGX_AGAIN;
}

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_queue_peer_set_session(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_queue_data_t *d = data;
    return d->peer.set_session(pc, d->peer.data);
}

static void ngx_http_upstream_queue_peer_save_session(ngx_peer_connection_t *pc, void *data) {
    ngx_http_upstream_queue_data_t  *d = data;
    d->peer.save_session(pc, d->peer.data);
}
#endif

static ngx_int_t ngx_http_upstream_queue_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    ngx_http_upstream_queue_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) return NGX_ERROR;
    queue_init(&d->queue);
    if (qscf->peer.init(r, uscf) != NGX_OK) return NGX_ERROR;
    ngx_http_upstream_t *u = r->upstream;
    d->peer = u->peer;
    d->request = r;
    u->peer.data = d;
    u->peer.free = ngx_http_upstream_queue_peer_free;
    u->peer.get = ngx_http_upstream_queue_peer_get;
#if (NGX_HTTP_SSL)
    u->peer.save_session = ngx_http_upstream_queue_peer_save_session;
    u->peer.set_session = ngx_http_upstream_queue_peer_set_session;
#endif
    return NGX_OK;
}

static ngx_int_t ngx_http_upstream_queue_peer_init_upstream(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    ngx_conf_init_msec_value(qscf->timeout, 60000);
    if (qscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "init_upstream != NGX_OK"); return NGX_ERROR; }
    qscf->peer.init = uscf->peer.init;
    uscf->peer.init = ngx_http_upstream_queue_peer_init;
    queue_init(&qscf->queue);
    return NGX_OK;
}

static void *ngx_http_upstream_queue_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_upstream_queue_srv_conf_t *conf;
    if (!(conf = ngx_pcalloc(cf->pool, sizeof(*conf)))) return NULL;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    return conf;
}

static char *ngx_http_upstream_queue_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_queue_srv_conf_t *qscf = conf;
    if (qscf->max) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    ngx_int_t n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || !n) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\" in \"%V\" directive", &value[1], &cmd->name); return NGX_CONF_ERROR; }
    qscf->max = n;
    if (cf->args->nelts > 2) {
        if (value[2].len <= sizeof("timeout=") - 1 || ngx_strncmp(value[2].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid name \"%V\" in \"%V\" directive", &value[2], &cmd->name); return NGX_CONF_ERROR; }
        value[2].data += sizeof("timeout=") - 1;
        value[2].len -= sizeof("timeout=") - 1;
        ngx_int_t n = ngx_parse_time(&value[2], 0);
        if (n == NGX_ERROR) return "ngx_parse_time == NGX_ERROR";
        qscf->timeout = (ngx_msec_t)n;
    }
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    qscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_http_upstream_queue_peer_init_upstream;
    return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_upstream_queue_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = NULL,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_http_upstream_queue_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = NULL,
    .merge_loc_conf = NULL
};

static ngx_command_t ngx_http_upstream_queue_commands[] = {
  { ngx_string("queue"), NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12, ngx_http_upstream_queue_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
    ngx_null_command
};

ngx_module_t ngx_http_upstream_queue_module = {
    NGX_MODULE_V1,
    .ctx = &ngx_http_upstream_queue_ctx,
    .commands = ngx_http_upstream_queue_commands,
    .type = NGX_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NGX_MODULE_V1_PADDING
};
