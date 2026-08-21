#include <ngx_http.h>
#include "ngx_http_upstream.c"

ngx_module_t ngx_http_upstream_queue_module;

typedef struct {
    ngx_flag_t detect;
    ngx_flag_t draining;
    ngx_flag_t reentered;
    ngx_http_upstream_peer_t peer;
    ngx_msec_t timeout;
    ngx_msec_t retry_interval;
    ngx_uint_t max;
    ngx_uint_t size;
    ngx_queue_t queue;
    ngx_event_t retry;
} ngx_http_upstream_queue_srv_conf_t;

typedef struct {
    ngx_event_t connect_timeout;
    ngx_event_t timeout;
    ngx_http_request_t *request;
    ngx_peer_connection_t peer;
    ngx_queue_t queue;
} ngx_http_upstream_queue_data_t;

static void ngx_http_upstream_queue_retry_handler(ngx_event_t *e);
static void ngx_http_upstream_queue_refresh_peer(ngx_http_upstream_queue_data_t *d);

static void ngx_http_upstream_queue_retry_schedule(ngx_http_upstream_queue_srv_conf_t *qscf) {
    if (ngx_queue_empty(&qscf->queue) || qscf->retry.timer_set) return;
    qscf->retry.data = qscf;
    qscf->retry.handler = ngx_http_upstream_queue_retry_handler;
    qscf->retry.log = ngx_cycle->log;
    qscf->retry.cancelable = 1;
    /*
     * Backstop for requests nothing else will ever wake: peer.free()
     * only drains the queue when some *other* connection on this
     * upstream is released, so a request queued because the peer set
     * was empty/unhealthy (e.g. a `resolve` server before its first
     * successful DNS answer) would otherwise just sit until its own
     * queue timeout, even after a peer becomes selectable again. This
     * timer re-tries periodically instead, every retry_interval (the
     * "queue" directive's retry_interval= param, default 200ms); it
     * re-arms itself only while the queue is still non-empty, so an
     * idle upstream never gets a lingering wakeup.
     */
    ngx_add_timer(&qscf->retry, qscf->retry_interval);
}

static void ngx_http_upstream_queue_drain(ngx_http_upstream_queue_srv_conf_t *qscf) {
    if (qscf->draining) { qscf->reentered = 1; return; }
    qscf->draining = 1;
    while (!ngx_queue_empty(&qscf->queue)) {
        ngx_queue_t *q = ngx_queue_head(&qscf->queue);
        ngx_queue_remove(q);
        qscf->size--;
        ngx_http_upstream_queue_data_t *d = ngx_queue_data(q, ngx_http_upstream_queue_data_t, queue);
        if (d->connect_timeout.timer_set) ngx_del_timer(&d->connect_timeout);
        if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
        ngx_queue_init(&d->queue);
        /*
         * Refresh this request's round-robin snapshot before retrying
         * it, not just when the retry timer's own probe does it: this
         * drain loop also runs directly from peer_free() whenever some
         * other connection on the upstream genuinely frees a slot, and
         * without refreshing here, a request whose snapshot went stale
         * while queued (e.g. a `resolve` server's peer set changed)
         * would still see a false BUSY on that real opportunity and
         * just get silently re-queued, waiting for the next timer tick
         * to fix what a real free-event should have fixed immediately.
         */
        ngx_http_upstream_queue_refresh_peer(d);
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        ngx_connection_t *c = u->peer.connection;
        ngx_close_connection(c);
        c->shared = 0;
        ngx_http_upstream_handler_pt read_event_handler = u->read_event_handler;
        ngx_http_upstream_handler_pt write_event_handler = u->write_event_handler;
        qscf->reentered = 0;
        ngx_http_upstream_connect(r, u);
        u->read_event_handler = read_event_handler;
        u->write_event_handler = write_event_handler;
        /*
         * ngx_http_upstream_connect() only re-enters this function
         * (caught above via draining) when the just-dequeued request's
         * connect fails synchronously. Anything else - a real connect
         * left in progress, or one that succeeded outright - means the
         * peer slot this drain pass freed up is now spoken for again;
         * further queued requests must wait for their own turn instead
         * of being popped speculatively.
         */
        if (!qscf->reentered) break;
    }
    qscf->draining = 0;
}

static void ngx_http_upstream_queue_retry_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, "queue retry");
    ngx_http_upstream_queue_srv_conf_t *qscf = e->data;
    if (!ngx_queue_empty(&qscf->queue)) {
        /*
         * Unlike peer_free()'s drain, nothing here guarantees a slot
         * actually freed up - this fires on a plain timer. Popping the
         * head and reconnecting unconditionally (as peer_free() safely
         * does, because it is only called right after a slot really
         * did free up) would, on every tick where nothing changed,
         * requeue the head request at the tail with fresh timers -
         * breaking FIFO order and resetting its deadline for no reason.
         * So probe the underlying peer first, with a clean rollback,
         * and only actually touch the queue when it would truly
         * succeed.
         */
        ngx_http_upstream_queue_data_t *d = ngx_queue_data(ngx_queue_head(&qscf->queue), ngx_http_upstream_queue_data_t, queue);
        ngx_http_upstream_queue_refresh_peer(d);
        ngx_peer_connection_t probe;
        ngx_memzero(&probe, sizeof(ngx_peer_connection_t));
        probe.log = e->log;
        if (d->peer.get(&probe, d->peer.data) == NGX_OK) {
            d->peer.free(&probe, d->peer.data, 0);
            ngx_http_upstream_queue_drain(qscf);
        }
    }
    ngx_http_upstream_queue_retry_schedule(qscf);
}

static void ngx_http_upstream_queue_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_http_upstream_queue_data_t *d = data;
    d->peer.free(pc, d->peer.data, state);
    ngx_http_upstream_t *u = d->request->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    ngx_http_upstream_queue_drain(qscf);
}

static void ngx_http_upstream_queue_cleanup_handler(void *data) {
    ngx_http_upstream_queue_data_t *d = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    if (!ngx_queue_empty(&d->queue)) {
        ngx_http_upstream_t *u = d->request->upstream;
        ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
        ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
        ngx_queue_remove(&d->queue);
        qscf->size--;
        /*
         * A single request can register this cleanup handler more
         * than once - each connect attempt that lands back in
         * peer_get()'s "still busy, queue it" branch adds another
         * ngx_pool_cleanup_t for the same d, e.g. on a retry after the
         * request was already queued once. Without resetting d->queue
         * to the self-referential "empty" state here (as
         * ngx_http_upstream_queue_drain() already does after its own
         * ngx_queue_remove()), a second invocation of this handler for
         * the same d would see stale, dangling next/prev pointers,
         * misread ngx_queue_empty() as false, and attempt a second,
         * invalid removal through them.
         */
        ngx_queue_init(&d->queue);
    }
    if (d->connect_timeout.timer_set) ngx_del_timer(&d->connect_timeout);
    if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
}

static void ngx_http_upstream_queue_connect_timeout_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_connection_t *c = e->data;
    if (c->write->timer_set) ngx_del_timer(c->write);
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
    if (qscf->detect) {
        ngx_http_upstream_rr_peer_data_t *rrp = d->peer.data;
        time_t now = ngx_time();
        ngx_flag_t all_peers_down = 1;
        ngx_http_upstream_rr_peers_wlock(rrp->peers);
        for (ngx_http_upstream_rr_peer_t *peer = rrp->peers->peer; peer; peer = peer->next) {
            if (!peer->down) {
                if (peer->max_fails && peer->fails >= peer->max_fails && now - peer->checked <= peer->fail_timeout) continue;
                all_peers_down = 0;
                break;
            }
        }
        ngx_http_upstream_rr_peers_unlock(rrp->peers);
        if (all_peers_down) return rc;
    }
    if (qscf->size >= qscf->max) return rc;
    if (!(pc->connection = ngx_get_connection(0, pc->log))) { ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_get_connection"); return NGX_ERROR; }
    pc->connection->shared = 1;
    ngx_pool_cleanup_t *cln;
    if (!(cln = ngx_pool_cleanup_add(r->pool, 0))) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0, "!ngx_pool_cleanup_add");
        ngx_connection_t *c = pc->connection;
        ngx_close_connection(c);
        c->shared = 0;
        pc->connection = NULL;
        return NGX_ERROR;
    }
    cln->handler = ngx_http_upstream_queue_cleanup_handler;
    cln->data = d;
    if (u->conf->connect_timeout <= qscf->timeout) {
        d->connect_timeout.data = pc->connection;
        d->connect_timeout.handler = ngx_http_upstream_queue_connect_timeout_handler;
        d->connect_timeout.log = pc->log;
        ngx_add_timer(&d->connect_timeout, u->conf->connect_timeout / 2);
    }
    d->timeout.data = r;
    d->timeout.handler = ngx_http_upstream_queue_timeout_handler;
    d->timeout.log = pc->log;
    ngx_add_timer(&d->timeout, qscf->timeout);
    if (ngx_queue_empty(&d->queue)) {
        /*
         * Guard against linking an already-linked node: if something
         * outside this module's own drain (e.g. nginx core retrying
         * the same request's connect on its own) calls back in here
         * while d is still sitting in qscf->queue from an earlier
         * attempt, ngx_queue_insert_tail() on an already-linked node
         * would corrupt the list - the same corruption that produced
         * the ngx_queue_remove() crash fixed in the cleanup handler
         * above. d->queue is only ever non-empty here because it is
         * still genuinely queued, so it is already exactly where it
         * needs to be; nothing to do.
         */
        ngx_queue_insert_tail(&qscf->queue, &d->queue);
        qscf->size++;
    }
    ngx_http_upstream_queue_retry_schedule(qscf);
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

static void ngx_http_upstream_queue_refresh_peer(ngx_http_upstream_queue_data_t *d) {
    /*
     * d->peer.data is a round-robin ngx_http_upstream_rr_peer_data_t
     * captured once, when this request first started. Its ->config
     * field is a snapshot of the upstream's peer-set generation taken
     * at that moment; ngx_http_upstream_get_round_robin_peer() treats
     * any mismatch against the *current* generation as permanently
     * busy for that snapshot, no matter how many times it is retried
     * (see its "rrp->config != *peers->config" check) - and a
     * `resolve` server bumps that generation the moment DNS adds or
     * removes an address. So a request that queued before such a
     * change can never succeed on its original snapshot; re-running
     * the wrapped peer.init refreshes rrp->config (and rrp->tried) in
     * place before every retry, exactly as a brand new request would
     * get a current snapshot.
     */
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    u->peer.data = d->peer.data;
    if (qscf->peer.init(r, uscf) == NGX_OK) {
        d->peer = u->peer;
    }
    u->peer.data = d;
    u->peer.get = ngx_http_upstream_queue_peer_get;
    u->peer.free = ngx_http_upstream_queue_peer_free;
#if (NGX_HTTP_SSL)
    u->peer.save_session = ngx_http_upstream_queue_peer_save_session;
    u->peer.set_session = ngx_http_upstream_queue_peer_set_session;
#endif
}

static ngx_int_t ngx_http_upstream_queue_peer_init(ngx_http_request_t *r, ngx_http_upstream_srv_conf_t *uscf) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s", __func__);
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    ngx_http_upstream_queue_data_t *d;
    if (!(d = ngx_pcalloc(r->pool, sizeof(*d)))) return NGX_ERROR;
    ngx_queue_init(&d->queue);
    if (qscf->peer.init(r, uscf) != NGX_OK) return NGX_ERROR;
    ngx_http_upstream_t *u = r->upstream;
    u->conf->upstream = uscf;
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
    ngx_conf_init_value(qscf->detect, 0);
    ngx_conf_init_msec_value(qscf->timeout, 60000);
    ngx_conf_init_msec_value(qscf->retry_interval, 200);
    if (qscf->peer.init_upstream(cf, uscf) != NGX_OK) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "init_upstream != NGX_OK"); return NGX_ERROR; }
    qscf->peer.init = uscf->peer.init;
    uscf->peer.init = ngx_http_upstream_queue_peer_init;
    ngx_queue_init(&qscf->queue);
    return NGX_OK;
}

static void *ngx_http_upstream_queue_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_upstream_queue_srv_conf_t *conf;
    if (!(conf = ngx_pcalloc(cf->pool, sizeof(*conf)))) return NULL;
    conf->detect = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->retry_interval = NGX_CONF_UNSET_MSEC;
    return conf;
}

static char *ngx_http_upstream_queue_ups_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_upstream_queue_srv_conf_t *qscf = conf;
    if (qscf->max) return "is duplicate";
    ngx_str_t *value = cf->args->elts;
    ngx_int_t n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR || !n) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\" in \"%V\" directive", &value[1], &cmd->name); return NGX_CONF_ERROR; }
    qscf->max = n;
    for (ngx_uint_t i = 2; i < cf->args->nelts; i++) {
        if (value[i].len > sizeof("timeout=") - 1 && !ngx_strncmp(value[i].data, (u_char *)"timeout=", sizeof("timeout=") - 1)) {
            ngx_str_t s = value[i];
            s.data += sizeof("timeout=") - 1;
            s.len -= sizeof("timeout=") - 1;
            ngx_int_t timeout = ngx_parse_time(&s, 0);
            if (timeout == NGX_ERROR) return "ngx_parse_time == NGX_ERROR";
            qscf->timeout = (ngx_msec_t)timeout;
            continue;
        }
        if (value[i].len > sizeof("retry_interval=") - 1 && !ngx_strncmp(value[i].data, (u_char *)"retry_interval=", sizeof("retry_interval=") - 1)) {
            ngx_str_t s = value[i];
            s.data += sizeof("retry_interval=") - 1;
            s.len -= sizeof("retry_interval=") - 1;
            ngx_int_t interval = ngx_parse_time(&s, 0);
            if (interval == NGX_ERROR || !interval) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            qscf->retry_interval = (ngx_msec_t)interval;
            continue;
        }
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid name \"%V\" in \"%V\" directive", &value[i], &cmd->name);
        return NGX_CONF_ERROR;
    }
    ngx_http_upstream_srv_conf_t *uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);
    qscf->peer.init_upstream = uscf->peer.init_upstream ? uscf->peer.init_upstream : ngx_http_upstream_init_round_robin;
    uscf->peer.init_upstream = ngx_http_upstream_queue_peer_init_upstream;
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_upstream_queue_postconfiguration(ngx_conf_t *cf) {
    ngx_http_upstream_main_conf_t *umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);
    ngx_http_upstream_srv_conf_t **uscfp = umcf->upstreams.elts;
    for (ngx_uint_t i = 0; i < umcf->upstreams.nelts; i++) {
        if (!uscfp[i]->srv_conf) continue;
        ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscfp[i], ngx_http_upstream_queue_module);
        if (qscf->detect == 1 && !qscf->max) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"queue_detect_all_peer_down\" is specified without \"queue\" in upstream \"%V\"", &uscfp[i]->host);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_http_module_t ngx_http_upstream_queue_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = ngx_http_upstream_queue_postconfiguration,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = ngx_http_upstream_queue_create_srv_conf,
    .merge_srv_conf = NULL,
    .create_loc_conf = NULL,
    .merge_loc_conf = NULL
};

static ngx_command_t ngx_http_upstream_queue_commands[] = {
  { ngx_string("queue"), NGX_HTTP_UPS_CONF|NGX_CONF_TAKE123, ngx_http_upstream_queue_ups_conf, NGX_HTTP_SRV_CONF_OFFSET, 0, NULL },
  { ngx_string("queue_detect_all_peer_down"), NGX_HTTP_UPS_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_SRV_CONF_OFFSET, .offset = offsetof(ngx_http_upstream_queue_srv_conf_t, detect), NULL },
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
