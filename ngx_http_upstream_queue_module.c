#include <ngx_http.h>
#include "ngx_http_upstream.c"

ngx_module_t ngx_http_upstream_queue_module;

typedef struct {
    ngx_flag_t detect;
    ngx_flag_t detect_warned;
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
#if defined ngx_http_upstream_conf_changed
    /*
     * Angie, told apart by ngx_http_upstream_conf_changed(), takes
     * u->peer.data for round-robin's peer data in an upstream with a zone
     * (ngx_http_upstream_need_connection_drop() follows rrp->current on
     * every request) - and u->peer.data is ours. So lead with one, its
     * current set after every peer.get to the wrapped balancer's.
     */
    ngx_http_upstream_rr_peer_data_t rrp;
#endif
    ngx_event_t connect_timeout;
    ngx_event_t timeout;
    ngx_event_t posted;
    ngx_http_request_t *request;
    ngx_http_upstream_t *upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf;
    ngx_peer_connection_t peer;
    ngx_queue_t queue;
    ngx_uint_t used;
    ngx_uint_t budget;
    ngx_array_t *failed;
    ngx_flag_t rr;
    ngx_flag_t deadline_set;
    ngx_msec_t deadline;
} ngx_http_upstream_queue_data_t;

static void ngx_http_upstream_queue_retry_handler(ngx_event_t *e);
static void ngx_http_upstream_queue_refresh_peer(ngx_http_upstream_queue_data_t *d);
static void ngx_http_upstream_queue_remember_failed(ngx_http_upstream_queue_data_t *d, ngx_peer_connection_t *pc);

static ngx_flag_t ngx_http_upstream_queue_finalized(ngx_http_upstream_queue_data_t *d) {
    /*
     * ngx_http_upstream_finalize_request() clears u->cleanup first thing.
     * A queued request can be finalized while d lives on: a subrequest
     * (SSI include, auth_request, mirror) shares the main request's pool,
     * so the pool cleanup that takes d out of the queue only runs once
     * the main request is done. Such a d must just be dropped from the
     * queue - its upstream, placeholder connection included, is gone.
     * And r->upstream may not be its upstream any more: a finalized
     * request can start over with another one - post_action, which runs
     * when the client goes away, or error_page into another proxy_pass -
     * and that one, not finalized, would make the d look live.
     */
    return d->request->upstream != d->upstream || d->upstream->cleanup == NULL;
}

static ngx_flag_t ngx_http_upstream_queue_is_rr(void *data, ngx_http_upstream_srv_conf_t *uscf) {
    /*
     * Whether a balancer's freshly initialized peer data is round-robin's,
     * which queue_detect_all_peer_down scans and mark_failed() marks:
     * round-robin itself and every balancer built on it (least_conn,
     * least_time, ip_hash, hash, random) start their peer data with
     * ngx_http_upstream_rr_peer_data_t, set up by
     * ngx_http_upstream_init_round_robin_peer(), which points ->peers at
     * the upstream's peer set, uscf->peer.data. Anything else - the
     * third-party fair (a peer index there), or a wrapper such as sticky
     * declared before "queue" (a request pointer) - has something else at
     * that spot. Only valid right after peer.init: round-robin's peer.get
     * moves ->peers on to the backup set once the primary one is spent.
     * This reads a balancer's private data, so a third-party one whose
     * peer data is smaller than that, or happens to keep the upstream's
     * peer set pointer at that very spot, would fool it.
     */
    return data && ((ngx_http_upstream_rr_peer_data_t *) data)->peers == uscf->peer.data;
}

static ngx_flag_t ngx_http_upstream_queue_failed_before(ngx_http_upstream_queue_data_t *d, ngx_peer_connection_t *pc) {
    ngx_addr_t *failed = d->failed->elts;
    for (ngx_uint_t i = 0; i < d->failed->nelts; i++) {
        if (ngx_cmp_sockaddr(failed[i].sockaddr, failed[i].socklen, pc->sockaddr, pc->socklen, 1) == NGX_OK) return 1;
    }
    return 0;
}

static ngx_int_t ngx_http_upstream_queue_get(ngx_http_upstream_queue_data_t *d, ngx_peer_connection_t *pc) {
    if (d->rr && d->failed) {
        /*
         * One peer and no backups: round-robin hands it out whether this
         * request already failed on it or not. If it did - e.g. a `resolve`
         * name shrank to just that peer while the request waited - there
         * is nothing it may use: stay busy, so it waits for the peer set
         * to change or for its queue timeout, as with any busy upstream.
         */
        ngx_http_upstream_rr_peers_t *peers = ((ngx_http_upstream_rr_peer_data_t *) d->peer.data)->peers;
        if (peers->single && (!peers->next || !peers->next->number)) {
            ngx_http_upstream_rr_peers_rlock(peers);
            ngx_flag_t failed = 0;
            if (peers->peer) {
                ngx_peer_connection_t one = { .sockaddr = peers->peer->sockaddr, .socklen = peers->peer->socklen };
                failed = ngx_http_upstream_queue_failed_before(d, &one);
            }
            ngx_http_upstream_rr_peers_unlock(peers);
            if (failed) {
                pc->name = peers->name;
                return NGX_BUSY;
            }
        }
    }
    ngx_int_t rc = d->peer.get(pc, d->peer.data);
    if (!d->rr || !d->failed) return rc;
    /*
     * mark_failed() keeps a refreshed request off the primary peers it
     * already failed on, but round-robin clears rrp->tried whenever it
     * moves on to the backup set - which every retry out of the queue
     * makes it do again - so a backup it failed on can come back here.
     * Hand such a peer straight back and ask again: round-robin has
     * marked it tried by now, so it won't return it twice. A single peer
     * it hands out tried or not, and its free resets the peer's fails
     * unconditionally, so that one is left alone here.
     */
    ngx_http_upstream_rr_peer_data_t *rrp = d->peer.data;
    for (ngx_uint_t n = 0; rc == NGX_OK && !rrp->peers->single && n < d->failed->nelts && ngx_http_upstream_queue_failed_before(d, pc); n++) {
#if !defined ngx_http_upstream_conf_changed
        /*
         * peer.get may just have picked this peer to re-check it after
         * fail_timeout (setting peer->checked), and a free without
         * NGX_PEER_FAILED then counts as a check that passed, resetting
         * its fails - although nothing was sent to it. Put checked back
         * to the time of the last failure first, as if it had not been
         * picked, so the next request re-checks it for real. (Angie,
         * told apart by its ngx_http_upstream_conf_changed(), only counts
         * a check as passed when there was a connection, which a peer
         * handed back here never has.)
         */
        ngx_http_upstream_rr_peer_t *peer = rrp->current;
        ngx_http_upstream_rr_peers_rlock(rrp->peers);
        ngx_http_upstream_rr_peer_lock(rrp->peers, peer);
        peer->checked = peer->accessed;
        ngx_http_upstream_rr_peer_unlock(rrp->peers, peer);
        ngx_http_upstream_rr_peers_unlock(rrp->peers);
#endif
        ngx_uint_t tries = pc->tries;
        d->peer.free(pc, d->peer.data, 0);
        pc->tries = tries;
        /*
         * Forget the peer just handed back: on NGX_BUSY round-robin sets
         * only pc->name, and a request queued with a stale pc->sockaddr
         * would have that peer freed once more when it is finalized.
         */
        pc->sockaddr = NULL;
        pc->socklen = 0;
        pc->name = NULL;
        rc = d->peer.get(pc, d->peer.data);
    }
    return rc;
}

static void ngx_http_upstream_queue_unlink(ngx_http_upstream_queue_data_t *d) {
    if (!ngx_queue_empty(&d->queue)) {
        ngx_queue_remove(&d->queue);
        /*
         * Back to the self-referential "empty" state, so a second unlink
         * of the same d (e.g. the pool cleanup after the timeout handler,
         * or a cleanup handler registered once per queueing) is a no-op
         * instead of a removal through dangling next/prev pointers.
         */
        ngx_queue_init(&d->queue);
        d->qscf->size--;
    }
    if (d->connect_timeout.timer_set) ngx_del_timer(&d->connect_timeout);
    if (d->timeout.timer_set) ngx_del_timer(&d->timeout);
}

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

static void ngx_http_upstream_queue_posted_handler(ngx_event_t *e) {
    ngx_http_run_posted_requests(e->data);
}

static void ngx_http_upstream_queue_post(ngx_http_upstream_queue_data_t *d) {
    /*
     * Have this request's posted requests run at the end of this event
     * loop pass: finalizing it can post its termination (when its client
     * is already gone, c->error), and whatever event got us here belongs
     * to some other request, which runs posted requests only for its own
     * connection once it is done. Not right away: drain() may be inside
     * another request's peer.free(), halfway through finalizing that one,
     * and nginx never runs posted requests at such a point. The pool
     * cleanup withdraws the event should the request be freed first.
     */
    d->posted.handler = ngx_http_upstream_queue_posted_handler;
    d->posted.data = d->request->connection;
    d->posted.log = d->request->connection->log;
    if (!d->posted.posted) { ngx_post_event(&d->posted, &ngx_posted_events); }
}

static void ngx_http_upstream_queue_drain(ngx_http_upstream_queue_srv_conf_t *qscf) {
    if (qscf->draining) { qscf->reentered = 1; return; }
    qscf->draining = 1;
    while (!ngx_queue_empty(&qscf->queue)) {
        ngx_http_upstream_queue_data_t *d = ngx_queue_data(ngx_queue_head(&qscf->queue), ngx_http_upstream_queue_data_t, queue);
        ngx_http_upstream_queue_unlink(d);
        /* already finalized while queued: nothing to connect, slot still free */
        if (ngx_http_upstream_queue_finalized(d)) continue;
        /*
         * Refresh this request's balancer data before retrying it, not
         * just when the retry timer's own probe does it: this drain loop
         * also runs directly from peer_free() whenever some other
         * connection on the upstream genuinely frees a slot, and without
         * refreshing here, the request would still be looking at the
         * state its last NGX_BUSY left behind (see refresh_peer()) and
         * just get silently re-queued, waiting for the next timer tick
         * to fix what a real free-event should have fixed immediately.
         */
        ngx_http_upstream_queue_refresh_peer(d);
        ngx_http_request_t *r = d->request;
        ngx_http_upstream_t *u = r->upstream;
        ngx_connection_t *c = u->peer.connection;
        /*
         * ngx_http_upstream_connect() gave this placeholder its own
         * c->pool when peer_get() returned NGX_AGAIN; closing the
         * connection doesn't free it, and ngx_get_connection() zeroes
         * the slot on reuse, so destroy it here.
         */
        if (c->pool) ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
        c->shared = 0;
        /*
         * Not left pointing at the closed placeholder for the balancer's
         * peer.get to see: Angie's round-robin, for one, counts a free with
         * a connection as a check that passed.
         */
        u->peer.connection = NULL;
        qscf->reentered = 0;
        /* the connect below can finalize this request */
        ngx_http_upstream_queue_post(d);
        /*
         * Don't touch r/u after this call: if the connect fails
         * synchronously with no tries left, it finalizes the request
         * and may free r->pool (and u with it) before returning.
         */
        ngx_http_upstream_connect(r, u);
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
    /*
     * Unlike peer_free()'s drain, nothing here guarantees a slot actually
     * freed up - this fires on a plain timer. Popping the head and
     * reconnecting unconditionally (as peer_free() safely does, because
     * it is only called right after a slot really did free up) would, on
     * every tick where nothing changed, requeue the head request at the
     * tail - breaking FIFO order for no reason. So probe the underlying
     * peer first, with a clean rollback, and only actually touch the
     * queue when it would truly succeed.
     *
     * The head may be unable to use the very peer that is free, because
     * it already failed on it, while a request behind it could. So as
     * long as the request probed has peers of its own to avoid, go on to
     * the next one, and move the first that can connect to the head. A
     * request with none sees what everyone behind it would: stop there.
     */
    ngx_uint_t n = qscf->size;
    ngx_queue_t *q = ngx_queue_head(&qscf->queue);
    while (q != ngx_queue_sentinel(&qscf->queue) && n--) {
        ngx_http_upstream_queue_data_t *d = ngx_queue_data(q, ngx_http_upstream_queue_data_t, queue);
        q = ngx_queue_next(q);
        if (ngx_http_upstream_queue_finalized(d)) {
            ngx_http_upstream_queue_unlink(d);
            continue;
        }
        ngx_http_upstream_queue_refresh_peer(d);
        /*
         * The request's own peer connection, so the balancer sees what it
         * would on a real connect - Angie's ip_hash, hash and least_time
         * take the request from pc->ctx, and its round-robin does on free
         * - minus anything of an earlier attempt.
         */
        ngx_peer_connection_t probe = d->upstream->peer;
        probe.connection = NULL;
        probe.sockaddr = NULL;
        probe.socklen = 0;
        probe.name = NULL;
        probe.cached = 0;
        probe.log = e->log;
        if (ngx_http_upstream_queue_get(d, &probe) == NGX_OK) {
            d->peer.free(&probe, d->peer.data, 0);
            /*
             * The probe's peer.get() marked the peer it picked in this
             * request's rrp->tried, and peer.free() doesn't clear it - left
             * alone, it would keep this very request off the peer the probe
             * just found free. drain() pops this request first and starts
             * its balancer data over before connecting, which takes care of
             * that.
             */
            if (&d->queue != ngx_queue_head(&qscf->queue)) {
                ngx_queue_remove(&d->queue);
                ngx_queue_insert_head(&qscf->queue, &d->queue);
            }
            ngx_http_upstream_queue_drain(qscf);
            break;
        }
        if (!d->failed || !d->failed->nelts) break;
    }
    ngx_http_upstream_queue_retry_schedule(qscf);
}

static void ngx_http_upstream_queue_peer_free(ngx_peer_connection_t *pc, void *data, ngx_uint_t state) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_http_upstream_queue_data_t *d = data;
    d->used++;
    /*
     * Remember the peers this request has moved on from, as
     * ngx_http_upstream_next() does after a failure (or a 403/404 with
     * proxy_next_upstream), so refresh_peer() can mark them as tried
     * again - re-running peer.init forgets them.
     */
    if (pc->sockaddr && (state & (NGX_PEER_FAILED|NGX_PEER_NEXT))) ngx_http_upstream_queue_remember_failed(d, pc);
    d->peer.free(pc, d->peer.data, state);
    ngx_http_upstream_t *u = d->request->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    ngx_http_upstream_queue_drain(qscf);
}

static void ngx_http_upstream_queue_cleanup_handler(void *data) {
    ngx_http_upstream_queue_data_t *d = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, d->request->connection->log, 0, "%s", __func__);
    /*
     * A single request can register this cleanup handler more than once -
     * each connect attempt that lands back in peer_get()'s "still busy,
     * queue it" branch adds another ngx_pool_cleanup_t for the same d -
     * which unlink() is safe against.
     */
    ngx_http_upstream_queue_unlink(d);
    if (d->posted.posted) { ngx_delete_posted_event(&d->posted); }
}

static void ngx_http_upstream_queue_connect_timeout_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_http_upstream_queue_data_t *d = e->data;
    /* finalized: the placeholder is closed, and its slot may be someone else's by now */
    if (ngx_http_upstream_queue_finalized(d)) { ngx_http_upstream_queue_unlink(d); return; }
    ngx_connection_t *c = d->request->upstream->peer.connection;
    if (c && c->write->timer_set) ngx_del_timer(c->write);
}

static void ngx_http_upstream_queue_timeout_handler(ngx_event_t *e) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, e->log, 0, e->write ? "write" : "read");
    ngx_http_upstream_queue_data_t *d = e->data;
    ngx_http_upstream_queue_unlink(d);
    if (ngx_http_upstream_queue_finalized(d)) return;
    ngx_http_request_t *r = d->request;
    ngx_connection_t *c = r->connection;
    ngx_log_error(NGX_LOG_ERR, e->log, 0, "upstream queue timed out");
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_finalize_request(r, u, NGX_HTTP_GATEWAY_TIME_OUT);
    /*
     * Like any event handler that drives a request: when the client is
     * already gone (c->error - nginx keeps a cacheable request running
     * then), finalizing only posts the termination, and it is up to us
     * to run it. Left posted, the request would never close, never leave
     * the queue, and later be retried half torn down.
     */
    ngx_http_run_posted_requests(c);
}

static ngx_int_t ngx_http_upstream_queue_peer_get(ngx_peer_connection_t *pc, void *data) {
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "%s", __func__);
    ngx_http_upstream_queue_data_t *d = data;
    ngx_int_t rc = ngx_http_upstream_queue_get(d, pc);
#if defined ngx_http_upstream_conf_changed
    if (rc == NGX_OK) d->rrp.current = d->rr ? ((ngx_http_upstream_rr_peer_data_t *) d->peer.data)->current : NULL;
#endif
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer.get = %i", rc);
    if (rc != NGX_BUSY) { d->deadline_set = 0; return rc; }
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    /*
     * Detection scans the peer data as round-robin's, which only holds
     * for balancers built on it (see is_rr()). With any other, the scan
     * would read some other structure: skip it there, as if detection
     * were off.
     */
    if (qscf->detect && !d->rr) {
        if (!qscf->detect_warned) {
            ngx_log_error(NGX_LOG_WARN, pc->log, 0, "queue_detect_all_peer_down is ignored: the load balancing method is not based on round-robin");
            qscf->detect_warned = 1;
        }
    } else if (qscf->detect) {
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
        d->connect_timeout.data = d;
        d->connect_timeout.handler = ngx_http_upstream_queue_connect_timeout_handler;
        d->connect_timeout.log = pc->log;
        ngx_add_timer(&d->connect_timeout, u->conf->connect_timeout / 2);
    }
    d->timeout.data = d;
    d->timeout.handler = ngx_http_upstream_queue_timeout_handler;
    d->timeout.log = pc->log;
    /*
     * A request that drain() pops and reconnects can find no peer again
     * and land back here, e.g. when the slot that freed up is on a peer
     * it has already tried. Keep the deadline it got when it started
     * waiting rather than a fresh timeout each round, or frees on such
     * peers could keep it queued well past the timeout. Only a peer
     * actually selected (above) starts a new wait.
     */
    if (!d->deadline_set) {
        d->deadline = ngx_current_msec + qscf->timeout;
        d->deadline_set = 1;
    }
    ngx_msec_int_t left = (ngx_msec_int_t) (d->deadline - ngx_current_msec);
    ngx_add_timer(&d->timeout, left > 0 ? (ngx_msec_t) left : 0);
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

static void ngx_http_upstream_queue_peer_notify(ngx_peer_connection_t *pc, void *data, ngx_uint_t type) {
    ngx_http_upstream_queue_data_t *d = data;
    d->peer.notify(pc, d->peer.data, type);
}

static void ngx_http_upstream_queue_set_hooks(ngx_http_upstream_t *u, ngx_http_upstream_queue_data_t *d) {
    u->peer.data = d;
    u->peer.get = ngx_http_upstream_queue_peer_get;
    u->peer.free = ngx_http_upstream_queue_peer_free;
#if (NGX_HTTP_SSL)
    u->peer.set_session = ngx_http_upstream_queue_peer_set_session;
    u->peer.save_session = ngx_http_upstream_queue_peer_save_session;
#endif
    /*
     * nginx calls notify with u->peer.data, i.e. ours: pass it on with
     * the wrapped balancer's own data (sticky's "learn ... header" sets
     * one), or leave it unset like the balancer did.
     */
    u->peer.notify = d->peer.notify ? ngx_http_upstream_queue_peer_notify : NULL;
}

static void ngx_http_upstream_queue_remember_failed(ngx_http_upstream_queue_data_t *d, ngx_peer_connection_t *pc) {
    ngx_pool_t *pool = d->request->pool;
    if (!d->failed && !(d->failed = ngx_array_create(pool, 2, sizeof(ngx_addr_t)))) return;
    ngx_addr_t *failed = d->failed->elts;
    for (ngx_uint_t i = 0; i < d->failed->nelts; i++) {
        if (ngx_cmp_sockaddr(failed[i].sockaddr, failed[i].socklen, pc->sockaddr, pc->socklen, 1) == NGX_OK) return;
    }
    struct sockaddr *sockaddr;
    if (!(sockaddr = ngx_palloc(pool, pc->socklen))) return;
    ngx_memcpy(sockaddr, pc->sockaddr, pc->socklen);
    ngx_addr_t *addr;
    if (!(addr = ngx_array_push(d->failed))) return;
    addr->sockaddr = sockaddr;
    addr->socklen = pc->socklen;
    ngx_str_null(&addr->name);
}

static ngx_flag_t ngx_http_upstream_queue_rr_stale(ngx_http_upstream_rr_peers_t *peers, ngx_http_upstream_rr_peer_data_t *rrp) {
#if defined ngx_http_upstream_conf_changed
    return ngx_http_upstream_conf_changed(peers, rrp); /* Angie */
#elif (NGX_HTTP_UPSTREAM_ZONE && defined ngx_http_upstream_rr_peer_ref)
    return peers->config && rrp->config != *peers->config; /* nginx 1.27.3+ */
#else
    return 0; /* no runtime `resolve`: the peer set never changes */
#endif
}

static void ngx_http_upstream_queue_mark_failed(ngx_http_upstream_queue_data_t *d) {
    /*
     * Only called for balancers built on round-robin (see is_rr()),
     * whose peer data starts with ngx_http_upstream_rr_peer_data_t and
     * whose peer.get skips peers set in rrp->tried. Peers are matched by
     * address, not index, so this holds across `resolve` updates; if
     * the peer set changed since peer.init sized rrp->tried, leave it -
     * peer.get won't use this stale snapshot anyway. Only the primary
     * set can be marked here: round-robin clears rrp->tried when it
     * moves on to the backup set, so ngx_http_upstream_queue_get() turns
     * away backups failed on before as they come up.
     */
    ngx_http_upstream_rr_peer_data_t *rrp = d->peer.data;
    ngx_http_upstream_rr_peers_t *peers = rrp->peers;
    ngx_addr_t *failed = d->failed->elts;
    ngx_http_upstream_rr_peers_rlock(peers);
    if (!ngx_http_upstream_queue_rr_stale(peers, rrp)) {
        ngx_uint_t i = 0;
        for (ngx_http_upstream_rr_peer_t *peer = peers->peer; peer; peer = peer->next, i++) {
            for (ngx_uint_t j = 0; j < d->failed->nelts; j++) {
                if (ngx_cmp_sockaddr(peer->sockaddr, peer->socklen, failed[j].sockaddr, failed[j].socklen, 1) != NGX_OK) continue;
                rrp->tried[i / (8 * sizeof(uintptr_t))] |= (uintptr_t) 1 << (i % (8 * sizeof(uintptr_t)));
                break;
            }
        }
    }
    ngx_http_upstream_rr_peers_unlock(peers);
}

static ngx_uint_t ngx_http_upstream_queue_budget(ngx_http_upstream_t *u) {
    /* u->peer.tries right after peer.init, capped as ngx_http_upstream_init_request() does */
    ngx_uint_t budget = u->peer.tries;
    if (u->conf->next_upstream_tries && budget > u->conf->next_upstream_tries) budget = u->conf->next_upstream_tries;
    return budget;
}

static void ngx_http_upstream_queue_refresh_peer(ngx_http_upstream_queue_data_t *d) {
    /*
     * A queued request only got here because its balancer's peer.get()
     * returned NGX_BUSY, and nginx expects that to end the request, so
     * nothing keeps the balancer's per-request data usable for another
     * try. Round-robin, for one, leaves it pointing at the backup set
     * (rrp->peers switched, rrp->tried cleared) once the primary set
     * had nothing free - a request retried on that state would never
     * see a primary peer that frees up later. So re-run the wrapped
     * peer.init before every retry, for every balancer, and start over
     * exactly as a brand new request would.
     *
     * That also covers `resolve`: d->peer.data is a round-robin
     * ngx_http_upstream_rr_peer_data_t captured when this request
     * first started. Its ->config field is a snapshot of the upstream's
     * peer-set generation taken at that moment;
     * ngx_http_upstream_get_round_robin_peer() treats
     * any mismatch against the *current* generation as permanently
     * busy for that snapshot, no matter how many times it is retried
     * (see its "rrp->config != *peers->config" check) - and a
     * `resolve` server bumps that generation the moment DNS adds or
     * removes an address. So a request that queued before such a
     * change can never succeed on its original snapshot without it.
     *
     * The retry budget and, for balancers built on round-robin, the
     * peers already failed on are carried over below. The price left:
     * ip_hash, hash, random and least_time allocate new peer data from
     * r->pool on every refresh.
     */
    ngx_http_request_t *r = d->request;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_srv_conf_t *uscf = u->conf->upstream;
    ngx_http_upstream_queue_srv_conf_t *qscf = ngx_http_conf_upstream_srv_conf(uscf, ngx_http_upstream_queue_module);
    /*
     * u->peer is ours only if nothing wraps the queue. A wrapper set up
     * around it per request - keepalive, which nginx 1.29.7+ always puts
     * outside, or one declared after "queue" - keeps its own data and
     * hooks there, with ours tucked inside it, and must keep them.
     */
    ngx_peer_connection_t outer = u->peer;
    /*
     * Hand peer.init the same u->peer a brand new request has: no hooks,
     * and no data - except round-robin's own (see is_rr()), which
     * round-robin and least_conn reuse in place instead of allocating
     * anew, and ip_hash, hash, random and least_time ignore. Anything
     * else would be misread: a wrapper such as sticky passes u->peer.data
     * straight to round-robin, and records the hooks it finds as the
     * "original" ones - ours from the last round, looping notify back
     * into itself.
     */
    u->peer.data = d->rr ? d->peer.data : NULL;
    u->peer.get = NULL;
    u->peer.free = NULL;
    u->peer.notify = NULL;
#if (NGX_HTTP_SSL)
    u->peer.set_session = NULL;
    u->peer.save_session = NULL;
#endif
    if (qscf->peer.init(r, uscf) == NGX_OK) {
        /*
         * peer.init also resets u->peer.tries to the full peer count, as
         * for a brand new request. The request keeps the retry budget it
         * started with (see peer_init()), minus the attempts it has made,
         * so it can't get a fresh one on every refresh. The budget only
         * grows - with a peer set that grew, e.g. a `resolve` name that
         * had no addresses yet - and never shrinks: a name that briefly
         * resolves to nothing, or to peers the request never tried, must
         * not cost it the attempts it has left.
         */
        ngx_uint_t budget = ngx_http_upstream_queue_budget(u);
        if (budget > d->budget) d->budget = budget;
        u->peer.tries = d->budget > d->used ? d->budget - d->used : 0;
        d->peer = u->peer;
        d->rr = ngx_http_upstream_queue_is_rr(d->peer.data, uscf);
        if (d->failed && d->rr) ngx_http_upstream_queue_mark_failed(d);
    }
    if (outer.data == d) {
        ngx_http_upstream_queue_set_hooks(u, d);
        return;
    }
    u->peer.data = outer.data;
    u->peer.get = outer.get;
    u->peer.free = outer.free;
    u->peer.notify = outer.notify;
#if (NGX_HTTP_SSL)
    u->peer.set_session = outer.set_session;
    u->peer.save_session = outer.save_session;
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
    d->rr = ngx_http_upstream_queue_is_rr(d->peer.data, uscf);
    d->budget = ngx_http_upstream_queue_budget(u);
    d->request = r;
    d->upstream = u;
    d->qscf = qscf;
    ngx_http_upstream_queue_set_hooks(u, d);
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
            if (qscf->timeout != NGX_CONF_UNSET_MSEC) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate parameter \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            ngx_str_t s = value[i];
            s.data += sizeof("timeout=") - 1;
            s.len -= sizeof("timeout=") - 1;
            ngx_int_t timeout = ngx_parse_time(&s, 0);
            if (timeout == NGX_ERROR || !timeout) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid value \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
            qscf->timeout = (ngx_msec_t)timeout;
            continue;
        }
        if (value[i].len > sizeof("retry_interval=") - 1 && !ngx_strncmp(value[i].data, (u_char *)"retry_interval=", sizeof("retry_interval=") - 1)) {
            if (qscf->retry_interval != NGX_CONF_UNSET_MSEC) { ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "duplicate parameter \"%V\" in \"%V\" directive", &value[i], &cmd->name); return NGX_CONF_ERROR; }
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
    /*
     * Where keepalive wraps the balancer as soon as its directive is
     * parsed (nginx before 1.29.7, freenginx, Angie - its module has no
     * init_main_conf there), "keepalive" before "queue" would leave
     * queue wrapping keepalive instead of the balancer: queue would
     * treat keepalive's peer data as round-robin's, and the retry
     * probe would strand a cached connection on NGX_DONE. Newer nginx
     * sets keepalive up after all directives, outside of queue, so
     * either order works there. Looked up by name: referencing the
     * symbol would stop the module loading into an nginx built
     * without keepalive.
     */
    for (ngx_uint_t i = 0; cf->cycle->modules[i]; i++) {
        ngx_module_t *m = cf->cycle->modules[i];
        if (m->type != NGX_HTTP_MODULE || ngx_strcmp(m->name, "ngx_http_upstream_keepalive_module")) continue;
        ngx_http_module_t *ctx = m->ctx;
        ngx_uint_t *max_cached = uscf->srv_conf[m->ctx_index];
        if (!ctx->init_main_conf && *max_cached) return "must be specified before \"keepalive\"";
        break;
    }
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
