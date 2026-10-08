# Nginx upstream queue

# Build

The module includes nginx's own `src/http/ngx_http_upstream.c` to reach functions that nginx keeps static, so it can only be built as a dynamic module:

    ./configure --add-dynamic-module=/path/to/ngx_http_upstream_queue_module

and loaded with `load_module modules/ngx_http_upstream_queue_module.so;`. `--add-module` is rejected by configure: linked into nginx statically, the module would define that file's symbols a second time.

# Directive

queue
-------------
* Syntax: **queue** *number* [ timeout=*time* ] [ retry_interval=*time* ]
* Default: --
* Context: upstream

If an upstream server cannot be selected immediately while processing a request, the request will be placed into the queue. The directive specifies the maximum *number* of requests that can be in the queue at the same time. If the queue is filled up, the 502 (Bad Gateway) error will be returned to the client. If the server to pass the request to cannot be selected within the time period specified in the timeout parameter, the 504 (Gateway Time-out) error will be returned to the client, and an "upstream queue timed out" error is logged.

The queue, and so the *number* limit, is kept by each worker process separately: with `worker_processes 4;` and `queue 10;`, up to 40 requests can be queued in total. A queued request waits in the worker that accepted it. It is woken right away when a connection in that same worker frees a slot; a slot freed by another worker (with a shared `zone`, where `max_conns` and failures are counted across workers) is only noticed by the retry timer, every retry_interval.

The retry timer passes over a queued request that cannot use any free server because it already failed on it, and tries the next one, but stops at the first request that is simply out of luck, since everyone behind it would be too. With a load balancing method where the choice of server depends on the request itself so strictly that a request waits for its own server even while others are free (Angie's `sticky_strict`), such a request can hold up those behind it when the slot is freed in another worker process.

The default value of the timeout parameter is 60 seconds.

The retry_interval parameter controls how often a queued request is re-checked when nothing else has woken it in the meantime (see "Compatibility with `resolve`" below for what that covers). The default is 200 milliseconds. timeout= and retry_interval= may be given in either order.

When using load balancer methods other than the default round-robin method, it is necessary to activate them before the queue directive.

The keepalive directive, if any, must come after the queue directive on nginx before 1.29.7 and on forks such as freenginx and Angie, where keepalive takes effect at the point it is declared; `nginx -t` rejects the other order there. Since 1.29.7 nginx sets keepalive up after all other upstream directives, so either order works.

queue_detect_all_peer_down;
-------------
* Syntax: queue_detect_all_peer_down on | off;
* Default: off
* Context: upstream

Enables/disables detect all peer down

Only supported with load balancer methods built on top of the standard round-robin peer data (the default round-robin, `least_conn`, `least_time`, `ip_hash`, `hash`, and `random`); with any other method (e.g. the third-party `fair`) detection is skipped, as if it were off, and a warning is logged once per upstream in each worker.

# Compatibility with `resolve`

`server ... resolve` (with `zone`) is supported: a request that queues while the upstream currently has no usable resolved peer - e.g. before a `resolve` server's first successful DNS answer - is retried once the peer set changes, instead of waiting out the full queue timeout regardless of what the resolver does in the meantime. This is handled entirely within the module; no nginx core patch is required.

Retrying happens two ways: immediately whenever some other connection on the same upstream frees a slot, same as for static servers, and on a backstop timer (the queue directive's retry_interval=, default 200ms) for the case nothing else ever does (there is no way to be notified the instant DNS resolves without patching nginx core). Both paths always retry against a current snapshot of the peer set.

`queue_detect_all_peer_down` behaves the same with `resolve` as with static servers: it fails over immediately rather than queuing both before the first successful resolution (the peer list is empty) and once the only resolved peer is recently failed.

Tested against a `resolve` server with zero, one, and two simultaneously resolved addresses (the latter exercises weighted round-robin's general multi-peer selection, not just its single-peer shortcut). Also tested with backup servers, with either the primary or the backup being a `resolve` server, including a primary whose name only starts resolving while requests are queued. Also tested with names resolving to IPv6 (AAAA) addresses, alone or together with IPv4 ones. SSL session reuse for queued requests is tested as well, with and without a zone and with `resolve`.
