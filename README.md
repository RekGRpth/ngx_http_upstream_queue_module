# Nginx upstream queue

# Directive

queue
-------------
* Syntax: **queue** *number* [ timeout=*time* ] [ retry_interval=*time* ]
* Default: --
* Context: upstream

If an upstream server cannot be selected immediately while processing a request, the request will be placed into the queue. The directive specifies the maximum *number* of requests that can be in the queue at the same time. If the queue is filled up, or the server to pass the request to cannot be selected within the time period specified in the timeout parameter, the 502 (Bad Gateway) error will be returned to the client.

The default value of the timeout parameter is 60 seconds.

The retry_interval parameter controls how often a queued request is re-checked when nothing else has woken it in the meantime (see "Compatibility with `resolve`" below for what that covers). The default is 200 milliseconds. timeout= and retry_interval= may be given in either order.

When using load balancer methods other than the default round-robin method, it is necessary to activate them before the queue directive.

queue_detect_all_peer_down;
-------------
* Syntax: queue_detect_all_peer_down on | off;
* Default: off
* Context: upstream

Enables/disables detect all peer down

Only supported with load balancer methods built on top of the standard round-robin peer data (the default round-robin, `least_conn`, `ip_hash`, `hash`, and `random`); third-party balancer modules that do not embed `ngx_http_upstream_rr_peer_data_t` are not supported.

# Compatibility with `resolve`

`server ... resolve` (with `zone`) is supported: a request that queues while the upstream currently has no usable resolved peer - e.g. before a `resolve` server's first successful DNS answer - is retried once the peer set changes, instead of waiting out the full queue timeout regardless of what the resolver does in the meantime. This is handled entirely within the module; no nginx core patch is required.

Retrying happens two ways: immediately whenever some other connection on the same upstream frees a slot, same as for static servers, and on a backstop timer (the queue directive's retry_interval=, default 200ms) for the case nothing else ever does (there is no way to be notified the instant DNS resolves without patching nginx core). Both paths always retry against a current snapshot of the peer set.

`queue_detect_all_peer_down` behaves the same with `resolve` as with static servers: it fails over immediately rather than queuing both before the first successful resolution (the peer list is empty) and once the only resolved peer is recently failed.

Tested against a `resolve` server with zero, one, and two simultaneously resolved addresses (the latter exercises weighted round-robin's general multi-peer selection, not just its single-peer shortcut). Not tested: backup servers, IPv6/AAAA, or SSL session reuse combined with `resolve`.
