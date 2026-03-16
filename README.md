# Nginx upstream queue

# Directive

queue
-------------
* Syntax: **queue** *number* [ timeout=*time* ]
* Default: --
* Context: upstream

If an upstream server cannot be selected immediately while processing a request, the request will be placed into the queue. The directive specifies the maximum *number* of requests that can be in the queue at the same time. If the queue is filled up, or the server to pass the request to cannot be selected within the time period specified in the timeout parameter, the 502 (Bad Gateway) error will be returned to the client.

The default value of the timeout parameter is 60 seconds.

When using load balancer methods other than the default round-robin method, it is necessary to activate them before the queue directive.

queue_detect_all_peer_down;
-------------
* Syntax: queue_detect_all_peer_down on | off;
* Default: off
* Context: upstream

Enables/disables detect all peer down

## Optional immediate post-resolve hook

An optional NGINX core patch is provided at `patches/nginx-upstream-zone-post-resolve-hook.patch`.

- Without the patch, this module still works (event + retry fallback path).
- With the patch, this module additionally hooks upstream-zone resolve completion and wakes queue immediately after DNS peer updates.

The module is guarded with `#if (NGX_HTTP_UPSTREAM_QUEUE_RESOLVE_HOOK)` so it compiles on both patched and unpatched NGINX trees.

Apply patch from NGINX source root:

```bash
patch -p1 < /path/to/ngx_http_upstream_queue_module/patches/nginx-upstream-zone-post-resolve-hook.patch
```
