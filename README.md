# Nginx queue upstream connection

# Directive

queue
-------------
* Syntax: **queue** *number* [ timeout=*time* ]
* Default: --
* Context: upstream

If an upstream server cannot be selected immediately while processing a request, the request will be placed into the queue. The directive specifies the maximum *number* of requests that can be in the queue at the same time. If the queue is filled up, or the server to pass the request to cannot be selected within the time period specified in the timeout parameter, the 502 (Bad Gateway) error will be returned to the client.

The default value of the timeout parameter is 60 seconds.

When using load balancer methods other than the default round-robin method, it is necessary to activate them before the queue directive.
