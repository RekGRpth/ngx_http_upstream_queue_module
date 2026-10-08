#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# A queued request used to leave the queue only from the cleanup handler
# of its pool.  A subrequest (SSI include, auth_request, mirror) shares
# the main request's pool, so once a queued subrequest was finalized - by
# its queue timeout, say - it stayed in the queue for as long as the main
# request lived.  The next drain() then popped a request whose upstream
# was already finalized (u->peer.connection == NULL) and crashed the
# worker.
#
# Layout:
#   - an SSI page includes /q/sub, proxied through a queue with
#     timeout=1s, and /slow, a backend that takes 3s - so the main
#     request outlives the subrequest by about 2s;
#   - the queue's only slot (max_conns=1) is taken by a holder that is
#     answered after 2s, i.e. while the main request is still running.
#
# Expected: /q/sub times out after 1s, the holder's answer drains the
# queue without tripping over it, and the page completes - no crash
# ("worker process ... exited on signal 11" is an [alert]).

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;

BEGIN {
	use FindBin;
	chdir($FindBin::Bin);
	$ENV{TEST_NGINX_BINARY} ||= '../../nginx/objs/nginx';
}

use lib '../../nginx-tests/lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $module = "$FindBin::Bin/../../nginx/objs/ngx_http_upstream_queue_module.so";

if (!-e $module) {
	Test::More::plan(skip_all => "$module not built");
}

my $t = Test::Nginx->new()->has(qw/http proxy ssi/)->plan(3);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my $queue_port = port(8081);
my $slow_port = port(8082);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream q {
        server 127.0.0.1:8081 max_conns=1;
        queue 5 timeout=1s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /q/ {
            proxy_pass http://q;
        }

        location /slow {
            proxy_pass http://127.0.0.1:8082;
        }

        location = /page.html {
            ssi on;
        }
    }
}

EOF

$t->write_file('page.html',
	'<!--# include virtual="/q/sub" -->|<!--# include virtual="/slow" -->');

$t->run_daemon(\&delayed_backend, $queue_port, 2);
$t->run_daemon(\&delayed_backend, $slow_port, 3);
$t->waitforsocket('127.0.0.1:' . $queue_port)
	or die "queue backend did not start\n";
$t->waitforsocket('127.0.0.1:' . $slow_port)
	or die "slow backend did not start\n";

$t->run();

###############################################################################

my $holder = send_request('/q/holder');
select(undef, undef, undef, 0.2);

my $page = read_response(send_request('/page.html'), 8);

# The page comes chunked, and the error log names whichever subrequest is
# active on the connection, not necessarily the one that timed out.

like($page, qr!^HTTP/1\.[01] 200 .*504 Gateway Time-out.*\|.*\bok\r\n0\r\n!s,
	'page with a timed out queued include completes');
like($t->read_file('error.log'),
	qr/upstream queue timed out.*request: "GET \/page\.html /,
	'the include itself timed out in the queue');
like(read_response($holder, 3), qr!^HTTP/1\.[01] 200 !,
	'holder served, draining the queue past the finalized include');

###############################################################################

sub send_request {
	my ($uri) = @_;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	$s->autoflush(1);
	$s->syswrite(<<EOF);
GET $uri HTTP/1.1\r
Host: localhost\r
Connection: close\r
\r
EOF

	return $s;
}

sub read_response {
	my ($s, $timeout) = @_;
	my $resp = '';
	my $deadline = time() + $timeout;

	while (time() < $deadline) {
		my $sel = IO::Select->new($s);
		last unless $sel->can_read($deadline - time());
		my $n = sysread($s, my $chunk, 65536);
		last if !$n;
		$resp .= $chunk;
	}

	return $resp;
}

# Answers each request with 200 after $delay seconds, one connection
# each, so a held request doesn't block the next one.

sub delayed_backend {
	my ($port, $delay) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		next if fork();

		# waitforsocket()'s probe sends nothing and just closes.

		exit 0 unless $client->sysread(my $buf, 65536);

		select(undef, undef, undef, $delay);
		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		exit 0;
	}
}

###############################################################################
