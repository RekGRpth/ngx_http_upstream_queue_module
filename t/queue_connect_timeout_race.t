#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# Once a request is queued, ngx_http_upstream_queue_peer_get() returns
# NGX_AGAIN.  nginx core treats that exactly like a real non-blocking
# connect() in progress and arms its own timer, for proxy_connect_timeout,
# on the placeholder connection's write event (ngx_http_upstream.c,
# "if (rc == NGX_AGAIN) { ngx_add_timer(c->write, u->conf->connect_timeout);
# }").  That timer is meaningless while the request is only queued - there
# is no real connect happening yet - so the module cancels it itself via
# ngx_http_upstream_queue_connect_timeout_handler(), scheduled at half of
# proxy_connect_timeout.
#
# That cancellation used to only be scheduled when
#   proxy_connect_timeout < queue's own timeout
# on the theory that otherwise the queue timeout fires first anyway and
# tears the placeholder connection down (which deletes any pending timer
# on it as an ordinary part of closing a connection) before nginx core's
# connect_timeout could ever fire.  That reasoning breaks down exactly at
# equality - the default for both is 60s - because both timers then get
# the *same* deadline (both are computed from the same ngx_current_msec
# snapshot within one synchronous call chain), and which of two timers
# with an identical key fires first is not something the module can rely
# on.  The fix widened the guard from < to <=, so the cancellation is
# always scheduled whenever there is any chance of a tie.
#
# This is not the kind of bug that can be forced into an observable crash
# from the outside (unlike the drain recursion in queue_cascade.t) - the
# fallback path already produces a correct-looking response most of the
# time regardless, because closing the placeholder connection deletes its
# timer as an ordinary side effect whenever the queue timeout's own
# handler happens to run first.  What *can* be checked directly is the
# module's own contract: whether it schedules its cancellation handler at
# all.  So this test sets proxy_connect_timeout equal to the queue
# timeout and asserts, via the debug log, that
# ngx_http_upstream_queue_connect_timeout_handler actually ran - before
# the fix it was never even armed in this case.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw/ SOCK_STREAM /;

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

my $sockpath = $t->testdir() . '/backend.sock';

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream backend {
        server unix:$sockpath max_conns=1 max_fails=0;
        queue 10 timeout=2s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;

            # Equal to the queue timeout above - the exact boundary the
            # fix is about.
            proxy_connect_timeout 2s;
        }
    }
}

EOF

$t->run_daemon(\&backend_daemon, $sockpath);
$t->waitforfile($sockpath) or die "backend daemon did not start\n";

$t->run();

###############################################################################

# Request #1: takes the only slot; the backend holds it open (unanswered)
# for the whole test, so request #2 below stays queued throughout.

my $holder = send_request();
select(undef, undef, undef, 0.3);

my $s = send_request();
my $resp = '';
my $deadline = time() + 10;
while (time() < $deadline) {
	my $n = sysread($s, my $chunk, 65536);
	last if !$n;
	$resp .= $chunk;
}

like($resp, qr!^HTTP/1\.[01] 504 !,
	'queued request times out cleanly at the connect_timeout == queue '
	. 'timeout boundary');

my $log = $t->read_file('error.log');

ok($log =~ /ngx_http_upstream_queue_connect_timeout_handler/,
	'the spurious core connect timer on the placeholder connection was '
	. 'armed for cancellation even though proxy_connect_timeout equals '
	. 'the queue timeout');

###############################################################################

sub send_request {
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	$s->autoflush(1);
	$s->syswrite(<<EOF);
GET / HTTP/1.1\r
Host: localhost\r
Connection: close\r
\r
EOF

	return $s;
}

sub backend_daemon {
	my ($path) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept unix connection: $!\n";

	# Hold the only occupied slot for the whole test; never answer.
	select(undef, undef, undef, 15);

	exit 0;
}

###############################################################################
