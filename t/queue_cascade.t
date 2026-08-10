#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_peer_free() drains the queue: whenever an
# upstream slot is released, it pops the next queued request and calls
# ngx_http_upstream_connect() for it.  If that connect attempt fails
# *synchronously* (no async round trip through the event loop), nginx core
# calls peer.free() again from inside the very same call, i.e. from inside
# ngx_http_upstream_queue_peer_free() itself.  Before the "draining" guard
# was added, this was plain recursion: one C stack frame per queued
# request, so a large enough queue could overflow the worker's stack when
# the upstream became unreachable.
#
# A real synchronous failure is not reachable over TCP: a non-blocking
# connect() to a closed TCP port on Linux returns EINPROGRESS and only
# fails later, asynchronously, once epoll reports it - by then it is a
# fresh call chain, not a recursive one.  AF_UNIX is different: connect()
# to a socket path that does not exist fails immediately, synchronously,
# with ENOENT, straight out of the connect() syscall.  That is what this
# test uses to force the cascade.
#
# Test layout:
#   - upstream has a single unix: peer with max_conns=1, max_fails=0
#     (max_fails=0 keeps the peer selectable on every attempt - we want
#     every dequeued request to actually reach connect() and fail there,
#     not be turned away earlier as "recently failed");
#   - one "holder" request occupies the only slot by connecting to a
#     backend daemon that accepts it and does not answer yet;
#   - a batch of further requests arrive while the slot is taken and pile
#     up in the queue;
#   - the backend daemon deletes its own listening socket right after
#     accepting the holder connection, then, after a delay, closes that
#     connection without ever answering it;
#   - that closure frees the slot and starts draining the queue: every
#     dequeued request's connect() now targets a unix path that no longer
#     exists, i.e. it fails synchronously, cascading through the whole
#     queue in one shot.
#
# What is asserted:
#   - every queued client eventually gets a complete response (nothing
#     hangs - the old recursive code did not hang either, but a stuck
#     drain is exactly the kind of failure mode this scenario could in
#     principle produce, so it is checked explicitly);
#   - every one of those responses is a well-formed 502/504, not a reset
#     or a partial read (which is what a mid-cascade worker crash looks
#     like from the client side);
#   - Test::Nginx itself fails the test if error.log gained an [alert]
#     line while stopping nginx - and "worker process ... exited on
#     signal 11 (core dumped)" from a stack overflow is logged at [alert]
#     level by the nginx master, so a crash is caught even if every
#     client above still happened to observe a clean-looking close.

###############################################################################

BEGIN {
	# Force a small worker stack.  A queue deep enough to matter here
	# (thousands of requests) still comfortably fits a typical multi-MB
	# default stack even with the old recursive drain, so without this
	# the test would pass against *both* the buggy and the fixed code -
	# not much of a regression test.  Capping the stack turns "maybe
	# overflows eventually" into a fast, deterministic crash, which is
	# what was verified empirically while writing this test: 512 KiB
	# reliably crashes the pre-fix code at $queued=2000 below, and the
	# fixed, iterative drain (O(1) stack regardless of queue depth)
	# keeps passing under the same limit however large $queued gets.
	if ($^O eq 'linux' && !$ENV{QUEUE_CASCADE_REEXEC}) {
		require Cwd;
		$ENV{QUEUE_CASCADE_REEXEC} = 1;
		exec { '/bin/sh' } '/bin/sh', '-c',
			'ulimit -s 512 || exit 1; exec "$@"',
			'sh', $^X, Cwd::abs_path(__FILE__), @ARGV
			or die "Can't re-exec under a reduced ulimit: $!\n";
	}
}

use warnings;
use strict;

use Test::More;
use IO::Select;
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

# Number of requests piled up behind the single occupied upstream slot.
# All of them must fail over in the single cascading peer_free() call
# triggered when the holder's connection is released.  Chosen well above
# the depth found (empirically, on this build) to overflow the worker's
# stack with the old recursive implementation - see t/README below.
my $queued = $ENV{TEST_QUEUE_N} || 2000;

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
    worker_connections @{[ ($queued + 100) * 4 ]};
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream backend {
        server unix:$sockpath max_conns=1 max_fails=0;
        queue @{[ $queued + 100 ]} timeout=10s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_connect_timeout 2s;
            proxy_read_timeout 5s;
        }
    }
}

EOF

$t->run_daemon(\&backend_daemon, $sockpath);
$t->waitforfile($sockpath) or die "backend daemon did not start\n";

$t->run();

###############################################################################

my @socks;

# Request #1: takes the only slot, held open (unanswered) by the backend
# for a while so the rest have time to pile up in the queue.

push @socks, send_request();

# Give request #1 time to actually reach the backend and be accept()ed -
# only then does the round-robin peer's conns counter reflect the slot
# being taken, which is what makes the rest of the requests queue up
# instead of racing for the same slot.

select(undef, undef, undef, 0.3);

push @socks, send_request() for (1 .. $queued);

# Read every response to completion (or give up after a generous
# deadline).  A stuck drain would show up here as sockets that never
# reach EOF.

my $sel = IO::Select->new(@socks);
my %buf;
my $deadline = time() + 30;

while ($sel->count() && time() < $deadline) {
	for my $s ($sel->can_read(0.2)) {
		my $n = sysread($s, my $chunk, 65536);
		if (!$n) {
			# EOF, or a hard error (e.g. reset by a crashing worker):
			# either way this socket is done.
			$sel->remove($s);
			next;
		}
		$buf{$s} .= $chunk;
	}
}

is($sel->count(), 0,
	'no hangs: all ' . scalar(@socks) . ' clients got a final response');

my $bad = grep { ($buf{$_} // '') !~ m!^HTTP/1\.[01] 50[24] ! } @socks;

is($bad, 0, 'all responses are well-formed 502/504, not a reset connection');

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

	# From this point on, connect() to $path must fail synchronously
	# with ENOENT - see the comment at the top of this file for why
	# that specifically (as opposed to a closed TCP port) is required.
	$server->close();
	unlink $path;

	# Hold the only occupied slot long enough for the rest of the
	# requests to queue up.
	select(undef, undef, undef, 1.5);

	# Abrupt close, no response: releases the slot and starts the
	# cascade.
	$client->close();

	exit 0;
}

###############################################################################
