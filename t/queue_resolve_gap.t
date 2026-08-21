#!/usr/bin/perl

# Reproduction test for a gap raised in PR #7
# (https://github.com/RekGRpth/ngx_http_upstream_queue_module/pull/7):
# whether this module cooperates with the core `resolve` upstream
# server parameter.
#
# ngx_http_upstream_queue_peer_get() only ever re-tries a queued request
# from one place: ngx_http_upstream_queue_peer_free()'s drain loop, which
# runs when some *other* connection on the same upstream is released.
# Nothing in the module re-checks a queued request when the underlying
# peer set becomes selectable for an unrelated, exogenous reason - most
# notably, a `resolve` server's DNS answer changing from empty/unhealthy
# to a real, reachable address. If a request queues while there is
# nothing to connect to, and no other connection on that upstream ever
# frees a slot in the meantime, that request sits until its own queue
# timeout fires - even after the resolver has since handed the upstream
# a perfectly good peer.
#
# This test does not need a flaky real DNS lookup to show that: a
# `resolve` server with zero currently-resolved addresses already makes
# ngx_http_upstream_get_round_robin_peer() return NGX_BUSY (there is
# nothing to iterate), which is exactly the condition the queue module
# reacts to. So:
#
#   - a mock DNS server first answers empty for the upstream's hostname;
#   - a request queues (zero peers -> BUSY -> queued, not 502);
#   - the mock DNS is then switched to answer with a real, reachable
#     backend address;
#   - once the resolver's `valid` TTL elapses and it re-resolves, a
#     *fresh* request to the same upstream is used to confirm the peer
#     is now genuinely selectable and the backend genuinely reachable;
#   - the original, still-queued request is checked against that same
#     deadline.
#
# The last check encodes the *desired* behavior (queued request is
# served promptly once a peer becomes available), not what the module
# currently does. As of this writing it is expected to FAIL on `main`:
# the queued request instead sits until the full `queue timeout` and
# comes back 504, because nothing ever called peer.free() to drain it.
# That failure is the point - it confirms the gap PR #7 is about, and
# this test should start passing once a resolve-aware (or more general,
# exogenous-change-aware) retry lands, whether that is PR #7's polling
# timer, its optional core-patch hook, or something else.
#
# Running this also turned up something worse than a latency gap: the
# worker reliably SIGSEGVs (not just times out) when this specific
# request's own queue timeout eventually fires. gdb on the core shows
# the crash is in this module, not in the request having gone through
# any unusual client-side abort pattern - it reproduces with exactly
# one clean, unaborted control request:
#
#   #0 ngx_http_upstream_queue_cleanup_handler (...) at .../ngx_http_upstream_queue_module.c:75
#      75          ngx_queue_remove(&d->queue);
#   #1 ngx_destroy_pool
#   #2 ngx_http_free_request
#   ...
#   #8 ngx_http_upstream_queue_timeout_handler
#   #9 ngx_event_expire_timers
#
# At the crash, `d->queue` is `{prev = 0x0, next = 0x0}` - never linked
# via ngx_queue_insert_tail(), and not the self-referential state
# ngx_queue_init() leaves an empty node in either. Because
# ngx_queue_empty() is defined as `(h) == (h)->prev`, a NULL prev on a
# non-NULL h reads as "not empty", so ngx_http_upstream_queue_peer_get()
# (line ~71 area) takes the removal branch and ngx_queue_remove()
# dereferences the NULL next/prev. Separately, this same request's
# round-robin peer data (rrp) shows `config = 1` while the live
# ngx_http_upstream_rr_peers_t it points at reads `number = 0, peer =
# NULL` even well after the resolver added the real address and a
# fresh control request (B) had already succeeded against it - matching
# the `rrp->config != *peers->config` staleness check in
# ngx_http_upstream_get_round_robin_peer() (round-robin's own guard
# against reusing a peer-selection snapshot taken before the peer set
# changed). That is left as an open lead, not a proven root cause: it
# would mean a request already queued before a `resolve` update can
# never be served without a fresh peer.init(), which is a materially
# harder problem than "the queue doesn't retry" - worth someone with
# more time on this module confirming before relying on it. PR #7's
# second commit ("fix for behaviour when waking up queued connection")
# suggests its author hit the same class of problem.
#
# This crash is already caught by Test::Nginx's built-in "no alerts"
# check (part of the +2 that ->plan() adds), so no extra assertion was
# needed to report it - it shows up as a failed test on its own.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use Socket qw/ SOCK_STREAM /;
use Time::HiRes qw/ time /;

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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone/);

my $backend_port = port(8090);
my $dns_port = port(8982, udp => 1);
my $control_port = port(8083);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:$dns_port valid=1s;
    resolver_timeout 1s;

    upstream resolve_backend {
        zone resolve_backend_zone 1m;
        server example.net:$backend_port resolve max_fails=0;
        queue 5 timeout=6s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /resolve/ {
            proxy_pass http://resolve_backend/;
            proxy_connect_timeout 1s;
            proxy_read_timeout 2s;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $control_port, $dns_port);
$t->run_daemon(\&backend_daemon, $backend_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(3);

###############################################################################

# Let the very first (empty) resolve round-trip complete - the zone
# module schedules it almost immediately after worker start, well before
# this sleep ends.

select(undef, undef, undef, 0.4);

# A: queues immediately, since the upstream currently has zero resolved
# peers (BUSY, not "down" - queue_detect_all_peer_down does not apply
# here and is not needed for this to queue).

my $start_a = time();
my $a = send_request('/resolve/A');

select(undef, undef, undef, 0.3);

{
	my $sel = IO::Select->new($a);
	my @ready = $sel->can_read(0);
	is(scalar(@ready), 0,
		'sanity: request queues (no immediate response) while the '
		. 'resolve server has zero addresses');
}

# Flip the mock DNS to the real, reachable backend, then give the
# zone module time to re-resolve. Empirically this does not track the
# resolver's valid=1s TTL exactly (~2s observed), so wait generously.
# A single plain sleep plus one clean request is used deliberately
# (rather than a poll-with-abort-and-retry loop): an earlier version of
# this test polled with repeated send/close cycles, and the crash
# documented above reproduced just as reliably with a single, entirely
# unaborted control request - the abort churn was a red herring, not
# the cause. Keeping this to one clean request avoids conflating two
# different findings in one run.

update_dns($control_port, "127.0.0.1");
select(undef, undef, undef, 3.0);

# B: a fresh request sent now must succeed - this is the control that
# proves the resolve update and the backend itself are both genuinely
# fine, isolating any failure of A to the queue's retry logic
# specifically, not to DNS or backend health.

my $b = send_request('/resolve/B');
my $resp_b = read_response($b, 3);

like($resp_b, qr!^HTTP/1\.[01] 200 !,
	'control: a fresh request succeeds once DNS resolves a healthy peer');

# The real check: A was already queued *before* the peer became
# available. Nothing freed a slot on this upstream in the meantime, so
# the only way A gets served promptly is if something re-checks queued
# requests when the peer set changes for a reason other than peer.free().

my $resp_a = read_response($a, 6);
my $elapsed_a = time() - $start_a;

diag("request A: elapsed=${elapsed_a}s response=" .
	(($resp_a =~ m!^(HTTP/\S+ \d+ [^\r\n]*)!) ? $1 : '(no response)'));

ok($resp_a =~ m!^HTTP/1\.[01] 200 ! && $elapsed_a < 3.5,
	'queued request is served promptly once DNS resolves a healthy peer, '
	. 'not left waiting for the full queue timeout (PR #7 gap)');

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

sub update_dns {
	my ($control_port, $addr) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => "127.0.0.1:$control_port",
	) or die "Can't connect to dns control socket: $!\n";

	$s->autoflush(1);
	$s->syswrite("$addr\n");

	local $/ = "\n";
	my $reply = $s->getline();
	$s->close();

	return $reply;
}

sub backend_daemon {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {
		my $buf = '';
		while ($buf !~ /\r\n\r\n/) {
			my $n = $client->sysread(my $chunk, 1024);
			last unless $n;
			$buf .= $chunk;
		}

		$client->syswrite("HTTP/1.1 200 OK\r\n"
			. "Content-Length: 2\r\n"
			. "Connection: close\r\n\r\nOK");
		$client->close();
	}
}

# Minimal mock DNS server for the "example.net" hostname used by the
# `resolve` server above, adapted from nginx-tests/upstream_resolve.t
# (only A records, single address, no AAAA/CNAME/error handling - this
# test only needs to toggle between "no addresses" and "one address").
# A plain TCP control channel lets the main test process update the
# daemon's in-memory answer, since run_daemon() forks a separate process.

sub dns_daemon {
	my ($t, $control_port, $dns_port) = @_;
	my $addr = ''; # empty: answer with zero A records

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $dns_port,
		Proto => 'udp',
	) or die "Can't create DNS listening socket: $!\n";

	my $control = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$control_port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create dns control socket: $!\n";

	my $sel = IO::Select->new($socket, $control);
	local $SIG{PIPE} = 'IGNORE';

	open my $fh, '>', $t->testdir() . '/dns_ready';
	close $fh;

	while (my @ready = $sel->can_read) {
		for my $fh (@ready) {
			if ($fh == $control) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif ($fh == $socket) {
				my $data;
				$fh->recv($data, 65536);
				$fh->send(dns_reply($data, $addr));

			} else {
				my $line = $fh->getline();
				if (defined $line) {
					chomp $line;
					$addr = $line;
					$fh->syswrite("OK\n");
				}
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub dns_reply {
	my ($recv_data, $addr) = @_;

	use constant NOERROR => 0;
	use constant A => 1;
	use constant IN => 1;

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 1);
	my (@name, @rdata);

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);
	my $name = join('.', @name);

	if ($name eq 'example.net' && $type == A && length($addr)) {
		push @rdata, rd_addr($ttl, $addr);
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;
	pack 'n3N nC4', 0xc00c, A, IN, $ttl, 4, split(/\./, $addr);
}

###############################################################################
