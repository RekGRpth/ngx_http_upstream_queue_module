#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_drain() runs from two different triggers:
# ngx_http_upstream_queue_peer_free(), whenever some other connection on
# the upstream genuinely releases a slot, and the retry timer, which
# polls every 200ms because there is no other way to notice a `resolve`
# server's peer set changing without patching nginx core. Each queued
# request's round-robin snapshot (ngx_http_upstream_rr_peer_data_t) is
# taken once, when it first queues; ngx_http_upstream_get_round_robin_peer()
# treats a mismatch between that snapshot's generation and the
# upstream's current one as permanently busy, no matter how many times
# it is retried, so a request that queued before a `resolve` server's
# peer set changed needs that snapshot refreshed before a retry can
# ever succeed.
#
# The retry timer already refreshes the snapshot of whichever request it
# probes. But ngx_http_upstream_queue_drain() only refreshed nothing on
# its own - meaning a *genuine* peer_free() event, the whole reason this
# module can normally react to freed slots instantly instead of on the
# next timer tick, did nothing for a request with a stale snapshot: it
# would see a false BUSY and just get silently re-queued again, having
# to wait out an entire extra timer interval for what a real event
# should have fixed on the spot.
#
# This test forces exactly that: two requests, First and Second, queue
# behind a `resolve` server with zero currently-resolved addresses (both
# snapshots taken while the peer set is still empty). DNS is then
# switched to a real, single-slot (max_conns=1) backend. The retry
# timer eventually refreshes and drains whichever request is at the
# head of the queue - First, by FIFO order - into the one slot. First's
# backend answers instantly, so First finishes fast and fires a *real*
# peer_free(). Second is still sitting on its original, stale snapshot
# at that point, exactly like First was before the timer refreshed it.
#
# What is asserted: that Second's response arrives essentially in the
# same instant as First's (a real free event unsticking it directly),
# not ~200ms later (having to wait for the next timer tick to notice
# and refresh it independently). Confirmed in both directions before
# writing this: reverting just the refresh call inside
# ngx_http_upstream_queue_drain() (keeping the retry timer's own
# refresh untouched) reproduces the ~200ms gap reliably; with it,
# the gap is a fraction of a millisecond.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
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
        server example.net:$backend_port resolve max_fails=0 max_conns=1;
        queue 5 timeout=8s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /resolve/ {
            proxy_pass http://resolve_backend/;
            proxy_connect_timeout 2s;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $control_port, $dns_port);
$t->run_daemon(\&backend_daemon, $backend_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(1);

###############################################################################

# Let the very first (empty) resolve round-trip complete before either
# request is sent, so both First and Second definitely take their
# stale, zero-peer snapshot.

select(undef, undef, undef, 0.4);

my $t_first_start = time();
my $first = send_request('/resolve/First');

select(undef, undef, undef, 0.1);

my $t_second_start = time();
my $second = send_request('/resolve/Second');

select(undef, undef, undef, 0.3);

# Flip DNS to the real, reachable, single-slot backend. The retry
# timer's own refresh+probe should pick First (the FIFO head) up on one
# of its 200ms ticks and drain it into the one slot.

update_dns($control_port, "127.0.0.1");

my $resp_first = read_response($first, 6);
my $t_first_done = time();

my $resp_second = read_response($second, 6);
my $t_second_done = time();

diag("First: elapsed=" . ($t_first_done - $t_first_start) . "s response=" .
	(($resp_first =~ m!^(HTTP\S* \d+ [^\r\n]*)!) ? $1 : '(no response)'));
diag("Second: elapsed=" . ($t_second_done - $t_second_start)
	. "s, arrived " . ($t_second_done - $t_first_done)
	. "s after First; response=" .
	(($resp_second =~ m!^(HTTP\S* \d+ [^\r\n]*)!) ? $1 : '(no response)'));

ok($resp_first =~ m!^HTTP/1\.[01] 200 !
	&& $resp_second =~ m!^HTTP/1\.[01] 200 !
	&& ($t_second_done - $t_first_done) < 0.15,
	'a real slot freeing up (First finishing) unsticks Second '
	. 'essentially immediately, not ~200ms later on the next retry '
	. 'timer tick');

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
# `resolve` server above - see t/queue_resolve_gap.t for the identical,
# more thoroughly commented version this was copied from.

sub dns_daemon {
	my ($t, $control_port, $dns_port) = @_;
	my $addr = '';

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
