#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_refresh_peer() re-runs the balancer's peer.init
# on a queued request before every retry, so it starts over from a clean,
# current state (see queue_backup.t for why).  peer.init is written for a
# brand new request: it resets u->peer.tries to the full peer count and
# clears the rrp->tried bitmap.  Run on a request that has already failed
# some attempts, that hands it a fresh retry budget - proxy_next_upstream_tries
# and the attempts already spent are both forgotten - and lets it go back
# to the very peers it failed on.
#
# Worse, the retry timer refreshes the head request on every tick: the
# reset makes an already-failed peer selectable again, the probe sees it
# as available, the request is drained into it, fails, finds the other
# peer busy, queues again - and the next tick starts the same cycle over,
# until the queue timeout finally answers 504.
#
# Layout, run once for a static upstream and once for one with a
# `resolve` server:
#   - peer A: a backend that accepts exactly one connection and then
#     stops listening; max_conns=1;
#   - peer B: a closed port, every connect is refused;
#   - proxy_next_upstream_tries 2, max_fails=0 on both (keeps every peer
#     selectable, so nothing but the tries budget limits the attempts);
#   - a holder request takes A's only slot, unanswered;
#   - request R then fails on B (attempt 1), finds A busy and queues.
#
# Expected: R makes exactly one more attempt, on A once the holder lets go
# - not on B again - and then gets a 502: two attempts in total, as
# proxy_next_upstream_tries says, on two different peers, as nginx itself
# would do without a queue.  So the module keeps the retry budget across
# refreshes, and remembers the peers the request has failed on to mark
# them in rrp->tried again.  Counted from $upstream_addr, ignoring the
# upstream-name entries a queued connect leaves behind.
#
# The retry timer's probe needs a refresh after it as well: it calls
# peer.get(), which marks the peer it picks in the request's rrp->tried.
# Left there, drain() could not pick the very peer the probe had just
# found free, so the request queued again and every later probe came
# back BUSY until the queue timeout.  The last scenario covers that:
# peer A of a static upstream fails and is
# disabled for fail_timeout=1s (the other peer is "down"), R queues,
# A comes back up - and R must be served once fail_timeout is over,
# not answered with 504 at the queue timeout.

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

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the static servers are written with their raw numbers below.

my $static_port = port(8081);
my $resolve_port = port(8083);
my $probe_port = port(8084);
my $dns_port = port(8982, udp => 1);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:$dns_port valid=1h;
    resolver_timeout 1s;

    upstream static_backend {
        server 127.0.0.1:8081 max_conns=1 max_fails=0;
        server 127.0.0.1:8082 max_fails=0;
        queue 5 timeout=5s;
    }

    upstream resolve_backend {
        zone resolve_backend_zone 1m;
        server example.net:$resolve_port resolve max_conns=1 max_fails=0;
        server 127.0.0.1:8082 max_fails=0;
        queue 5 timeout=5s;
    }

    upstream probe_backend {
        server 127.0.0.1:8084 max_fails=1 fail_timeout=1s;
        server 127.0.0.1:8085 down;
        queue 5 timeout=4s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;

        proxy_next_upstream error timeout;
        proxy_next_upstream_tries 2;
        proxy_connect_timeout 5s;
        proxy_read_timeout 10s;

        location /static/ {
            proxy_pass http://static_backend;
        }

        location /resolve/ {
            proxy_pass http://resolve_backend;
        }

        location /probe/ {
            proxy_pass http://probe_backend;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $dns_port);
$t->run_daemon(\&hold_backend, $static_port);
$t->run_daemon(\&hold_backend, $resolve_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(8);

###############################################################################

my ($status, $attempts, $addr) = scenario('/static/');

is($status, 502, 'static upstream: queued request ends with 502')
	or diag("X-Upstream-Addr: $addr");
is($attempts, 2, 'static upstream: proxy_next_upstream_tries 2 respected '
	. 'across the queue') or diag("X-Upstream-Addr: $addr");
is(distinct_peers($addr), 2, 'static upstream: R does not retry the peer it '
	. 'already failed on') or diag("X-Upstream-Addr: $addr");

# Give the resolver time to answer before relying on example.net.

select(undef, undef, undef, 1);

($status, $attempts, $addr) = scenario('/resolve/');

is($status, 502, 'resolve upstream: queued request ends with 502')
	or diag("X-Upstream-Addr: $addr");
is($attempts, 2, 'resolve upstream: proxy_next_upstream_tries 2 respected '
	. 'across snapshot refreshes') or diag("X-Upstream-Addr: $addr");
is(distinct_peers($addr), 2, 'resolve upstream: R does not retry the peer it '
	. 'already failed on') or diag("X-Upstream-Addr: $addr");

# Peer A is not listening yet: X fails on it and disables it for 1s.

read_response(send_request('/probe/X'), 5);

my $start = time();
my $s = send_request('/probe/R');

# R is queued now; bring A up while it waits out fail_timeout.

select(undef, undef, undef, 0.2);
$t->run_daemon(\&ok_backend, $probe_port);

my $resp = read_response($s, 8);
my $elapsed = time() - $start;

like($resp, qr!^HTTP/1\.[01] 200 !,
	'retry probe: queued request is served once the peer is back')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 3, 'retry probe: served after fail_timeout, not at the '
	. 'queue timeout') or diag("elapsed: $elapsed");

###############################################################################

sub distinct_peers {
	my ($addr) = @_;
	my %peers = map { $_ => 1 } $addr =~ /(\d+\.\d+\.\d+\.\d+:\d+)/g;
	return scalar keys %peers;
}

sub scenario {
	my ($prefix) = @_;

	my $holder = send_request($prefix . 'holder');

	# Let the holder reach A and take its slot before R arrives.

	select(undef, undef, undef, 0.5);

	my $s = send_request($prefix . 'R');
	my $resp = read_response($s, 10);

	my ($status) = $resp =~ m!^HTTP/1\.[01] (\d{3}) !;
	my ($addr) = $resp =~ m!^X-Upstream-Addr: ([^\r\n]*)!mi;
	$addr //= '';

	my $attempts = () = $addr =~ /\d+\.\d+\.\d+\.\d+:\d+/g;

	read_response($holder, 5);

	return ($status // 0, $attempts, $addr);
}

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

sub hold_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept backend connection: $!\n";

	# From here on, connects to this port are refused.

	$server->close();

	# Hold the only slot long enough for R to fail once and queue.

	select(undef, undef, undef, 1.5);

	$client->close();

	exit 0;
}

sub ok_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {
		$client->sysread(my $buf, 65536);
		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		$client->close();
	}
}

# Minimal mock DNS server: example.net always resolves to 127.0.0.1 - see
# t/queue_resolve_gap.t for the fuller, commented version.

sub dns_daemon {
	my ($t, $dns_port) = @_;

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $dns_port,
		Proto => 'udp',
	) or die "Can't create DNS listening socket: $!\n";

	open my $fh, '>', $t->testdir() . '/dns_ready';
	close $fh;

	while (1) {
		my $data;
		$socket->recv($data, 65536);
		$socket->send(dns_reply($data, '127.0.0.1'));
	}
}

sub dns_reply {
	my ($recv_data, $addr) = @_;

	use constant NOERROR => 0;
	use constant A => 1;
	use constant IN => 1;

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);
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

	if ($name eq 'example.net' && $type == A) {
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
