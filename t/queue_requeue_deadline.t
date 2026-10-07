#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_peer_get() started a fresh queue timeout every
# time it queued a request.  A request that ngx_http_upstream_queue_drain()
# pops and reconnects can find no peer again and land straight back in
# the queue - e.g. when the slot that freed up is on a peer this request
# has already tried.  Each such round restarted its timeout, so with
# enough traffic freeing slots it could wait far longer than "timeout=",
# up to as long as it took a usable peer to free up.
#
# Layout:
#   - peer A: nothing listens at first, max_fails=0 (stays selectable);
#   - peer B: a backend that accepts one connection and holds it, then
#     stops listening; max_conns=1;
#   - queue timeout=2s;
#   - a holder request is refused by A and ends up holding B;
#   - request R is refused by A too (A is now in R's rrp->tried), finds
#     B busy and queues;
#   - A then comes up, and steady traffic through it frees a slot every
#     ~0.3s - each free drains R, which finds A tried and B busy, and
#     queues again.
#
# Expected: R still gets its 504 about 2s after it first queued, not
# an answer only once the holder lets B go.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(3);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my $a_port = port(8081);
my $b_port = port(8082);

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
        server 127.0.0.1:8081 max_fails=0;
        server 127.0.0.1:8082 max_conns=1 max_fails=0;
        queue 5 timeout=2s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_read_timeout 20s;
        }
    }
}

EOF

$t->run_daemon(\&hold_backend, $b_port);
$t->waitforsocket('127.0.0.1:' . $b_port)
	or die "backend B did not start\n";

$t->run();

###############################################################################

my $holder = send_request('/holder');
select(undef, undef, undef, 0.3);

my $start = time();
my $r = send_request('/R');
select(undef, undef, undef, 0.3);

$t->run_daemon(\&ok_backend, $a_port);
wait_listen($a_port) or die "backend A did not start\n";

# Traffic through A until R is answered, or well past the point where
# the holder releases B.

my $resp = '';
my $sel = IO::Select->new($r);
my $traffic_ok = 1;

while (time() < $start + 8) {
	my $s = send_request('/traffic');
	my $tr = read_response($s, 2);
	$traffic_ok = 0 unless $tr =~ m!^HTTP/1\.[01] 200 !;

	if ($sel->can_read(0)) {
		$resp = read_response($r, 2);
		last;
	}

	select(undef, undef, undef, 0.3);
}

my $elapsed = time() - $start;

ok($traffic_ok, 'traffic through A is served');
like($resp, qr!^HTTP/1\.[01] 504 !,
	'requeued request times out with 504')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 3.5,
	'requeued request times out at its original deadline, not later')
	or diag("elapsed: $elapsed");

read_response($holder, 10);

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

sub wait_listen {
	my ($port) = @_;

	for (1 .. 50) {
		my $s = IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => "127.0.0.1:$port",
		);
		return 1 if $s;
		select(undef, undef, undef, 0.05);
	}

	return 0;
}

sub hold_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	# The first connection is waitforsocket()'s own probe.

	$server->accept()->close();

	my $client = $server->accept()
		or die "Can't accept backend connection: $!\n";

	$server->close();

	select(undef, undef, undef, 6);

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

###############################################################################
