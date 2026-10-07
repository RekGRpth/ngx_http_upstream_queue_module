#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_peer_get() started a fresh queue timeout every
# time it queued a request.  A request that ngx_http_upstream_queue_drain()
# pops and reconnects can find no peer again and land straight back in
# the queue - e.g. when the connection that freed the slot failed and got
# its peer disabled by max_fails.  Each such round restarted its timeout,
# so with enough of them a request could wait far longer than "timeout=".
#
# Layout:
#   - peer A: max_conns=1, max_fails=1, fail_timeout=10s; its backend
#     closes the first connection after 1.5s without answering;
#   - peer B: max_conns=1; its backend holds every connection;
#   - queue timeout=2s;
#   - H1 takes A, H2 takes B, R finds both busy and queues;
#   - H1's failure frees A's slot and disables A at the same time, so the
#     drain it triggers pops R, which finds no peer and queues again,
#     about 1.1s after it first queued.
#
# Expected: R still gets its 504 about 2s after it first queued, not 2s
# after it was queued again.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

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
        server 127.0.0.1:8081 max_conns=1 max_fails=1 fail_timeout=10s;
        server 127.0.0.1:8082 max_conns=1;
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

$t->run_daemon(\&failing_backend, $a_port);
$t->run_daemon(\&holding_backend, $b_port);
$t->waitforsocket('127.0.0.1:' . $a_port)
	or die "backend A did not start\n";
$t->waitforsocket('127.0.0.1:' . $b_port)
	or die "backend B did not start\n";

$t->run();

###############################################################################

my $h1 = send_request('/H1');
select(undef, undef, undef, 0.2);

my $h2 = send_request('/H2');
select(undef, undef, undef, 0.2);

my $start = time();
my $r = send_request('/R');
my $resp = read_response($r, 6);
my $elapsed = time() - $start;

like($resp, qr!^HTTP/1\.[01] 504 !, 'requeued request times out with 504')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 2.6,
	'requeued request times out at its original deadline, not later')
	or diag("elapsed: $elapsed");

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

sub failing_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {

		# waitforsocket()'s probe sends nothing and just closes.

		next unless $client->sysread(my $buf, 65536);

		select(undef, undef, undef, 1.5);
		$client->close();
	}
}

sub holding_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	my @held;

	while (my $client = $server->accept()) {
		push @held, $client;
	}
}

###############################################################################
