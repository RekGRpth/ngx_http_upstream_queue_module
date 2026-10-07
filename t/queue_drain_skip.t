#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# When a connection frees a slot, ngx_http_upstream_queue_drain() pops the
# head of the queue and reconnects it.  That request can find no peer it
# may use - e.g. the freed slot is on a peer it has already tried - and go
# straight back into the queue, leaving the slot free.  drain() used to
# stop there anyway, so a request further back that could have taken the
# slot waited for the next retry timer tick (or some other free) instead.
#
# Layout:
#   - peer A: nothing listens at first, max_conns=1, max_fails=0;
#   - peer B: a backend that accepts one connection and holds it, then
#     stops listening; max_conns=1;
#   - retry_interval=5s, so the timer can't hide the difference;
#   - a holder request is refused by A and ends up holding B;
#   - R1 is refused by A as well (A is now in R1's rrp->tried) and
#     queues;
#   - A comes up, answering each request after 1s; T takes A's slot;
#   - R2 queues behind R1 while A and B are both busy.
#
# When T finishes and frees A, R1 (at the head) can't use A and queues
# again.  Expected: R2, which can, gets A right then - answered about 2s
# after it was sent, not only once the holder lets B go or the retry
# timer fires, ~5s in.

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
        server 127.0.0.1:8081 max_conns=1 max_fails=0;
        server 127.0.0.1:8082 max_conns=1 max_fails=0;
        queue 5 timeout=10s retry_interval=5s;
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

my $r1 = send_request('/R1');
select(undef, undef, undef, 0.3);

$t->run_daemon(\&slow_backend, $a_port);
$t->waitforsocket('127.0.0.1:' . $a_port)
	or die "backend A did not start\n";

my $tr = send_request('/T');
select(undef, undef, undef, 0.2);

my $start = time();
my $r2 = send_request('/R2');

my $tresp = read_response($tr, 5);
my $resp = read_response($r2, 10);
my $elapsed = time() - $start;

like($tresp, qr!^HTTP/1\.[01] 200 !, 'T is served by A');
like($resp, qr!^HTTP/1\.[01] 200 !, 'R2 is served')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 3, 'R2 gets the slot T frees, even though R1 ahead of it '
	. 'cannot use it') or diag("elapsed: $elapsed");

read_response($r1, 10);
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

	select(undef, undef, undef, 5);

	$client->close();

	exit 0;
}

sub slow_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {

		# waitforsocket()'s probe sends nothing and just closes.

		if ($client->sysread(my $buf, 65536)) {
			select(undef, undef, undef, 1);
			$client->syswrite(
				"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		}

		$client->close();
	}
}

###############################################################################
