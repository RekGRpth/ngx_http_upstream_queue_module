#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module with least_time, a balancer
# built on round-robin's peer data (ngx_http_upstream_rr_peer_data_t
# first) that installs its own peer.free.
#
# The module has to tell such balancers apart from ones with peer data
# of their own (e.g. the third-party fair) both for
# queue_detect_all_peer_down, which scans the peer data, and for marking
# the peers a queued request has already failed on in rrp->tried.  Going
# by peer.free mistook least_time for a foreign balancer and turned both
# off for it.
#
#   - detect: with every peer down, a request must fail over at once
#     (502), as with plain round-robin - not wait in the queue for its
#     timeout (504) - and no "is ignored" warning is logged;
#   - tried: a request that failed on B and queued behind a busy A must
#     try A next, not B again.

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

my $t = Test::Nginx->new()->has(qw/http proxy/);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.  Nothing
# listens on 8082, 8083 and 8084.

my $a_port = port(8081);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream down {
        least_time header;
        server 127.0.0.1:8082 max_fails=1 fail_timeout=10s;
        server 127.0.0.1:8083 max_fails=1 fail_timeout=10s;
        queue 5 timeout=2s;
        queue_detect_all_peer_down on;
    }

    upstream tried {
        least_time header;
        server 127.0.0.1:8081 max_conns=1 max_fails=0;
        server 127.0.0.1:8084 max_fails=0;
        queue 5 timeout=5s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;
        proxy_next_upstream error timeout;
        proxy_next_upstream_tries 2;

        location /down/ {
            proxy_pass http://down;
        }

        location /tried/ {
            proxy_pass http://tried;
        }
    }
}

EOF

$t->run_daemon(\&holding_backend, $a_port);
$t->waitforsocket('127.0.0.1:' . $a_port) or die "backend did not start\n";

$t->try_run('no least_time')->plan(4);

###############################################################################

# X fails on both peers and gets them disabled; Y then finds no live peer.

read_response(send_request('/down/X'), 5);

my $start = time();
my $y = read_response(send_request('/down/Y'), 5);
my $elapsed = time() - $start;

like($y, qr!^HTTP/1\.[01] 502 !, 'detect: all peers down, 502');
ok($elapsed < 0.5, 'detect: at once, without queueing')
	or diag("elapsed: $elapsed");

# The holder takes A's only slot; R fails on B and queues.  The holder
# backend closes A after 1s, so R's retry on A fails too: 502 either way,
# what matters is where the second attempt went.

my $holder = send_request('/tried/holder');
select(undef, undef, undef, 0.3);

my $r = read_response(send_request('/tried/R'), 6);
my ($addr) = $r =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;
$addr //= '';
my %peers = map { $_ => 1 } $addr =~ /(\d+\.\d+\.\d+\.\d+:\d+)/g;

is(scalar keys %peers, 2, 'tried: the queued request does not retry the '
	. 'peer it already failed on') or diag("X-Upstream-Addr: $addr");

read_response($holder, 3);

unlike($t->read_file('error.log'), qr/queue_detect_all_peer_down is ignored/,
	'least_time recognized as built on round-robin');

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

# Accepts the holder's connection and closes it after 1s unanswered, then
# stops listening.

sub holding_backend {
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

	select(undef, undef, undef, 1);

	$client->close();

	exit 0;
}

###############################################################################
