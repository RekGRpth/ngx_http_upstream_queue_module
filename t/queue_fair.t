#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module with the third-party
# nginx-upstream-fair balancer.
#
# fair keeps its own per-request peer data, not round-robin's.
# queue_detect_all_peer_down scans that data as round-robin's, and with
# fair it read a peer index as a pointer: the worker crashed on the first
# NGX_BUSY.  Now detection is skipped, with a warning, whenever the
# balancer is not built on round-robin (its peer.free is not
# ngx_http_upstream_free_round_robin_peer()).
#
# fair has no max_conns, so it only answers NGX_BUSY when every peer is
# down or failed - and then resets every peer's fail count itself.  So a
# request queued behind such peers is retried on the next retry timer
# tick, and with all of them still refusing it gets a 502 once its tries
# are spent.

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

my $objs = "$FindBin::Bin/../../nginx/objs";
my $module = "$objs/ngx_http_upstream_queue_module.so";
my $fair = "$objs/ngx_http_upstream_fair_module.so";

if (!-e $module) {
	Test::More::plan(skip_all => "$module not built");
}

if (!-e $fair) {
	Test::More::plan(skip_all => "$fair not built");
}

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(4);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.  Nothing
# listens on 8082 and 8083.

my $up_port = port(8081);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $fair;
load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream fair_up {
        fair;
        server 127.0.0.1:8081;
        queue 5 timeout=2s;
    }

    upstream fair_down {
        fair;
        server 127.0.0.1:8082 max_fails=1 fail_timeout=10s;
        server 127.0.0.1:8083 max_fails=1 fail_timeout=10s;
        queue 5 timeout=2s;
        queue_detect_all_peer_down on;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /up/ {
            proxy_pass http://fair_up;
        }

        location /down/ {
            proxy_pass http://fair_down;
        }
    }
}

EOF

$t->run_daemon(\&ok_backend, $up_port);
$t->waitforsocket('127.0.0.1:' . $up_port)
	or die "backend did not start\n";

$t->run();

###############################################################################

like(get('/up/'), qr!^HTTP/1\.[01] 200 !, 'fair + queue: request served');

# X fails on both peers and gets them disabled; Y then finds no peer, which
# is where queue_detect_all_peer_down looks at the peer data.

get('/down/X');

like(get('/down/Y'), qr!^HTTP/1\.[01] 502 !,
	'fair + queue_detect_all_peer_down, all peers down: 502');
like(get('/up/'), qr!^HTTP/1\.[01] 200 !, 'worker still serving afterwards');
like($t->read_file('error.log'),
	qr/queue_detect_all_peer_down is ignored/,
	'detection skipped, with a warning');

###############################################################################

sub get {
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

	my $resp = '';
	my $sel = IO::Select->new($s);

	while ($sel->can_read(5)) {
		my $n = sysread($s, my $chunk, 65536);
		last if !$n;
		$resp .= $chunk;
	}

	return $resp;
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

		# waitforsocket()'s probe sends nothing and just closes.

		next unless $client->sysread(my $buf, 65536);

		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		$client->close();
	}
}

###############################################################################
