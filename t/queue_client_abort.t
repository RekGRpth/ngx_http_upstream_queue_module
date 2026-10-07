#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# When a client goes away, ngx_http_upstream_check_broken_connection() sets
# c->error on its connection, but for a cacheable response it does not
# finalize the request: nginx goes on to fill the cache.  The queue
# timeout handler used to return early on c->error, so such a request,
# once its client had gone while it was queued, never timed out - it kept
# its place in the queue until some peer freed up, however long that took.
#
# Layout:
#   - one peer, max_conns=1, held by a holder request;
#   - proxy_cache on, so R's response is cacheable;
#   - queue 1 timeout=1s;
#   - R queues, and its client closes the connection;
#   - 2s later Q comes in.
#
# Expected: R times out after 1s like any queued request ("upstream queue
# timed out" in error.log), so Q finds the queue empty, queues, and gets
# its own 504 after 1s - not an immediate 502 for a full queue.

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

my $t = Test::Nginx->new()->has(qw/http proxy cache/)->plan(3);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the server is written with its raw number below.

my $port = port(8081);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path %%TESTDIR%%/cache keys_zone=cache:1m;

    upstream backend {
        server 127.0.0.1:8081 max_conns=1;
        queue 1 timeout=1s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_cache cache;
            proxy_cache_valid 200 1m;
            proxy_read_timeout 5s;
        }
    }
}

EOF

$t->run_daemon(\&holding_backend, $port);
$t->waitforsocket('127.0.0.1:' . $port)
	or die "backend did not start\n";

$t->run();

###############################################################################

my $holder = send_request('/holder');
select(undef, undef, undef, 0.2);

# R queues behind the holder, then its client goes away.

my $r = send_request('/R');
select(undef, undef, undef, 0.3);
$r->close();

select(undef, undef, undef, 1.7);

my $start = time();
my $q = send_request('/Q');
my $resp = read_response($q, 5);
my $elapsed = time() - $start;

like($t->read_file('error.log'),
	qr/upstream queue timed out.*"GET \/R /,
	'queued request whose client went away still times out');
like($resp, qr!^HTTP/1\.[01] 504 !, 'a later request finds room in the queue')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed > 0.7, 'it waits out its own timeout, rather than being '
	. 'turned away as if the queue were full') or diag("elapsed: $elapsed");

read_response($holder, 6);

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
