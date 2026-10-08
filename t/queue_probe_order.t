#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# The retry timer probes the queue before draining it.  It used to probe
# the head only.  But a queued request may not use a peer it already
# failed on - so with that peer the only one free, the head kept probing
# busy on every tick, and a request behind it that could use the peer
# waited for some unrelated slot to free up, or for its queue timeout.
# Now, as long as the request probed has exclusions of its own, the
# timer goes on to the next one, and moves the first that can connect to
# the head before draining.
#
# Layout: the primary is held for good; nothing listens on the only
# backup B1 at first (max_fails=1, fail_timeout=1s).
#   - R fails on B1, which disables it for 1s, and queues - at the head;
#   - B1 comes up; Z finds it disabled still and queues behind R;
#   - once fail_timeout is over, B1 is free: R may not use it, Z may.
#
# Expected: Z gets B1 about a second in, not a 504 at the queue timeout.

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

my $primary_port = port(8081);
my $b1_port = port(8082);

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
        server 127.0.0.1:8081 max_conns=1;
        server 127.0.0.1:8082 max_fails=1 fail_timeout=1s backup;
        queue 5 timeout=6s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;

        location / {
            proxy_pass http://backend;
            proxy_read_timeout 20s;
        }
    }
}

EOF

$t->run_daemon(\&holding_backend, $primary_port);
$t->waitforsocket('127.0.0.1:' . $primary_port)
	or die "backend did not start\n";

$t->run();

###############################################################################

my $h = send_request('/H');
select(undef, undef, undef, 0.2);

my $r = send_request('/R');
select(undef, undef, undef, 0.2);

$t->run_daemon(\&ok_backend, $b1_port);
$t->waitforsocket('127.0.0.1:' . $b1_port) or die "B1 did not start\n";

my $start = time();
my $resp = read_response(send_request('/Z'), 8);
my $elapsed = time() - $start;

like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: backend, 127\.0\.0\.1:$b1_port\r$!ms,
	'Z queued, then got B1 although R ahead of it could not use it')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 3, 'once fail_timeout was over, not at the queue timeout')
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
