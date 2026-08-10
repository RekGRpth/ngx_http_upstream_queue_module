#!/usr/bin/perl

# Basic functional tests for ngx_http_upstream_queue_module.
#
# Unlike queue_cascade.t and queue_connect_timeout_race.t, which each
# target one specific fix, this file covers the module's ordinary,
# documented behaviour end to end: FIFO ordering, the queue directive's
# own size cap, its timeout, queue_detect_all_peer_down, and cleanup when
# a queued client goes away before ever getting a slot.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;
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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(11);

my $fifo_sock = $t->testdir() . '/fifo.sock';
my $full_sock = $t->testdir() . '/full.sock';
my $timeout_sock = $t->testdir() . '/timeout.sock';
my $abort_sock = $t->testdir() . '/abort.sock';

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream fifo_backend {
        server unix:$fifo_sock max_conns=1 max_fails=0;
        queue 10 timeout=5s;
    }

    upstream full_backend {
        server unix:$full_sock max_conns=1 max_fails=0;
        queue 1 timeout=5s;
    }

    upstream timeout_backend {
        server unix:$timeout_sock max_conns=1 max_fails=0;
        queue 10 timeout=1s;
    }

    upstream abort_backend {
        server unix:$abort_sock max_conns=1 max_fails=0;
        queue 1 timeout=3s;
    }

    # Never reachable, statically down: exercises queue_detect_all_peer_down
    # without needing to hold a real connection open.
    upstream detect_off_backend {
        server 127.0.0.1:1 down;
        queue 5 timeout=1s;
    }

    upstream detect_on_backend {
        server 127.0.0.1:1 down;
        queue 5 timeout=1s;
        queue_detect_all_peer_down on;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /fifo/ {
            proxy_pass http://fifo_backend/;
            proxy_connect_timeout 5s;
        }
        location /full/ {
            proxy_pass http://full_backend/;
            proxy_connect_timeout 5s;
        }
        location /timeout/ {
            proxy_pass http://timeout_backend/;
            proxy_connect_timeout 5s;
        }
        location /abort/ {
            proxy_pass http://abort_backend/;
            proxy_connect_timeout 5s;
        }
        location /detect_off/ {
            proxy_pass http://detect_off_backend/;
            proxy_connect_timeout 5s;
        }
        location /detect_on/ {
            proxy_pass http://detect_on_backend/;
            proxy_connect_timeout 5s;
        }
    }
}

EOF

$t->run_daemon(\&echo_backend, $fifo_sock);
$t->run_daemon(\&hold_backend, $full_sock);
$t->run_daemon(\&hold_backend, $timeout_sock);
$t->run_daemon(\&hold_backend, $abort_sock);
$t->waitforfile($fifo_sock) or die "fifo backend did not start\n";
$t->waitforfile($full_sock) or die "full backend did not start\n";
$t->waitforfile($timeout_sock) or die "timeout backend did not start\n";
$t->waitforfile($abort_sock) or die "abort backend did not start\n";

$t->run();

###############################################################################
# 1: FIFO ordering - queued requests are served in arrival order.
###############################################################################

{
	my $holder = send_request('/fifo/holder');

	# Deliberately short: must clear well before echo_backend's own
	# response delay below, so B and C are both still sitting in the
	# queue - not already dequeued and connecting for real - at the
	# moment the holder's slot is freed. That is what actually exercises
	# the drain loop with more than one item queued at once.
	select(undef, undef, undef, 0.05);

	my $b = send_request('/fifo/B');
	my $c = send_request('/fifo/C');

	my @order;
	my %body;
	my $sel = IO::Select->new($holder, $b, $c);
	my %sock_name = ("$holder" => 'holder', "$b" => 'B', "$c" => 'C');
	my $deadline = time() + 10;

	while ($sel->count() && time() < $deadline) {
		for my $s ($sel->can_read(0.2)) {
			my $n = sysread($s, my $chunk, 65536);
			if (!$n) {
				$sel->remove($s);
				push @order, $sock_name{"$s"};
				next;
			}
			$body{"$s"} .= $chunk;
		}
	}

	is("@order", "holder B C", 'queued requests are served in FIFO order');
}

###############################################################################
# 2: queue N - once the queue is at capacity, further requests are
# rejected immediately (502), not queued.
###############################################################################

{
	my $holder = send_request('/full/holder');
	select(undef, undef, undef, 0.2);

	my $x = send_request('/full/X');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $y = send_request('/full/Y');
	my $resp = read_response($y, 2);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 502 !, 'queue full: extra request gets 502');
	ok($elapsed < 1, 'queue full: rejection is immediate, not queued')
		or diag("elapsed: $elapsed");
}

###############################################################################
# 3: queue timeout - a request that never gets a slot times out with 504
# after the configured duration.
###############################################################################

{
	my $holder = send_request('/timeout/holder');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $z = send_request('/timeout/Z');
	my $resp = read_response($z, 5);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 504 !, 'queue timeout: 504 after the timeout');
	ok($elapsed > 0.7 && $elapsed < 3,
		'queue timeout: fires around the configured 1s, not immediately '
		. 'and not stuck')
		or diag("elapsed: $elapsed");
}

###############################################################################
# 4: queue_detect_all_peer_down - off queues and waits for the full
# timeout, on fails over immediately.
###############################################################################

{
	my $start = time();
	my $s = send_request('/detect_off/');
	my $resp = read_response($s, 5);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 50[24] !,
		'queue_detect_all_peer_down off: request still queues');
	ok($elapsed > 0.7,
		'queue_detect_all_peer_down off: waits for the queue timeout '
		. 'instead of failing fast')
		or diag("elapsed: $elapsed");
}

{
	my $start = time();
	my $s = send_request('/detect_on/');
	my $resp = read_response($s, 5);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 502 !,
		'queue_detect_all_peer_down on: fails over instead of queueing');
	ok($elapsed < 0.5,
		'queue_detect_all_peer_down on: fails over immediately')
		or diag("elapsed: $elapsed");
}

###############################################################################
# 5: a client that disappears while its request is still queued must not
# leak its slot - ngx_http_upstream_queue_cleanup_handler has to run and
# actually free it back up.
###############################################################################

{
	my $holder = send_request('/abort/holder');
	select(undef, undef, undef, 0.2);

	my $q = send_request('/abort/Q');
	select(undef, undef, undef, 0.2);
	$q->close();
	select(undef, undef, undef, 0.3);

	my $log = $t->read_file('error.log');
	ok($log =~ /ngx_http_upstream_queue_cleanup_handler/,
		'aborted queued request runs the queue cleanup handler');

	# queue is "1" for this upstream, so if the aborted request's slot
	# was not reclaimed, this next one would be bounced immediately with
	# a "queue full" 502 instead of actually queueing.
	my $r = send_request('/abort/R');
	my $sel = IO::Select->new($r);
	my @ready = $sel->can_read(0.4);

	is(scalar(@ready), 0,
		'the reclaimed slot lets a new request queue instead of being '
		. 'rejected as "queue full"');
}

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

sub echo_backend {
	my ($path) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	while (my $client = $server->accept()) {
		my $buf = '';
		while ($buf !~ /\r\n\r\n/) {
			my $n = $client->sysread(my $chunk, 1024);
			last unless $n;
			$buf .= $chunk;
		}

		my ($uri) = $buf =~ m!^GET (\S+)!;
		$uri = '?' unless defined $uri;

		# Deliberate delay: gives the other requests in the FIFO test
		# time to actually reach the queue before this one finishes.
		select(undef, undef, undef, 0.3);

		$client->syswrite("HTTP/1.1 200 OK\r\n"
			. "Content-Length: " . length($uri) . "\r\n"
			. "Connection: close\r\n\r\n$uri");
		$client->close();
	}
}

sub hold_backend {
	my ($path) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept unix connection: $!\n";

	# Holds the only slot for the rest of the test; never answers.
	select(undef, undef, undef, 20);
	exit 0;
}

###############################################################################
