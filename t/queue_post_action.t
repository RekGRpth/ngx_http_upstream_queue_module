#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# A queued request that is finalized stays in the queue until its pool goes
# (a subrequest's pool is the main request's), and the module tells such a
# stale entry apart by its upstream having been finalized.  It used to look
# at r->upstream for that - but after finalization the request can start
# over with another upstream: post_action, for one, runs when the client
# goes away, and its proxy_pass creates a new ngx_http_upstream_t, not
# finalized.  The stale entry then looked live, and drain() went on to
# refresh, close the connection of and reconnect an upstream that wasn't
# its own (here one not even in a queue).
#
# Layout: one peer, max_conns=1, held by H for 1s; the location has a
# post_action that proxies to a backend taking 2s.  R queues behind H, and
# its client goes away: R is finalized (499), and its post_action starts.
# H is done while that post_action still runs, and drains the queue.
#
# Expected: no crash, and both post_actions reach their backend.

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

my $module = "$FindBin::Bin/../../nginx/objs/ngx_http_upstream_queue_module.so";

if (!-e $module) {
	Test::More::plan(skip_all => "$module not built");
}

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my $queue_port = port(8081);
my $pa_port = port(8082);
my $log = $t->testdir() . '/post_action.log';

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream q {
        server 127.0.0.1:8081 max_conns=1;
        queue 5 timeout=10s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://q;
            post_action /pa;
        }

        location /pa {
            proxy_pass http://127.0.0.1:8082;
        }
    }
}

EOF

$t->run_daemon(\&delayed_backend, $queue_port, 1, undef);
$t->run_daemon(\&delayed_backend, $pa_port, 2, $log);
$t->waitforsocket('127.0.0.1:' . $queue_port)
	or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . $pa_port)
	or die "post_action backend did not start\n";

$t->run();

###############################################################################

my $h = send_request('/H');
select(undef, undef, undef, 0.2);

my $r = send_request('/R');
select(undef, undef, undef, 0.2);
$r->close();

like(read_response($h, 5), qr!^HTTP/1\.[01] 200 !, 'H served');

# Both post_actions (H's and R's) reach the backend and finish.

select(undef, undef, undef, 3);

my $count = -e $log ? () = $t->read_file('post_action.log') =~ /^done$/mg : 0;
is($count, 2, 'both post_actions completed');

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

# Answers each request with 200 after $delay seconds, one process per
# connection; logs "done" for each answer if given a log.

sub delayed_backend {
	my ($port, $delay, $log) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		next if fork();

		# waitforsocket()'s probe sends nothing and just closes.

		exit 0 unless $client->sysread(my $buf, 65536);

		select(undef, undef, undef, $delay);
		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");

		if (defined $log) {
			open my $fh, '>>', $log or die "Can't open $log: $!\n";
			print $fh "done\n";
			close $fh;
		}

		exit 0;
	}
}

###############################################################################
