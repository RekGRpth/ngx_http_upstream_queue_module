#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# When ngx_http_upstream_get_round_robin_peer() finds no primary peer it
# switches the request's rrp->peers to the backup set (clearing
# rrp->tried), and leaves it there when the backup set has nothing free
# either - harmless in nginx itself, where NGX_BUSY ends the request.  A
# queued request is retried later, though, so before each retry the
# module has to re-run the balancer's peer.init: skipping that left the
# request looking at the backup set only, never at a primary peer that
# had freed up, until the queue timeout.
#
# Layout:
#   - primary peer A, max_conns=1: the first request is held 1s and then
#     answered, later ones are answered at once;
#   - backup peer C, max_conns=1: holds every connection;
#   - H1 takes A, H2 (finding A busy) takes C, R finds both busy and
#     queues.
#
# Expected: R gets A once H1 is done with it, about 1s in - not a 504 at
# the 3s queue timeout.

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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(10);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my $a_port = port(8081);
my $c_port = port(8082);

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
        server 127.0.0.1:8082 max_conns=1 backup;
        queue 5 timeout=3s;
    }

    upstream pr {
        server 127.0.0.1:8091 max_conns=1;
        server 127.0.0.1:8092 max_fails=2 fail_timeout=1s backup;
        queue 5 timeout=6s;
    }

    upstream lf {
        server 127.0.0.1:8089 max_conns=1;
        server 127.0.0.1:8090 max_fails=2 fail_timeout=1s backup;
        queue 5 timeout=5s;
    }

    upstream stale {
        server 127.0.0.1:8086 max_conns=1 max_fails=1 fail_timeout=10s;
        server 127.0.0.1:8087 max_conns=1 max_fails=0 backup;
        server 127.0.0.1:8088 max_conns=1 backup;
        queue 5 timeout=2s;
    }

    upstream backups {
        server 127.0.0.1:8083 max_conns=1;
        server 127.0.0.1:8084 max_fails=0 backup;
        server 127.0.0.1:8085 max_conns=1 backup;
        queue 5 timeout=5s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_read_timeout 20s;
        }

        location /pr/ {
            proxy_pass http://pr;
            proxy_read_timeout 20s;
        }

        location /lf/ {
            proxy_pass http://lf;
            proxy_read_timeout 20s;
            add_header X-Upstream-Addr \$upstream_addr always;
        }

        location /stale/ {
            proxy_pass http://stale;
            proxy_read_timeout 20s;
        }

        location /backups/ {
            proxy_pass http://backups;
            proxy_read_timeout 20s;
            add_header X-Upstream-Addr \$upstream_addr always;
        }
    }
}

EOF

$t->run_daemon(\&primary_backend, $a_port);
$t->run_daemon(\&backup_backend, $c_port);
$t->run_daemon(\&backup_backend, port(8083));
$t->run_daemon(\&primary_backend, port(8085));
$t->run_daemon(\&failing_once_backend, port(8086));
$t->run_daemon(\&backup_backend, port(8089));
$t->run_daemon(\&backup_backend, port(8091));
$t->waitforsocket('127.0.0.1:' . port(8091)) or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . port(8089)) or die "backend did not start\n";
$t->run_daemon(\&backup_backend, port(8088));
$t->waitforsocket('127.0.0.1:' . port(8086)) or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . port(8088)) or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . port(8083)) or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . port(8085)) or die "backend did not start\n";
$t->waitforsocket('127.0.0.1:' . $a_port)
	or die "backend A did not start\n";
$t->waitforsocket('127.0.0.1:' . $c_port)
	or die "backend C did not start\n";

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

like(read_response($h1, 5), qr!^HTTP/1\.[01] 200 !, 'H1 is served by A');
like($resp, qr!^HTTP/1\.[01] 200 !,
	'queued request gets the primary peer once it frees up')
	or diag($resp =~ /^([^\r\n]*)/ ? $1 : '(no response)');
ok($elapsed < 2, 'served when A frees up, not at the queue timeout')
	or diag("elapsed: $elapsed");

# Second upstream: H1 holds the primary for good, H2 a backup (B2) for
# 1s; the other backup (B1) refuses every connection.  R fails on B1,
# finds B2 busy and queues.  Once B2 frees up, R must get it - without
# trying B1 again, although round-robin clears rrp->tried each time it
# moves on to the backup set, which a retry from the queue makes it do
# once more.

{
	my $h1 = send_request('/backups/H1');
	select(undef, undef, undef, 0.2);
	my $h2 = send_request('/backups/H2');
	select(undef, undef, undef, 0.2);

	my $resp = read_response(send_request('/backups/R'), 6);
	my ($addr) = $resp =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;
	$addr //= '';
	my $b1 = port(8084);
	my $b1_tries = () = $addr =~ /:$b1\b/g;

	like($resp, qr!^HTTP/1\.[01] 200 !, 'backups: R served by B2')
		or diag("X-Upstream-Addr: $addr");
	is($b1_tries, 1, 'backups: R does not retry the backup it failed on')
		or diag("X-Upstream-Addr: $addr");

	read_response($h2, 3);
}

# Third upstream: H1 holds the primary P and fails after 1s, H2 holds the
# backup B2; nothing listens on the backup B1 yet, so R fails on it and
# queues.  H1's failure disables P and drains the queue: R's retry turns
# B1 away and finds B2 busy - and that BUSY used to leave R with B1 as
# its u->peer.sockaddr.  R then timed out, and finalizing it freed B1 a
# second time, wrapping its conns counter: with max_conns=1, B1 counted
# as busy for good.  Once B1 is up, a later request Q must get it.

{
	my $h1 = send_request('/stale/H1');
	select(undef, undef, undef, 0.2);
	my $h2 = send_request('/stale/H2');
	select(undef, undef, undef, 0.2);

	read_response(send_request('/stale/R'), 4);

	$t->run_daemon(\&primary_backend, port(8087));
	$t->waitforsocket('127.0.0.1:' . port(8087))
		or die "backend did not start\n";

	like(read_response(send_request('/stale/Q'), 5), qr!^HTTP/1\.[01] 200 !,
		'stale: a backup turned away from a queued request stays usable');
}

# Fourth upstream: H holds the primary for good; nothing listens on the
# only backup B1 (max_fails=2, fail_timeout=1s).  R fails on B1 (fails=1)
# and queues.  Once B1's fail_timeout is up, each retry tick has
# round-robin pick B1 to re-check it, and R turns it away - which used to
# count as a check that passed and reset B1's fails to 0.  Then Z1 fails
# on B1 too: with fails reset that is only 1 of 2, and Z2 went straight to
# B1 as well; without, it is 2 of 2, B1 is disabled for a second, and Z2
# stays off it.  Only Z2's first attempt matters, so the error log is
# checked right away, while B1 is still disabled.

{
	my $h = send_request('/lf/H');
	select(undef, undef, undef, 0.2);
	my $r = send_request('/lf/R');
	select(undef, undef, undef, 1.8);

	my $z1 = send_request('/lf/Z1');
	select(undef, undef, undef, 0.2);
	my $z2 = send_request('/lf/Z2');
	select(undef, undef, undef, 0.4);

	my $log = $t->read_file('error.log');

	like($log, qr/connect\(\) failed.*"GET \/lf\/Z1 /,
		'lf: Z1 failed on B1');
	unlike($log, qr/connect\(\) failed.*"GET \/lf\/Z2 /,
		'lf: turning a peer away from a queued request does not count '
		. 'as a passed check');
}

# Fifth upstream: H holds the primary for good; nothing listens on the
# only backup B1 (max_fails=2, fail_timeout=1s).  X1 and X2 fail on B1,
# which disables it, and queue; R, with no failures of its own, queues
# behind them.  Once fail_timeout is up, the retry timer's probe for R has
# round-robin pick B1 to re-check it, and hands it back - which used to
# count as a check that passed and reset B1's fails to 0.  R's real
# attempt then fails on B1: with fails reset that is only 1 of 2, and Z,
# right after, went to B1 as well; without, B1 is disabled again, and Z
# stays off it.

{
	my $h = send_request('/pr/H');
	select(undef, undef, undef, 0.2);
	my $x1 = send_request('/pr/X1');
	select(undef, undef, undef, 0.1);
	my $x2 = send_request('/pr/X2');
	select(undef, undef, undef, 0.1);
	my $r = send_request('/pr/R');

	my $log = '';
	for (1 .. 40) {
		$log = $t->read_file('error.log');
		last if $log =~ /connect\(\) failed.*"GET \/pr\/R /;
		select(undef, undef, undef, 0.1);
	}

	my $z = send_request('/pr/Z');
	select(undef, undef, undef, 0.3);
	$log = $t->read_file('error.log');

	like($log, qr/connect\(\) failed.*"GET \/pr\/R /,
		'pr: R tried B1 once its fail_timeout was over');
	unlike($log, qr/connect\(\) failed.*"GET \/pr\/Z /,
		'pr: a probe handing back a re-checked peer does not count as a '
		. 'passed check');
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

sub primary_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	my $first = 1;

	while (my $client = $server->accept()) {

		# waitforsocket()'s probe sends nothing and just closes.

		next unless $client->sysread(my $buf, 65536);

		if ($first) {
			$first = 0;
			select(undef, undef, undef, 1);
		}

		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		$client->close();
	}
}

# Accepts the first request and closes it after 1s without answering.

sub failing_once_backend {
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

		select(undef, undef, undef, 1);
		$client->close();
	}
}

sub backup_backend {
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
