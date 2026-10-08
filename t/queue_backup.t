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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(5);

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
