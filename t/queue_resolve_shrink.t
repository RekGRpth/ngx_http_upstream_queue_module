#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# Before a queued request is retried, refresh_peer() re-runs peer.init and
# recomputes its retry budget: the peer count (capped by
# proxy_next_upstream_tries) minus the attempts already made.  When a
# `resolve` server's addresses shrink while the request waits, that can
# come out at zero - yet drain() still connected the request, one attempt
# more than allowed, and to the one peer left, which round-robin's single
# peer path hands out whether tried or not.
#
# Layout: one `resolve` name, max_conns=1, max_fails=0.  It first resolves
# to 127.0.0.1, where nothing listens, and 127.0.0.2, where a backend
# holds whatever connects.
#   - H ends up holding 127.0.0.2;
#   - R fails on 127.0.0.1 (1 of its 2 tries), finds 127.0.0.2 busy and
#     queues;
#   - the name then resolves to 127.0.0.1 alone: one peer, R has no tries
#     left.
#
# Expected: R gets its 502 without connecting to 127.0.0.1 again.

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

IO::Socket::INET->new(LocalAddr => '127.0.0.2:0', Listen => 1)
	or Test::More::plan(skip_all => 'no 127.0.0.2');

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone/);

my $port = port(8081);
my $dns_port = port(8982, udp => 1);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:$dns_port valid=1s;
    resolver_timeout 1s;

    upstream backend {
        zone backend 64k;
        server multi.example.net:$port resolve max_conns=1 max_fails=0;
        queue 5 timeout=8s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;
        proxy_read_timeout 10s;

        location / {
            proxy_pass http://backend;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $dns_port);
$t->run_daemon(\&holding_backend, '127.0.0.2', $port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";
$t->waitforsocket("127.0.0.2:$port") or die "backend did not start\n";

$t->try_run('no resolve/zone support')->plan(3);

# Give the resolver time to answer with both addresses.

select(undef, undef, undef, 1.5);

###############################################################################

my $h = send_request('/H');
select(undef, undef, undef, 0.3);

my $start = time();
my $r = send_request('/R');
select(undef, undef, undef, 0.3);

# Now only 127.0.0.1.

$t->write_file('shrunk', '');

my $resp = read_response($r, 10);
my $elapsed = time() - $start;

my ($addr) = $resp =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;
$addr //= '';
my $tries = () = $addr =~ /127\.0\.0\.1:$port/g;

like($resp, qr!^HTTP/1\.[01] 502 !, 'R gets 502')
	or diag("X-Upstream-Addr: $addr");
is($tries, 1, 'without a second attempt on the peer it failed on')
	or diag("X-Upstream-Addr: $addr");
ok($elapsed < 6, 'once the shrink is seen, not at the queue timeout')
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
	my ($host, $port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "$host:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	my @held;

	while (my $client = $server->accept()) {
		push @held, $client;
	}
}

# Minimal mock DNS server: multi.example.net resolves to 127.0.0.1 and
# 127.0.0.2, or to 127.0.0.1 alone once the test creates "shrunk" - see
# t/queue_resolve_gap.t for the fuller, commented version.

sub dns_daemon {
	my ($t, $dns_port) = @_;

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $dns_port,
		Proto => 'udp',
	) or die "Can't create DNS listening socket: $!\n";

	open my $fh, '>', $t->testdir() . '/dns_ready';
	close $fh;

	while (1) {
		my $data;
		$socket->recv($data, 65536);
		$socket->send(dns_reply($t, $data));
	}
}

sub dns_reply {
	my ($t, $recv_data) = @_;

	use constant NOERROR => 0;
	use constant A => 1;
	use constant IN => 1;

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 1);
	my (@name, @rdata);

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);
	my $name = join('.', @name);

	if ($name eq 'multi.example.net' && $type == A) {
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, 1);
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, 2)
			unless -e $t->testdir() . '/shrunk';
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

###############################################################################
