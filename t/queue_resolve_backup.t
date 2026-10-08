#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module: `resolve` servers together
# with backup servers.
#
# A queued request is only retried after its balancer answered NGX_BUSY,
# and round-robin leaves the request's peer data on the backup set by
# then (see queue_backup.t); with `resolve`, the request's snapshot of the
# peer set can also go stale while it waits (see queue_resolve_gap.t).
# Each retry has to start from fresh, current peer data for both to work
# out, in every combination:
#   - S1: primary is a `resolve` server, backup is static; both busy.
#     R must get the primary once it frees up.
#   - S2: primary is a `resolve` server not resolved yet, backup is
#     static and busy.  R must get the primary once its name resolves,
#     well before the queue timeout.
#   - S3: primary is static and busy, backup is a `resolve` server, busy
#     as well.  R must get the backup once it frees up.
# Each R must have waited in the queue (the upstream name shows up in
# $upstream_addr) and then be served by the right peer.

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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone/);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the static servers are written with their raw numbers below; the
# `resolve` ones resolve to 127.0.0.1 and get their remapped ports.

my $s1_primary = port(8081);
my $s2_primary = port(8083);
my $s3_backup = port(8085);
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

    upstream s1 {
        zone s1 64k;
        server example.net:$s1_primary resolve max_conns=1;
        server 127.0.0.1:8082 max_conns=1 backup;
        queue 5 timeout=4s;
    }

    upstream s2 {
        zone s2 64k;
        server late.example.net:$s2_primary resolve max_conns=1;
        server 127.0.0.1:8084 max_conns=1 backup;
        queue 5 timeout=6s;
    }

    upstream s3 {
        zone s3 64k;
        server 127.0.0.1:8086 max_conns=1;
        server backup.example.net:$s3_backup resolve max_conns=1 backup;
        queue 5 timeout=4s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_read_timeout 4s;
        add_header X-Upstream-Addr \$upstream_addr always;

        location /s1/ {
            proxy_pass http://s1;
        }

        location /s2/ {
            proxy_pass http://s2;
        }

        location /s3/ {
            proxy_pass http://s3;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $dns_port);
$t->run_daemon(\&first_slow_backend, $s1_primary);
$t->run_daemon(\&holding_backend, port(8082));
$t->run_daemon(\&first_slow_backend, $s2_primary);
$t->run_daemon(\&holding_backend, port(8084));
$t->run_daemon(\&holding_backend, port(8086));
$t->run_daemon(\&first_slow_backend, $s3_backup);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(6);

# Give the resolver time to answer for the names that do resolve.

select(undef, undef, undef, 1.5);

###############################################################################

# S1: H1 takes the primary (answered after 1s), H2 the backup.

{
	my $h1 = send_request('/s1/H1');
	select(undef, undef, undef, 0.2);
	my $h2 = send_request('/s1/H2');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $resp = read_response(send_request('/s1/R'), 6);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s1, 127\.0\.0\.1:$s1_primary\r$!ms,
		'S1: queued, then served by the resolve primary')
		or diag(summary($resp));
	ok($elapsed < 2, 'S1: as soon as the primary frees up')
		or diag("elapsed: $elapsed");
}

# S2: H2 takes the backup; the primary's name doesn't resolve until R has
# queued.

{
	my $h2 = send_request('/s2/H2');
	select(undef, undef, undef, 0.3);

	my $start = time();
	my $r = send_request('/s2/R');
	select(undef, undef, undef, 0.5);
	$t->write_file('late_on', '');

	my $resp = read_response($r, 8);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s2, 127\.0\.0\.1:$s2_primary\r$!ms,
		'S2: queued, then served by the primary once its name resolves')
		or diag(summary($resp));
	ok($elapsed < 5, 'S2: well before the 6s queue timeout')
		or diag("elapsed: $elapsed");
}

# S3: H1 takes the primary, H2 the resolve backup (answered after 1s).

{
	my $h1 = send_request('/s3/H1');
	select(undef, undef, undef, 0.2);
	my $h2 = send_request('/s3/H2');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $resp = read_response(send_request('/s3/R'), 6);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s3, 127\.0\.0\.1:$s3_backup\r$!ms,
		'S3: queued, then served by the resolve backup')
		or diag(summary($resp));
	ok($elapsed < 2, 'S3: as soon as the backup frees up')
		or diag("elapsed: $elapsed");
}

###############################################################################

sub summary {
	my ($resp) = @_;
	my ($status) = $resp =~ /^([^\r\n]*)/;
	my ($addr) = $resp =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;
	return ($status // '(no response)') . ', X-Upstream-Addr: '
		. ($addr // '(none)');
}

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

# Answers every request with 200, the first one only after 1s.

sub first_slow_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	my $first = 1;

	while (my $client = $server->accept()) {
		next unless $client->sysread(my $buf, 65536);

		if ($first) {
			$first = 0;
			select(undef, undef, undef, 1);
		}

		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		$client->close();
	}
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

# Minimal mock DNS server: example.net and backup.example.net resolve to
# 127.0.0.1, late.example.net only once the test creates "late_on" - see
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

	my $resolves = $name eq 'example.net' || $name eq 'backup.example.net'
		|| ($name eq 'late.example.net'
			&& -e $t->testdir() . '/late_on');

	if ($resolves && $type == A) {
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, 1);
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

###############################################################################
