#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module: `resolve` servers whose names
# resolve to IPv6 (AAAA) addresses.
#
# The module itself never looks at peer addresses, but queued requests do
# depend on the resolver's results reaching their retries (see
# queue_resolve_gap.t and queue_resolve_backup.t), so the same paths are
# exercised with AAAA records:
#   - S1: the only server resolves to [::1] alone, and is busy.  R must
#     get it once it frees up.
#   - S2: the primary's name only starts resolving (to [::1]) while R is
#     queued; the static IPv4 backup is busy.  R must get the primary
#     well before the queue timeout.
#   - S3: one name resolves to both 127.0.0.1 and [::1], one peer each,
#     and both are busy.  R must get whichever frees up.
# Each R must have waited in the queue (the upstream name shows up in
# $upstream_addr) and then be served by the right peer.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::IP;
use Socket qw/ AF_INET6 inet_pton /;
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

IO::Socket::IP->new(LocalHost => '::1', LocalPort => 0, Listen => 1)
	or Test::More::plan(skip_all => 'no IPv6 on ::1');

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone/);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the static server is written with its raw number below; the `resolve`
# ones get their remapped ports.

my $s1_port = port(8081);
my $s2_port = port(8083);
my $s3_port = port(8085);
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
        server v6.example.net:$s1_port resolve max_conns=1;
        queue 5 timeout=4s;
    }

    upstream s2 {
        zone s2 64k;
        server late6.example.net:$s2_port resolve max_conns=1;
        server 127.0.0.1:8084 max_conns=1 backup;
        queue 5 timeout=6s;
    }

    upstream s3 {
        zone s3 64k;
        server dual.example.net:$s3_port resolve max_conns=1;
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
$t->run_daemon(\&first_slow_backend, '::1', $s1_port);
$t->run_daemon(\&first_slow_backend, '::1', $s2_port);
$t->run_daemon(\&holding_backend, '127.0.0.1', port(8084));
$t->run_daemon(\&first_slow_backend, '127.0.0.1', $s3_port);
$t->run_daemon(\&first_slow_backend, '::1', $s3_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(6);

# Give the resolver time to answer for the names that do resolve.

select(undef, undef, undef, 1.5);

###############################################################################

# S1: H1 takes the only peer, [::1], answered after 1s.

{
	my $h1 = send_request('/s1/H1');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $resp = read_response(send_request('/s1/R'), 6);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s1, \[::1\]:$s1_port\r$!ms,
		'S1: queued, then served by the AAAA-only peer')
		or diag(summary($resp));
	ok($elapsed < 2, 'S1: as soon as it frees up')
		or diag("elapsed: $elapsed");
}

# S2: H2 takes the IPv4 backup; the primary's name doesn't resolve until R
# has queued.

{
	my $h2 = send_request('/s2/H2');
	select(undef, undef, undef, 0.3);

	my $start = time();
	my $r = send_request('/s2/R');
	select(undef, undef, undef, 0.5);
	$t->write_file('late_on', '');

	my $resp = read_response($r, 8);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s2, \[::1\]:$s2_port\r$!ms,
		'S2: queued, then served by [::1] once its name resolves')
		or diag(summary($resp));
	ok($elapsed < 5, 'S2: well before the 6s queue timeout')
		or diag("elapsed: $elapsed");
}

# S3: H1 and H2 take both peers of the dual-stack name, each answered
# after 1s.

{
	my $h1 = send_request('/s3/H1');
	select(undef, undef, undef, 0.2);
	my $h2 = send_request('/s3/H2');
	select(undef, undef, undef, 0.2);

	my $start = time();
	my $resp = read_response(send_request('/s3/R'), 6);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 200 .*^X-Upstream-Addr: s3, (127\.0\.0\.1|\[::1\]):$s3_port\r$!ms,
		'S3: queued, then served by a peer of the dual-stack name')
		or diag(summary($resp));
	ok($elapsed < 2, 'S3: as soon as one frees up')
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
	my ($host, $port) = @_;

	my $server = IO::Socket::IP->new(
		LocalHost => $host,
		LocalPort => $port,
		Listen => 5,
		ReuseAddr => 1,
	) or die "Can't create backend listening socket: $@\n";

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
	my ($host, $port) = @_;

	my $server = IO::Socket::IP->new(
		LocalHost => $host,
		LocalPort => $port,
		Listen => 5,
		ReuseAddr => 1,
	) or die "Can't create backend listening socket: $@\n";

	my @held;

	while (my $client = $server->accept()) {
		push @held, $client;
	}
}

# Minimal mock DNS server: v6.example.net resolves to ::1 (AAAA only),
# dual.example.net to both 127.0.0.1 and ::1, late6.example.net to ::1
# only once the test creates "late_on" - see t/queue_resolve_gap.t for the
# fuller, commented version.

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
	use constant AAAA => 28;
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

	my $v4 = $name eq 'dual.example.net';
	my $v6 = $name eq 'v6.example.net' || $name eq 'dual.example.net'
		|| ($name eq 'late6.example.net' && -e $t->testdir() . '/late_on');

	if ($v4 && $type == A) {
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, 1);
	}

	if ($v6 && $type == AAAA) {
		push @rdata, pack('n3N n a16', 0xc00c, AAAA, IN, $ttl, 16,
			inet_pton(AF_INET6, '::1'));
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

###############################################################################
