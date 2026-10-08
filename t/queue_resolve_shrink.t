#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module: a queued request whose
# `resolve` server's addresses change while it waits, after it already
# failed on one of them.
#
# Before each retry, refresh_peer() re-runs peer.init and sets the
# request's retry budget: the peer count, capped by
# proxy_next_upstream_tries, minus the attempts already made.  The
# budget must not shrink with the peer set - neither a set that briefly
# resolves to nothing nor one that shrinks to peers the request never
# tried may cost it its remaining attempts.  But neither may the request
# go back to a peer it already failed on just because that is the only
# one left: round-robin hands a single peer out whether tried or not.
#
# Each scenario has its own `resolve` name and port, max_conns=1 and
# max_fails=0, first resolving to 127.0.0.1, where nothing listens, and
# 127.0.0.2, where a backend holds the first connection (H's) for 4s and
# answers everything with 200.  R fails on 127.0.0.1 (1 of its 2 tries),
# finds 127.0.0.2 busy and queues.  Then the name changes:
#   - A: to 127.0.0.1 alone - R must not try it again, and waits out
#     the queue (504);
#   - B: to 127.0.0.2 alone - R must get it once H is done (200);
#   - C: to nothing for a while, then back to both - R must wait and get
#     127.0.0.2 once H is done (200).

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

my %port = (a => port(8081), b => port(8082), c => port(8083));
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

    upstream a {
        zone a 64k;
        server a.example.net:$port{a} resolve max_conns=1 max_fails=0;
        queue 5 timeout=3s;
    }

    upstream b {
        zone b 64k;
        server b.example.net:$port{b} resolve max_conns=1 max_fails=0;
        queue 5 timeout=6s;
    }

    upstream c {
        zone c 64k;
        server c.example.net:$port{c} resolve max_conns=1 max_fails=0;
        queue 5 timeout=8s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;
        proxy_read_timeout 10s;

        location /a/ {
            proxy_pass http://a;
        }

        location /b/ {
            proxy_pass http://b;
        }

        location /c/ {
            proxy_pass http://c;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $dns_port);
$t->run_daemon(\&first_held_backend, '127.0.0.2', $port{$_}) for qw/ a b c /;
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";
$t->waitforsocket("127.0.0.2:$port{$_}") or die "backend did not start\n"
	for qw/ a b c /;

$t->try_run('no resolve/zone support')->plan(7);

# Give the resolver time to answer with both addresses.

select(undef, undef, undef, 1.5);

###############################################################################

# A: down to the peer R already failed on.

{
	my ($resp, $addr, $elapsed) = scenario('a', sub {
		$t->write_file('a_only_1', '');
	});

	like($resp, qr!^HTTP/1\.[01] 504 !, 'A: R waits out the queue')
		or diag("X-Upstream-Addr: $addr");
	is(attempts($addr, '127.0.0.1', $port{a}), 1,
		'A: without trying the peer it failed on again')
		or diag("X-Upstream-Addr: $addr");
}

# B: down to the peer R never tried.

{
	my ($resp, $addr, $elapsed) = scenario('b', sub {
		$t->write_file('b_only_2', '');
	});

	like($resp, qr!^HTTP/1\.[01] 200 !, 'B: R gets the peer it never tried')
		or diag("X-Upstream-Addr: $addr");
	ok($elapsed < 5.5, 'B: once H is done with it')
		or diag("elapsed: $elapsed");
}

# C: no addresses for a while, then both again.

{
	my ($resp, $addr, $elapsed) = scenario('c', sub {
		$t->write_file('c_empty', '');
		select(undef, undef, undef, 2);
		unlink $t->testdir() . '/c_empty';
	});

	like($resp, qr!^HTTP/1\.[01] 200 !, 'C: R survives the empty answers')
		or diag("X-Upstream-Addr: $addr");
	is(attempts($addr, '127.0.0.1', $port{c}), 1,
		'C: and gets the peer it never tried, not the one it failed on')
		or diag("X-Upstream-Addr: $addr");
	ok($elapsed < 7, 'C: before the queue timeout')
		or diag("elapsed: $elapsed");
}

###############################################################################

sub scenario {
	my ($name, $change) = @_;

	my $h = send_request("/$name/H");
	select(undef, undef, undef, 0.3);

	my $start = time();
	my $r = send_request("/$name/R");
	select(undef, undef, undef, 0.3);

	$change->();

	my $resp = read_response($r, 10);
	my $elapsed = time() - $start;

	my ($addr) = $resp =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;

	read_response($h, 6);

	return ($resp, $addr // '', $elapsed);
}

sub attempts {
	my ($addr, $ip, $port) = @_;
	return scalar(() = $addr =~ /\Q$ip\E:$port\b/g);
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

# Holds the first connection for 4s, then answers every request with 200.

sub first_held_backend {
	my ($host, $port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "$host:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';
	my $first = 1;

	while (my $client = $server->accept()) {
		my $delay = 0;

		# waitforsocket()'s probe sends nothing and just closes.

		next unless $client->sysread(my $buf, 65536);

		if ($first) {
			$first = 0;
			$delay = 4;
		}

		next if fork();

		select(undef, undef, undef, $delay);
		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		exit 0;
	}
}

# Minimal mock DNS server: [abc].example.net resolve to 127.0.0.1 and
# 127.0.0.2, changed by files the test creates - see
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
	my $d = $t->testdir();

	my @addrs;

	if ($name eq 'a.example.net') {
		@addrs = -e "$d/a_only_1" ? (1) : (1, 2);
	} elsif ($name eq 'b.example.net') {
		@addrs = -e "$d/b_only_2" ? (2) : (1, 2);
	} elsif ($name eq 'c.example.net') {
		@addrs = -e "$d/c_empty" ? () : (1, 2);
	}

	if ($type == A) {
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, $_)
			for @addrs;
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

###############################################################################
