#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# queue_detect_all_peer_down walks the upstream's *current* round-robin
# peer list (ngx_http_upstream_rr_peer_data_t->peers->peer) looking for
# any peer that is neither explicitly down nor recently failed
# (max_fails within fail_timeout); if it finds none, the request fails
# over immediately (502) instead of queuing. That list is exactly what
# the `resolve` server / zone module dynamically adds to and removes
# from, so this checks two cases the rest of the test suite does not:
#
#   - before a `resolve` server's first successful DNS answer, the peer
#     list is genuinely empty (not "down" - there is nothing there at
#     all). The loop's "found nothing selectable" fallback (all_peers_down
#     stays at its initial true) should still trigger, and this should
#     fail over immediately rather than queue and wait out the full
#     queue timeout;
#
#   - once resolved, if that one peer then fails enough to hit
#     max_fails, a *subsequent* request should see the same fail-fast
#     behaviour - the list is non-empty now, but its only entry is
#     recently-failed, which the loop already treats the same as "down"
#     for a static server.
#
# Neither of these is expected to behave any differently from a static
# server - the loop only reads the live list under lock, it does not
# care whether entries arrived from static config or from a resolver -
# but that is exactly the kind of assumption worth confirming rather
# than leaving untested.

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

my $backend_port = port(8090);
my $dns_port = port(8982, udp => 1);
my $control_port = port(8083);

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

    upstream detect_backend {
        zone detect_backend_zone 1m;
        server example.net:$backend_port resolve max_fails=1 fail_timeout=1h;
        queue 5 timeout=2s;
        queue_detect_all_peer_down on;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /detect/ {
            proxy_pass http://detect_backend/;
            proxy_connect_timeout 1s;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $control_port, $dns_port);
$t->run_daemon(\&fail_backend, $backend_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(3);

###############################################################################
# 1: detect=on, resolve server not yet resolved (zero peers) - fails
# over immediately, does not queue and wait out the timeout.
###############################################################################

select(undef, undef, undef, 0.4);

{
	my $start = time();
	my $s = send_request('/detect/A');
	my $resp = read_response($s, 3);
	my $elapsed = time() - $start;

	like($resp, qr!^HTTP/1\.[01] 502 !,
		'detect=on + resolve server not yet resolved: fails over');
	ok($elapsed < 0.5,
		'detect=on + resolve server not yet resolved: fails over '
		. 'immediately, not after queuing')
		or diag("elapsed: $elapsed");
}

###############################################################################
# 2: resolve to the one real backend, drive it to max_fails=1 with a
# request that gets no response, then confirm a *subsequent* request
# fails over immediately too - the only resolved peer is now
# recently-failed, same as a statically-down server would be.
###############################################################################

update_dns($control_port, "127.0.0.1");
select(undef, undef, undef, 2.0);

{
	my $s = send_request('/detect/prime');
	read_response($s, 2);
}
select(undef, undef, undef, 0.3);

{
	my $start = time();
	my $s = send_request('/detect/B');
	my $resp = read_response($s, 3);
	my $elapsed = time() - $start;

	diag("resp=" . (($resp =~ m!^(HTTP\S* \d+ [^\r\n]*)!) ? $1 : '(none)')
		. " elapsed=$elapsed");

	ok($resp =~ m!^HTTP/1\.[01] 502 ! && $elapsed < 0.5,
		'detect=on + the only resolved peer now recently-failed: '
		. 'fails over immediately, same as it would for a static peer')
		or diag("elapsed: $elapsed");
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

sub update_dns {
	my ($control_port, $addr) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => "127.0.0.1:$control_port",
	) or die "Can't connect to dns control socket: $!\n";

	$s->autoflush(1);
	$s->syswrite("$addr\n");

	local $/ = "\n";
	my $reply = $s->getline();
	$s->close();

	return $reply;
}

sub fail_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	# Accepts and immediately closes without responding - an upstream
	# failure, driving fails towards max_fails for whichever request
	# is unlucky enough to be routed here.
	while (my $client = $server->accept()) {
		$client->close();
	}
}

# Minimal mock DNS server for the "example.net" hostname - see
# t/queue_resolve_gap.t for the identical, more thoroughly commented
# version this was copied from.

sub dns_daemon {
	my ($t, $control_port, $dns_port) = @_;
	my $addr = '';

	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => $dns_port,
		Proto => 'udp',
	) or die "Can't create DNS listening socket: $!\n";

	my $control = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => "127.0.0.1:$control_port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create dns control socket: $!\n";

	my $sel = IO::Select->new($socket, $control);
	local $SIG{PIPE} = 'IGNORE';

	open my $fh, '>', $t->testdir() . '/dns_ready';
	close $fh;

	while (my @ready = $sel->can_read) {
		for my $fh (@ready) {
			if ($fh == $control) {
				my $new = $fh->accept;
				$new->autoflush(1);
				$sel->add($new);

			} elsif ($fh == $socket) {
				my $data;
				$fh->recv($data, 65536);
				$fh->send(dns_reply($data, $addr));

			} else {
				my $line = $fh->getline();
				if (defined $line) {
					chomp $line;
					$addr = $line;
					$fh->syswrite("OK\n");
				}
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub dns_reply {
	my ($recv_data, $addr) = @_;

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

	if ($name eq 'example.net' && $type == A && length($addr)) {
		push @rdata, rd_addr($ttl, $addr);
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;
	pack 'n3N nC4', 0xc00c, A, IN, $ttl, 4, split(/\./, $addr);
}

###############################################################################
