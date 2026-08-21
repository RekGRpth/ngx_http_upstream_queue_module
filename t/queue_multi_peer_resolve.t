#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# Every other `resolve`-related test in this suite (queue_resolve_gap.t,
# queue_cleanup_reentry.t, queue_drain_refresh.t) uses a resolve server
# that has at most one currently-resolved address at a time, which
# keeps ngx_http_upstream_rr_peers_t->single true and exercises
# ngx_http_upstream_get_round_robin_peer()'s single-peer branch. Once a
# `resolve` server resolves to *more than one* address at the same
# time, the zone module flips ->single to false and peer selection
# goes through the general, weighted-round-robin branch
# (ngx_http_upstream_get_peer()) instead - a different code path this
# module's retry timer, drain(), and ngx_http_upstream_queue_refresh_peer()
# have not specifically been exercised against.
#
# This queues a request while the resolve server has zero addresses,
# then has DNS answer with two addresses at once, and confirms the
# queued request still gets served promptly - not left waiting out the
# full queue timeout - now that peer selection is happening through the
# multi-peer path rather than the single-peer one.

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

    upstream resolve_backend {
        zone resolve_backend_zone 1m;
        server example.net:$backend_port resolve max_fails=0;
        queue 5 timeout=6s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /resolve/ {
            proxy_pass http://resolve_backend/;
            proxy_connect_timeout 2s;
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t, $control_port, $dns_port);
$t->run_daemon(\&backend_daemon, $backend_port);
$t->waitforfile($t->testdir() . '/dns_ready')
	or die "dns daemon did not start\n";

$t->try_run('no resolve/zone support')->plan(1);

###############################################################################

select(undef, undef, undef, 0.4);

my $start = time();
my $a = send_request('/resolve/A');

select(undef, undef, undef, 0.3);

# Resolve to TWO addresses at once (both loopback, same backend port -
# both genuinely reachable). This is what flips peers->single to 0 and
# routes selection through the multi-peer branch instead of the
# single-peer one.

update_dns($control_port, "127.0.0.1 127.0.0.2");

my $resp = read_response($a, 6);
my $elapsed = time() - $start;

diag("A: elapsed=${elapsed}s response=" .
	(($resp =~ m!^(HTTP\S* \d+ [^\r\n]*)!) ? $1 : '(no response)'));

ok($resp =~ m!^HTTP/1\.[01] 200 ! && $elapsed < 3,
	'queued request is served promptly once resolve adds two addresses '
	. 'at once (multi-peer round-robin path), not left waiting for '
	. 'the full queue timeout');

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

sub backend_daemon {
	my ($port) = @_;

	# Bound to 0.0.0.0, not just 127.0.0.1: both resolved addresses
	# (127.0.0.1 and 127.0.0.2) are loopback and land on this same
	# listener either way.
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "0.0.0.0:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {
		my $buf = '';
		while ($buf !~ /\r\n\r\n/) {
			my $n = $client->sysread(my $chunk, 1024);
			last unless $n;
			$buf .= $chunk;
		}

		$client->syswrite("HTTP/1.1 200 OK\r\n"
			. "Content-Length: 2\r\n"
			. "Connection: close\r\n\r\nOK");
		$client->close();
	}
}

# Minimal mock DNS server for the "example.net" hostname, extended
# (relative to t/queue_resolve_gap.t, where this was copied from) to
# answer with more than one A record at once.

sub dns_daemon {
	my ($t, $control_port, $dns_port) = @_;
	my @addrs = ();

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
				$fh->send(dns_reply($data, \@addrs));

			} else {
				my $line = $fh->getline();
				if (defined $line) {
					chomp $line;
					@addrs = split(/\s+/, $line);
					$fh->syswrite("OK\n");
				}
				$sel->remove($fh);
				$fh->close;
			}
		}
	}
}

sub dns_reply {
	my ($recv_data, $addrs) = @_;

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

	if ($name eq 'example.net' && $type == A) {
		map { push @rdata, rd_addr($ttl, $_) } @$addrs;
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
