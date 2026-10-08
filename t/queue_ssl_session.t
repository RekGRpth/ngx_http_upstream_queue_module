#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module: SSL session reuse for queued
# requests.
#
# The module wraps the balancer's set_session/save_session, passing them
# on to the balancer's own peer data - which it re-creates with peer.init
# before every retry of a queued request (see queue_backup.t).  A request
# that waited in the queue must still resume the SSL session saved for
# its peer.
#
# For a plain upstream, one with a zone (sessions kept in shared memory)
# and one with a `resolve` server:
#   - "warm" does a full handshake and saves the session;
#   - a holder takes the only slot (max_conns=1) for 1s;
#   - R waits in the queue, then connects once the holder is done.
# Expected: R was queued (the upstream name shows up in $upstream_addr)
# and its handshake resumed the session ($ssl_session_reused on the TLS
# side is "r").  Upstream keepalive is kept out of the way, or R would just
# reuse a cached connection and not handshake at all.

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

my $t = Test::Nginx->new()->has(qw/http proxy http_ssl upstream_zone/)
	->has_daemon('openssl');

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the static servers are written with their raw numbers below; the
# `resolve` one gets the remapped port of the same TLS listener.

my $tls_port = port(8081);
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

    upstream plain {
        server 127.0.0.1:8081 max_conns=1;
        queue 5 timeout=5s;
    }

    upstream zoned {
        zone zoned 64k;
        server 127.0.0.1:8081 max_conns=1;
        queue 5 timeout=5s;
    }

    upstream resolved {
        zone resolved 64k;
        server example.net:$tls_port resolve max_conns=1;
        queue 5 timeout=5s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        add_header X-Upstream-Addr \$upstream_addr always;
        proxy_ssl_session_reuse on;

        # no upstream keepalive (on by default since nginx 1.29.7): every
        # request must open a connection of its own, so that its handshake
        # shows whether the session was resumed
        proxy_set_header Connection close;
        proxy_read_timeout 5s;

        location /plain/ {
            proxy_pass https://plain;
        }

        location /zoned/ {
            proxy_pass https://zoned;
        }

        location /resolved/ {
            proxy_pass https://resolved;
        }
    }

    server {
        listen       127.0.0.1:8081 ssl;
        server_name  localhost;

        ssl_certificate localhost.crt;
        ssl_certificate_key localhost.key;
        ssl_session_cache shared:SSL:1m;

        location / {
            proxy_pass http://127.0.0.1:8090;
            add_header X-Reused \$ssl_session_reused;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

system('openssl req -x509 -new '
	. "-config $d/openssl.conf -subj /CN=localhost/ "
	. "-out $d/localhost.crt -keyout $d/localhost.key "
	. ">>$d/openssl.out 2>&1") == 0
	or die "Can't create certificate for localhost: $!\n";

$t->run_daemon(\&dns_daemon, $t, $dns_port);
$t->run_daemon(\&app_backend, port(8090));
$t->waitforfile("$d/dns_ready") or die "dns daemon did not start\n";
$t->waitforsocket('127.0.0.1:' . port(8090))
	or die "backend did not start\n";

$t->try_run('no resolve/zone support')->plan(9);

# Give the resolver time to answer for example.net.

select(undef, undef, undef, 1.5);

###############################################################################

for my $upstream (qw/ plain zoned resolved /) {
	read_response(send_request("/$upstream/warm"), 5);

	my $holder = send_request("/$upstream/holder");
	select(undef, undef, undef, 0.2);

	my $resp = read_response(send_request("/$upstream/R"), 6);

	like($resp, qr!^HTTP/1\.[01] 200 !, "$upstream: R served")
		or diag(summary($resp));
	like($resp, qr!^X-Upstream-Addr: $upstream, !mi,
		"$upstream: R waited in the queue") or diag(summary($resp));
	like($resp, qr!^X-Reused: r\r$!mi,
		"$upstream: R resumed the SSL session") or diag(summary($resp));

	read_response($holder, 3);
}

###############################################################################

sub summary {
	my ($resp) = @_;
	my ($status) = $resp =~ /^([^\r\n]*)/;
	my ($addr) = $resp =~ /^X-Upstream-Addr: ([^\r\n]*)/mi;
	my ($reused) = $resp =~ /^X-Reused: ([^\r\n]*)/mi;
	return ($status // '(no response)') . ', X-Upstream-Addr: '
		. ($addr // '(none)') . ', X-Reused: ' . ($reused // '(none)');
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

# Answers every request with 200, the holders' only after 1s.

sub app_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	while (my $client = $server->accept()) {
		next unless $client->sysread(my $buf, 65536);

		select(undef, undef, undef, 1) if $buf =~ m!^GET /\w+/holder !;

		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		$client->close();
	}
}

# Minimal mock DNS server: example.net resolves to 127.0.0.1 - see
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
		$socket->send(dns_reply($data));
	}
}

sub dns_reply {
	my ($recv_data) = @_;

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
		push @rdata, pack('n3N nC4', 0xc00c, A, IN, $ttl, 4, 127, 0, 0, 1);
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

###############################################################################
