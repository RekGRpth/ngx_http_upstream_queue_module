#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# keepalive wraps the balancer from the outside: per request, its peer data
# and get/free sit in u->peer around the queue's.  (Since nginx 1.29.7
# keepalive is set up after all directives and is on by default, so it is
# always outside; elsewhere it is when declared after "queue".)  Before a
# queued request is retried, refresh_peer() re-runs the inner peer.init,
# and it used to install the queue's own hooks in u->peer afterwards -
# dropping keepalive's.  A request that had waited in the queue then
# neither took a cached connection nor gave its own back: every queued
# request cost the upstream a fresh connection.
#
# Layout: one server, max_conns=1, keepalive on; the backend serves any
# number of requests per connection and logs each one with the id of the
# connection it came on, and when nginx closes the connection.
#   - H takes the only slot for 1s; R waits in the queue;
#   - when H is done, keepalive caches H's connection before the queue
#     drains, so R must get that same connection;
#   - after R is done, the connection must stay open (cached again).

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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_keepalive/)->plan(3);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the server is written with its raw number below.

my $port = port(8081);

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
        queue 5 timeout=5s;
        keepalive 8;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
        }
    }
}

EOF

my $log = $t->testdir() . '/backend.log';

$t->run_daemon(\&keepalive_backend, $port, $log);
$t->waitforsocket('127.0.0.1:' . $port) or die "backend did not start\n";

$t->run();

###############################################################################

my $h = send_request('/H');
select(undef, undef, undef, 0.2);

like(read_response(send_request('/R'), 6), qr!^HTTP/1\.[01] 200 !,
	'queued request served');
read_response($h, 3);

select(undef, undef, undef, 0.5);

my %conn = map { (split ' ')[1] => (split ' ')[0] } grep { / \/\w+$/ }
	split /\n/, $t->read_file('backend.log');
my %closed = map { (split ' ')[0] => 1 } grep { / eof$/ }
	split /\n/, $t->read_file('backend.log');

is($conn{'/R'} // 'none', $conn{'/H'} // 'none',
	'queued request reuses the connection keepalive cached')
	or diag($t->read_file('backend.log'));
ok(defined $conn{'/R'} && !$closed{$conn{'/R'}},
	'and leaves it cached afterwards') or diag($t->read_file('backend.log'));

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

# HTTP/1.1 backend, one process per connection, any number of requests on
# each.  Logs "<connection id> <uri>" per request and "<connection id> eof"
# when nginx closes the connection; /H is answered after 1s.

sub keepalive_backend {
	my ($port, $log) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		next if fork();

		open my $fh, '>>', $log or die "Can't open $log: $!\n";
		$fh->autoflush(1);

		my $buf = '';

		while (1) {
			while ($buf !~ /\r\n\r\n/) {
				my $n = $client->sysread($buf, 65536, length $buf);

				if (!$n) {
					# waitforsocket()'s probe never sends a request.
					print $fh "$$ eof\n" if $buf ne '' || -s $log;
					exit 0;
				}
			}

			$buf =~ s/^GET (\S+)[^\r]*\r\n.*?\r\n\r\n//s;
			my $uri = $1;

			print $fh "$$ $uri\n";
			select(undef, undef, undef, 1) if $uri eq '/H';

			$client->syswrite("HTTP/1.1 200 OK\r\n"
				. "Content-Length: 2\r\n\r\nok");
		}
	}
}

###############################################################################
