#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# "sticky learn ... header" installs a u->peer.notify hook, which nginx
# calls with u->peer.data once the response header arrives.  The queue
# module replaces u->peer.data with its own data but did not wrap notify,
# so with sticky declared before queue, sticky's notify got the queue's
# data instead of its own and the worker crashed on the very first
# response.  notify is now passed through like get/free/set_session.
#
# Layout: two servers, each answering with its own name and a session
# cookie naming it; sticky learns the cookie from the response header.
#   - a plain request must be served, and a follow-up carrying the cookie
#     must go to the same server;
#   - in a second upstream (one server, max_conns=1), a request that
#     waited in the queue must be served and learned as well - its
#     balancer data was re-created on the way out of the queue.

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

my $t = Test::Nginx->new()->has(qw/http proxy upstream_zone/);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my $a_port = port(8081);
my $b_port = port(8082);
my $c_port = port(8083);

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    upstream two {
        zone two 64k;
        server 127.0.0.1:8081;
        server 127.0.0.1:8082;
        sticky learn create=\$upstream_cookie_sid lookup=\$cookie_sid
                     zone=two_sessions:1m header;
        queue 5 timeout=2s;
    }

    upstream one {
        zone one 64k;
        server 127.0.0.1:8083 max_conns=1;
        sticky learn create=\$upstream_cookie_sid lookup=\$cookie_sid
                     zone=one_sessions:1m header;
        queue 5 timeout=4s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /two/ {
            proxy_pass http://two;
        }

        location /one/ {
            proxy_pass http://one;
        }
    }
}

EOF

$t->run_daemon(\&named_backend, $a_port, 'a');
$t->run_daemon(\&named_backend, $b_port, 'b');
$t->run_daemon(\&named_backend, $c_port, 'c');
$t->waitforsocket('127.0.0.1:' . $_) or die "backend did not start\n"
	for ($a_port, $b_port, $c_port);

$t->try_run('no sticky')->plan(5);

###############################################################################

my $first = read_response(send_request('/two/first'), 5);

like($first, qr!^HTTP/1\.[01] 200 .*^Set-Cookie: sid=([ab])\r$!ms,
	'sticky learn + queue: served');

my ($sid) = $first =~ /^Set-Cookie: sid=([ab])\r$/m;
$sid //= 'none';

my $same = 0;
for (1 .. 4) {
	my $resp = read_response(send_request('/two/again', "sid=$sid"), 5);
	$same++ if $resp =~ /\r\n\r\nserver $sid$/;
}

is($same, 4, 'requests with the learned cookie stick to its server');

# Queued: the holder takes the only slot for 1s.

my $holder = send_request('/one/holder');
select(undef, undef, undef, 0.2);

my $queued = read_response(send_request('/one/R'), 6);

like($queued, qr!^HTTP/1\.[01] 200 .*^Set-Cookie: sid=c\r$!ms,
	'sticky learn + queue: request that waited in the queue served');
like(read_response($holder, 3), qr!^HTTP/1\.[01] 200 !, 'holder served');
like(read_response(send_request('/one/again', 'sid=c'), 5),
	qr!\r\n\r\nserver c$!, 'learned session still routes');

###############################################################################

sub send_request {
	my ($uri, $cookie) = @_;
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	my $cookie_header = defined $cookie ? "Cookie: $cookie\r\n" : '';

	$s->autoflush(1);
	$s->syswrite(<<EOF);
GET $uri HTTP/1.1\r
Host: localhost\r
${cookie_header}Connection: close\r
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

# Answers with its own name and a cookie naming it; a holder only after 1s.

sub named_backend {
	my ($port, $name) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';

	while (my $client = $server->accept()) {
		next if fork();

		# waitforsocket()'s probe sends nothing and just closes.

		exit 0 unless $client->sysread(my $buf, 65536);

		select(undef, undef, undef, 1) if $buf =~ m!^GET /\w+/holder !;

		my $body = "server $name";
		$client->syswrite("HTTP/1.0 200 OK\r\n"
			. "Set-Cookie: sid=$name\r\n"
			. "Content-Length: " . length($body) . "\r\n\r\n$body");
		exit 0;
	}
}

###############################################################################
