#!/usr/bin/perl

# Tests for ngx_http_upstream_queue_module: a queued request with each of
# the stock load balancing methods.
#
# While a request waits, the retry timer probes the balancer with a peer
# connection of its own.  That used to be a zeroed one, but Angie's
# ip_hash, hash and least_time take the request from pc->ctx in their
# peer.get (and its round-robin does on free): the worker crashed on the
# first retry tick.  The probe is now a copy of the request's own peer
# connection.  nginx's balancers never look at pc->ctx, so there this only
# makes sure every method gets a queued request served; under Angie it
# is the regression test.
#
# Layout per method: one peer, max_conns=1, the first request (H) held 1s;
# R waits in the queue, probed on every tick meanwhile, and must be served
# once H is done.

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

my @methods = (
	[ rr => '' ],
	[ least_conn => 'least_conn;' ],
	[ ip_hash => 'ip_hash;' ],
	[ hash => 'hash $request_uri;' ],
	[ random => 'random;' ],
);

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(scalar @methods);

# 127.0.0.1:8NNN in nginx.conf is remapped by write_file_expand() itself,
# so the servers are written with their raw numbers below.

my ($upstreams, $locations) = ('', '');
my $n = 8081;

for my $m (@methods) {
	my ($name, $directive) = @$m;
	$upstreams .= <<"EOF";
    upstream $name {
        $directive
        server 127.0.0.1:$n max_conns=1;
        queue 5 timeout=4s;
    }

EOF
	$locations .= <<"EOF";
        location /$name/ {
            proxy_pass http://$name;
        }

EOF
	$n++;
}

$t->write_file_expand('nginx.conf', <<"EOF");

%%TEST_GLOBALS%%

load_module $module;

daemon off;
worker_processes 1;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

$upstreams
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

$locations    }
}

EOF

for my $i (0 .. $#methods) {
	my $port = port(8081 + $i);
	$t->run_daemon(\&first_held_backend, $port);
	$t->waitforsocket("127.0.0.1:$port") or die "backend did not start\n";
}

$t->run();

###############################################################################

for my $m (@methods) {
	my ($name) = @$m;

	my $h = send_request("/$name/H");
	select(undef, undef, undef, 0.2);

	like(read_response(send_request("/$name/R"), 6), qr!^HTTP/1\.[01] 200 !,
		"$name: queued request served");

	read_response($h, 3);
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

# Holds the first request for 1s, answers everything with 200.

sub first_held_backend {
	my ($port) = @_;

	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalAddr => "127.0.0.1:$port",
		Listen => 5,
		Reuse => 1,
	) or die "Can't create backend listening socket: $!\n";

	local $SIG{CHLD} = 'IGNORE';
	my $first = 1;

	while (my $client = $server->accept()) {

		# waitforsocket()'s probe sends nothing and just closes.

		next unless $client->sysread(my $buf, 65536);

		my $delay = $first ? 1 : 0;
		$first = 0;

		next if fork();

		select(undef, undef, undef, $delay);
		$client->syswrite("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
		exit 0;
	}
}

###############################################################################
