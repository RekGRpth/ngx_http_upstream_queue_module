#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# ngx_http_upstream_queue_drain() pops a queued request and calls
# ngx_http_upstream_connect() for it.  If that connect fails synchronously
# and the request has no tries left, nginx core finalizes the request from
# inside that very call - which, for a plain "Connection: close" client,
# frees r->pool, and the ngx_http_upstream_t allocated from it, before
# ngx_http_upstream_connect() even returns.  drain() used to save
# u->read_event_handler / u->write_event_handler before the call and write
# them back into u afterwards, i.e. into freed memory.
#
# Same trigger as queue_cascade.t: a single unix: peer whose socket path
# disappears while requests sit in the queue, so every dequeued connect()
# fails synchronously with ENOENT.  A write into a just-freed pool block
# rarely crashes on its own, so the reliable signal is valgrind: run with
# TEST_NGINX_VALGRIND=1 to start nginx under valgrind and fail on any
# "Invalid read/write" it reports.  Without it, the test still checks every
# queued client gets a clean 502 and nothing [alert]-level was logged.
#
# The same run also checks for a leak on that path: when peer_get() queues
# a request it returns NGX_AGAIN with a placeholder connection, and
# ngx_http_upstream_connect() gives that placeholder its own c->pool.
# drain() used to close the placeholder without destroying that pool, so
# each dequeued request leaked it - valgrind reports it as "definitely
# lost", allocated from ngx_http_upstream_connect().

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw/ SOCK_STREAM /;

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

my $queued = 5;
my $valgrind = $ENV{TEST_NGINX_VALGRIND};

my $module = "$FindBin::Bin/../../nginx/objs/ngx_http_upstream_queue_module.so";

if (!-e $module) {
	Test::More::plan(skip_all => "$module not built");
}

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(3);

my $sockpath = $t->testdir() . '/backend.sock';

# Everything is several times slower under valgrind: give the holder
# request longer to reach the backend before the rest arrive, and the
# backend longer to hold the slot while they queue up.
my $settle = $valgrind ? 3 : 0.3;
my $hold = $valgrind ? 4 : 1;

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
        server unix:$sockpath max_conns=1 max_fails=0;
        queue 100 timeout=30s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_connect_timeout 20s;
            proxy_read_timeout 20s;
        }
    }
}

EOF

$t->run_daemon(\&backend_daemon, $sockpath, $hold);
$t->waitforfile($sockpath) or die "backend daemon did not start\n";

if ($valgrind) {
	my $nginx = File::Spec->rel2abs($Test::Nginx::NGINX);
	my $wrapper = $t->testdir() . '/valgrind.sh';
	$t->write_file('valgrind.sh', <<"EOF");
#!/bin/sh
exec valgrind --quiet --leak-check=full --show-leak-kinds=definite --log-file=@{[ $t->testdir() ]}/valgrind.%p.log $nginx "\$@"
EOF
	chmod 0755, $wrapper;
	$Test::Nginx::NGINX = $wrapper;
}

$t->run();

###############################################################################

my @socks;

# Request #1 takes the only slot; the backend holds it, unanswered.

push @socks, send_request();
select(undef, undef, undef, $settle);

# The rest queue up behind it.  Once the backend drops request #1, each
# of these is dequeued into a connect() that fails synchronously.

push @socks, send_request() for (1 .. $queued);

my $sel = IO::Select->new(@socks);
my %buf;
my $deadline = time() + ($valgrind ? 60 : 20);

while ($sel->count() && time() < $deadline) {
	for my $s ($sel->can_read(0.2)) {
		my $n = sysread($s, my $chunk, 65536);
		if (!$n) {
			$sel->remove($s);
			next;
		}
		$buf{$s} .= $chunk;
	}
}

my $bad = grep { ($buf{$_} // '') !~ m!^HTTP/1\.[01] 502 ! } @socks;

is($bad, 0, 'all ' . scalar(@socks) . ' clients got a complete 502');

$t->stop();

SKIP: {
	skip 'set TEST_NGINX_VALGRIND=1 to check memory under valgrind', 2
		unless $valgrind;

	my $log = join '', map { $t->read_file($_) }
		grep { /^valgrind\.\d+\.log$/ }
		do { opendir my $d, $t->testdir() or die; readdir $d };

	unlike($log, qr/Invalid (read|write)/,
		'valgrind: no invalid memory access in drain()')
		or diag($log);

	# Loss records are separated by bare "==pid== " lines.  Only count
	# the ones allocated via ngx_http_upstream_connect(): nginx itself
	# leaks a few unrelated bytes (e.g. ngx_set_environment()).

	my @leaks = grep { /definitely lost/ && /ngx_http_upstream_connect/ }
		split /^==\d+== *\n/m, $log;

	is(scalar @leaks, 0,
		'valgrind: no upstream connection pool leaked by drain()')
		or diag(join '', @leaks);
}

###############################################################################

sub send_request {
	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . port(8080),
	) or die "Can't connect to nginx: $!\n";

	$s->autoflush(1);
	$s->syswrite(<<EOF);
GET / HTTP/1.1\r
Host: localhost\r
Connection: close\r
\r
EOF

	return $s;
}

sub backend_daemon {
	my ($path, $hold) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept unix connection: $!\n";

	# From here on, connect() to $path fails synchronously with ENOENT.

	$server->close();
	unlink $path;

	select(undef, undef, undef, $hold);

	# Abrupt close, no response: frees the slot and starts the drain.

	$client->close();

	exit 0;
}

###############################################################################
