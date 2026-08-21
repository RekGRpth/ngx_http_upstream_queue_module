#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# A single request can register ngx_http_upstream_queue_cleanup_handler
# more than once: every time ngx_http_upstream_queue_peer_get() lands in
# its "still busy, queue it" branch it calls ngx_pool_cleanup_add()
# unconditionally, and a request can pass through that branch several
# times over its life - queued once, popped and reconnected by
# peer_free()'s drain when some other connection frees up, found still
# busy right there, and queued again. This is entirely normal, expected
# behaviour, not a misuse of the module.
#
# The bug: ngx_http_upstream_queue_cleanup_handler() removed the node
# with ngx_queue_remove() but never reset it with ngx_queue_init()
# afterwards, unlike ngx_http_upstream_queue_drain() which already does
# both after its own ngx_queue_remove(). The first cleanup invocation
# for a given d removed it correctly but left next/prev dangling
# instead of self-referential; a second invocation for the same d (from
# the second, redundant ngx_pool_cleanup_t registered above) then read
# ngx_queue_empty() as false against those stale pointers and attempted
# a second, invalid removal through them - a crash confirmed via core
# dump: two separate cleanup entries in the same request pool pointing
# at the same d, and d->queue as {NULL, NULL} at the point of the
# second, invalid ngx_queue_remove().
#
# Forcing a request through the "queued, popped by drain, still busy,
# queued again" cycle needs the popped slot to look free (so drain()
# tries it) while nothing is actually available yet. Two peers with
# max_fails=1 do this without any real timing race: request A queues
# behind both fully-occupied peers; peer 1 then fails (its backend
# closes without answering), which frees its slot but also marks it
# recently-failed for fail_timeout - so peer_free()'s drain pops A,
# tries to reconnect it, and finds NGX_BUSY again (peer 1 skipped as
# recently-failed, peer 2 still fully occupied by the other holder),
# re-queuing it. A's own queue timeout then fires and finalizes it,
# running every cleanup handler ever registered for its d.
#
# What is asserted: that this scenario is reachable at all (the debug
# log must show some connection's cleanup handler running more than
# once - otherwise this test would not be exercising the fix), that the
# request still gets a clean, well-formed final response, and - via
# Test::Nginx's built-in check - that nothing crashes.

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw/ SOCK_STREAM /;
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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(2);

my $sock1 = $t->testdir() . '/b1.sock';
my $sock2 = $t->testdir() . '/b2.sock';

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
        server unix:$sock1 max_conns=1 max_fails=1 fail_timeout=30s;
        server unix:$sock2 max_conns=1 max_fails=1 fail_timeout=30s;
        queue 5 timeout=3s;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_connect_timeout 5s;
            proxy_read_timeout 5s;
        }
    }
}

EOF

$t->run_daemon(\&fail_backend, $sock1);
$t->run_daemon(\&hold_backend, $sock2);
$t->waitforfile($sock1) or die "backend1 did not start\n";
$t->waitforfile($sock2) or die "backend2 did not start\n";

$t->run();

###############################################################################

# holder1 takes peer 1's only slot; holder2 takes peer 2's only slot -
# the upstream is now fully occupied.

my $h1 = send_request();
select(undef, undef, undef, 0.2);
my $h2 = send_request();
select(undef, undef, undef, 0.2);

# A queues behind both.

my $start = time();
my $a = send_request();
select(undef, undef, undef, 0.4);

# fail_backend (peer 1) closes without responding at around this point
# (see its own timing below) - freeing peer 1's slot but also marking
# it recently-failed. That should make peer_free()'s drain pop A, find
# it still busy (peer 1 skipped as recently-failed, peer 2 still held
# by holder2), and queue it again.

my $resp = '';
my $deadline = time() + 6;
while (time() < $deadline) {
	my $sel = IO::Select->new($a);
	last unless $sel->can_read($deadline - time());
	my $n = sysread($a, my $chunk, 65536);
	last if !$n;
	$resp .= $chunk;
}

like($resp, qr!^HTTP/1\.[01] (502|504) !,
	'request that got queued, drained, and found busy again still '
	. 'gets a clean final response');

my $log = $t->read_file('error.log');
my %cleanups_per_connection;
while ($log =~ /^\S+ \S+ \[debug\] \d+#\d+: \*(\d+) .*ngx_http_upstream_queue_cleanup_handler: ngx_http_upstream_queue_cleanup_handler/mg) {
	$cleanups_per_connection{$1}++;
}
my $max_cleanups = 0;
for (values %cleanups_per_connection) {
	$max_cleanups = $_ if $_ > $max_cleanups;
}

ok($max_cleanups >= 2,
	'sanity: some connection\'s cleanup handler actually ran more than '
	. 'once - otherwise this test is not exercising the fix')
	or diag("cleanup handler invocations per connection: "
		. join(', ', map { "*$_=$cleanups_per_connection{$_}" }
			sort keys %cleanups_per_connection));

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

sub fail_backend {
	my ($path) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept unix connection: $!\n";

	# Hold long enough that A is safely queued behind both occupied
	# slots before this closes without responding - an upstream-side
	# failure that frees this peer's slot while simultaneously marking
	# it recently-failed (max_fails=1), which is what should make
	# peer_free()'s drain pop A only to find nothing really available.
	select(undef, undef, undef, 1.2);
	$client->close();

	exit 0;
}

sub hold_backend {
	my ($path) = @_;

	unlink $path;

	my $server = IO::Socket::UNIX->new(
		Type => SOCK_STREAM,
		Local => $path,
		Listen => 5,
	) or die "Can't create unix listening socket: $!\n";

	my $client = $server->accept()
		or die "Can't accept unix connection: $!\n";

	# Holds peer 2's only slot for the whole test; never answers.
	select(undef, undef, undef, 15);
	exit 0;
}

###############################################################################
