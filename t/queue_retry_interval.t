#!/usr/bin/perl

# Regression test for ngx_http_upstream_queue_module.
#
# The "queue" directive's optional retry_interval=T parameter controls
# how often the backstop timer (ngx_http_upstream_queue_retry_schedule())
# re-checks a queued request when nothing else has woken it - see
# t/queue_resolve_gap.t and t/queue_drain_refresh.t for what that timer
# is for. This confirms the parameter actually changes that cadence,
# not just that config parsing accepts it (t/queue_directive.t already
# covers parsing).
#
# error.log timestamps only have one-second resolution, too coarse to
# tell a 200ms default apart from a custom interval directly. Instead,
# this counts how many times ngx_http_upstream_queue_retry_handler's
# own debug log line ("queue retry") appears within a fixed wait
# window: with retry_interval=700ms, a ~2.1s window should show around
# 3 ticks; the 200ms default would show around 10 in the same window.
# A permanently-down single peer (matching the existing detect_off_backend
# setup in t/queue_basic.t) queues a request that never gets served,
# so the timer keeps ticking for the whole window without anything
# else interfering.

###############################################################################

use warnings;
use strict;

use Test::More;
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

my $t = Test::Nginx->new()->has(qw/http proxy/)->plan(1);

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
        server 127.0.0.1:1 down;
        queue 5 timeout=5s retry_interval=700ms;
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            proxy_pass http://backend;
            proxy_connect_timeout 5s;
        }
    }
}

EOF

$t->run();

###############################################################################

my $s = send_request();
select(undef, undef, undef, 2.1);

my $log = $t->read_file('error.log');
my $ticks = () = ($log =~ /ngx_http_upstream_queue_retry_handler: queue retry/g);

diag("retry_interval=700ms: $ticks ticks in ~2.1s "
	. "(expect ~3; the 200ms default would show ~10)");

ok($ticks >= 2 && $ticks <= 4,
	'retry_interval=700ms produces roughly 3 timer ticks in ~2.1s, not '
	. 'the ~10 the 200ms default would - the parameter is actually '
	. 'taking effect, not just being parsed');

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

###############################################################################
