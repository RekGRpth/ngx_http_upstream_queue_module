#!/usr/bin/perl

# Config parsing tests for the "queue" directive of
# ngx_http_upstream_queue_module (ngx_http_upstream_queue_ups_conf()).
#
# Unlike the other .t files here, none of these need a running nginx, so
# this doesn't go through Test::Nginx->run() (or even instantiate a
# Test::Nginx object - its DESTROY unconditionally appends "no alerts" /
# "no sanitizer errors" checks meant for a stopped server, which fight
# with the plan when nothing ever ran). Each case is just "nginx -t"
# against a small config fragment, invoked directly.

###############################################################################

use warnings;
use strict;

use Test::More;
use File::Temp qw/ tempdir /;

BEGIN {
	use FindBin;
	chdir($FindBin::Bin);
}

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $nginx = $ENV{TEST_NGINX_BINARY} || '../../nginx/objs/nginx';
my $module = "$FindBin::Bin/../../nginx/objs/ngx_http_upstream_queue_module.so";

if (!-x $nginx || !-e $module) {
	plan(skip_all => "nginx binary or $module not built");
}

my $testdir = tempdir('nginx-queue-directive-XXXXXXXXXX', TMPDIR => 1,
	CLEANUP => 1);

plan(tests => 9);

is(conf_test("queue 10;"), 0, 'queue N: valid, minimal form');
is(conf_test("queue 10 timeout=30s;"), 0, 'queue N timeout=T: valid form');

isnt(conf_test("queue 0;"), 0, 'queue 0: rejected');
isnt(conf_test("queue abc;"), 0, 'queue <non-numeric>: rejected');
isnt(conf_test("queue -5;"), 0, 'queue <negative>: rejected');
isnt(conf_test("queue 10 timeout=;"), 0, 'queue N timeout=<empty>: rejected');
isnt(conf_test("queue 10 timeout=abc;"), 0,
	'queue N timeout=<not a time>: rejected');
isnt(conf_test("queue 10 badparam=5s;"), 0,
	'queue N <unknown param>=...: rejected');
isnt(conf_test("queue 10; queue 20;"), 0, 'queue given twice: rejected');

###############################################################################

# Runs "nginx -t" against an upstream block containing $queue_line and
# returns nginx's exit status (0 == config accepted).

sub conf_test {
	my ($queue_line) = @_;

	open F, '>', "$testdir/nginx.conf" or die "Can't write nginx.conf: $!";
	print F <<EOF;
pid $testdir/nginx.pid;
error_log $testdir/error.log;

load_module $module;

events {
}

http {
    client_body_temp_path $testdir/client_body_temp;
    proxy_temp_path $testdir/proxy_temp;

    upstream backend {
        server 127.0.0.1:1;
        $queue_line
    }

    server {
        listen 127.0.0.1:8080;
        location / {
            proxy_pass http://backend;
        }
    }
}
EOF
	close F;

	system("$nginx -t -p $testdir/ -c nginx.conf "
		. ">$testdir/conftest.log 2>&1");

	return $? >> 8;
}

###############################################################################
