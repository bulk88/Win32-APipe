# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Win32-APipe.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 13;
use constant ERROR_FILE_NOT_FOUND => 2;
use constant ERROR_SUCCESS => 0;
BEGIN { use_ok('Win32::APipe', ':all') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $pid;
my $opaque = 'nonexistant.exe';
my $err = run($opaque, $opaque, 0, $pid);
is($err, ERROR_FILE_NOT_FOUND, 'running non-existant exe returned ERROR_FILE_NOT_FOUND');
$opaque = "$^X -e\"0; exit 123;\"";
$err = run($opaque, $opaque, 0, $pid);
is($err, ERROR_SUCCESS, 'no output process started');

my $buf = 'QWERTY';
my $retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #1");
ok(ref($buf) eq 'HASH' && $buf->{ExitCode} == 123, 'buffer of no output process at proc end is correct');

$opaque = "$^X -e\"print 'ABCD';\"";
$err = run($opaque, $opaque, 0, $pid);
is($err, ERROR_SUCCESS, 'a little output process started');
$buf = 'QWERTY';
$retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #2");
is($buf, 'ABCD', 'buffer on 1st read from little output process is correct');
$buf = 'QWERTY';
$retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #3");
ok(ref($buf) eq 'HASH' && $buf->{ExitCode} == 0, 'buffer of little output process at proc end is correct');

{
    my $destroyed;
    package dtor;
    sub DESTROY {$destroyed = 1;}
    package main;
    my $cmd = "$^X -e\"0; exit 123;\"";
    $err = run($cmd, bless({}, 'dtor'), 0, $pid);
    ok(!$destroyed, 'opaque not destroyed yet');
    Win32::APipe::next($buf);
    ok(ref($buf) eq 'HASH' && $buf->{ExitCode} == 123, 'buffer of dtor test is correct');
    is($destroyed, 1, 'opaque doesnt leak');
}
