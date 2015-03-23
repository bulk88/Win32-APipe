# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Win32-APipe.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 10;
use constant ERROR_FILE_NOT_FOUND => 2;
use constant ERROR_SUCCESS => 0;
BEGIN { use_ok('Win32::APipe', ':all') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

my $opaque = 'nonexistant.exe';
my $err = run($opaque, $opaque);
is($err, ERROR_FILE_NOT_FOUND, 'running non-existant exe returned ERROR_FILE_NOT_FOUND');
$opaque = "$^X -e\"0;\"";
$err = run($opaque, $opaque);
is($err, ERROR_SUCCESS, 'no output process started');

my $buf = 'QWERTY';
my $retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #1");
ok(defined $buf && length $buf == 0, 'buffer of no output process is correct');

$opaque = "$^X -e\"print 'ABCD';\"";
$err = run($opaque, $opaque);
is($err, ERROR_SUCCESS, 'a little output process started');
$buf = 'QWERTY';
$retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #2");
is($buf, 'ABCD', 'buffer on 1st read from little output process is correct');
$buf = 'QWERTY';
$retopaque = Win32::APipe::next($buf);
is($retopaque, $opaque, "next()'s retval opaque feature works #3");
ok(defined $buf && length $buf == 0, 'end of stream detected for litte output');
