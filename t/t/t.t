# Before 'make install' is performed this script should be runnable with
# 'make test'. After 'make install' it should work as 'perl Win32-APipe.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

#use strict;
use warnings;
#use Win32API::File 'GetOsFHandle', 'FdGetOsFHandle';
BEGIN {
#    #printf("in %x out %x err %x", GetOsFHandle(STDIN),GetOsFHandle(STDOUT),GetOsFHandle(STDERR));
#    my $i = FdGetOsFHandle(fileno(STDIN));
#    my $o = FdGetOsFHandle(fileno(STDOUT));
#    warn $^E if $o == 0xffffffff;
#    my $e = FdGetOsFHandle(fileno(STDERR));
#    warn(sprintf("in %x out %x err %x", $i, $o, $e));
#    system 'pause';
}
use Test::More (tests => 5);
my $t = 1;
ok(1, "one");
sleep $t;
ok(1, "two");
sleep $t;
ok(1, "three");
sleep $t;
ok(1, "four");
sleep $t;
ok(1, "five");
sleep $t;

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.

