#!/usr/bin/perl -w
use strict;
print <<END;
1..10
ok 1 - one
ok 2 - two
ok 3 - three
ok 4 - four
ok 5 - five
END
system(1, "\"$^X\" t/t/2proctappart2.pl");
#let part 2 child procstart up and goto sleep, crudly make sure that the child proc
#fully inited and has gone to sleep before this exists
sleep 1;
exit 0;



