#!/usr/bin/perl -w
use strict;
#make sure the parent .t proc is gone
sleep 2;
print <<END;
ok 6 - six
ok 7 - seven
ok 8 - eight
ok 9 - nine
ok 10 - ten
END
exit 1;