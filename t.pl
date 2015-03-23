use blib;
use Win32::APipe;
use Data::Dumper;

#my $opaque;
my $buf;
#my $err;
my $f;
my $activeprocesses = 0;
#a handle visible in ProcMon, used to visually check if handles are being
#inherited or not
open($f , '<Changes');

#my @runlist = (('t/t/t.t'."\n") x 2);

my @runlist = qx'dir /s /b "C:\Documents and Settings\Owner\Desktop\cpan libs\w32a\g\t"';
foreach(@runlist) {
    chop($_);
    $_ = "$^X \"$_\"";
}
#print Dumper(\@runlist);
#exit;

my %results;

chdir('C:\Documents and Settings\Owner\Desktop\cpan libs\w32a\g');
foreach(@runlist) {
    $activeprocesses++;
    my $opaque = $_;
    Win32::APipe::run($opaque, $opaque);
}
#sleep 2;
do {
    my $opaque = Win32::APipe::next($buf);
    print Dumper([$opaque, $buf]);
    if(length($buf) == 0 ){
        $activeprocesses--;
    }
    else {
        $results{$opaque} .= $buf;
    }
} while($activeprocesses);

#print Dumper(\%results);

