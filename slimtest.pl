use Opcodes;
use B::Stats '-r';
use Test::More;
use Data::Dumper;
use File::Slurp;
use Win32::API;
use Win32::API::Test;

{
    my $GCP = new Win32::API('kernel32.dll', 'GetCurrentProcess', '', 'N');
    my $prochand = $GCP->Call();
    my $GPAM = new Win32::API::More('kernel32.dll', 'BOOL WINAPI GetProcessAffinityMask('
                   .'HANDLE hProcess, PHANDLE lpProcessAffinityMask, '
                   .'PHANDLE lpSystemAffinityMask);');
    die 'API obj for GetProcessAffinityMask failed' if !$GPAM;
    my ($ProcessAffinityMask, $SystemAffinityMask) = (0,0);
    die 'GetProcessAffinityMask failed' if !$GPAM->Call($prochand, $ProcessAffinityMask, $SystemAffinityMask);
    my $bitsinptr =  length(pack(PTR_LET(),0))*8;
    #low cpus on left side in string
    my $availcpus = unpack('b'.$bitsinptr, pack(PTR_LET, $SystemAffinityMask));
    my $highestCPU = index($availcpus, '0');
    die 'can\'t find highest CPU' if $highestCPU < 1;
    my $mask = 2**($highestCPU-1);
    diag("highest CPU mask is $mask\n");
    my $SPAM = new Win32::API('kernel32.dll',
    'BOOL WINAPI SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR dwProcessAffinityMask);');
    die 'API obj for SetProcessAffinityMask failed '.($^E+0) if !$SPAM;
    die 'SPAM failed' if !$SPAM->Call($prochand, $mask);
    $Data::Dumper::Sortkeys = 1;
}

B::Stats::reset_rtime();
plan tests => 100000;
ok(1, "foo $_") for 1..100000;
my $ar = B::Stats::rtime_all();
my $ac = B::Stats::rcount_all();
die "ar vs ac err" if @{$ar} != @{$ac};
my %slim;
for(0..scalar(@{$ar})){
    if(${$ar}[$_]){
        $slim{Opcodes::opname($_)} = {
            time => ${$ar}[$_],
            count => ${$ac}[$_],
            'time/op' => (${$ar}[$_]/${$ac}[$_])
        };
    }
}

#write_file($ARGV[1], Dumper(\%slim));
#$, = "\n";
#my @a = sort{$slim{$a}->{time} <=> $slim{$b}->{time}}keys %slim;;
#print Dumper(\@a);
#print Dumper(\%slim);
#foreach (@a) {
#    print Dumper({$_ => $slim{$_}});
#}
#system 'pause';
write_file($ARGV[0], Dumper(\%slim));

print 'opcode,time,count,time/op'."\n";
foreach(keys %slim) {
    print($_.','.$slim{$_}{time}.','.$slim{$_}{count}.','.$slim{$_}{'time/op'}."\n");
}