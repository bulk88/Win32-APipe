use Config;
my $is_64bit_build = ($Config{ptrsize} == 8);
my $is_msvc_compiler = ($Config{cc} =~ /cl/);
my $gen_ntdlldec_def = 'echo LIBRARY ntdll.dll> ntdlldec.def & echo EXPORTS>> ntdlldec.def'
    .' & echo    NtReadFile@36 = NtReadFile>> ntdlldec.def'
    .' & echo    NtCreateIoCompletion@16 = NtCreateIoCompletion>> ntdlldec.def'
    .' & echo    NtRemoveIoCompletion@20 = NtRemoveIoCompletion>> ntdlldec.def'
    .' & echo    NtSetInformationFile@20 = NtSetInformationFile>> ntdlldec.def'
    .' & echo    NtSetIoCompletion@20 = NtSetIoCompletion>> ntdlldec.def'
    .' & echo    NtClose@4 = NtClose>> ntdlldec.def';
if($is_msvc_compiler) {
    system 'echo LIBRARY ntdll.dll> ntdllundec.def & echo EXPORTS>> ntdllundec.def'
    .' & echo    NtReadFile>> ntdllundec.def'
    .' & echo    NtCreateIoCompletion>> ntdllundec.def'
    .' & echo    NtRemoveIoCompletion>> ntdllundec.def'
    .' & echo    NtSetInformationFile>> ntdllundec.def'
    .' & echo    NtSetIoCompletion>> ntdllundec.def'
    .' & echo    NtClose>> ntdllundec.def';
    if($is_64bit_build) {
        system 'lib /out:ntdll.lib /def:ntdllundec.def /machine:x64';
    } else {
        system $gen_ntdlldec_def;
        system 'lib /out:ntdllundec.lib /def:ntdllundec.def /machine:X86';
        system 'lib /out:ntdll.lib /def:ntdlldec.def /machine:X86 ntdllundec.lib';
    }
} else {
    system $gen_ntdlldec_def;
    system 'dlltool -k -d ntdlldec.def -l ntdll.a';
}
