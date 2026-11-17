#!/bin/bash
# Run explicitly with /bin/bash, or open in Terminal. No developer tools needed.
exec /usr/bin/perl -x "$0" "$@"
#!perl
use strict;
use warnings;
use Cwd qw(abs_path);
use File::Basename qw(dirname basename);
use File::Find;
use File::Temp qw(tempdir);
use File::Spec;
use Digest::SHA;
use JSON::PP;
use POSIX qw(WNOHANG strftime);
use Fcntl qw(:DEFAULT :mode);
use Time::HiRes qw(time sleep);
$ENV{PATH}='/usr/bin:/bin:/usr/sbin:/sbin';
umask 0077;
my $kit=dirname(abs_path($0));
my $home=$ENV{HOME};
my $name='Corporate VPN Router TUN Trial.app';
my $app="$kit/$name";
my $outdir="$home/Desktop";
my ($explicit,$skip_open)=(0,0);
while (@ARGV) {
    my $arg=shift @ARGV;
    if ($arg eq '--app') { $app=shift @ARGV // die "Missing app\n"; $explicit=1; }
    elsif ($arg eq '--output-dir') { $outdir=shift @ARGV // die "Missing output directory\n"; }
    elsif ($arg eq '--skip-open') { $skip_open=1; }
    else { die "Unknown argument\n"; }
}
sub clean {
    my ($text)=@_;
    $text =~ s/\Q$home\E/<HOME>/g;
    $text =~ s{/Users/[^/\s]+}{/Users/<USER>}g;
    $text =~ s{https?://[^\s<>"']+}{<URL>}gi;
    $text =~ s{\b[A-Z0-9._%+-]+\@[A-Z0-9.-]+\.[A-Z]{2,}\b}{<EMAIL>}gi;
    $text =~ s{\b(?:\d{1,3}\.){3}\d{1,3}\b}{<IP>}g;
    $text =~ s{((?:password|passwd|authorization|cookie|access_token|refresh_token|secret)\s*[:=]\s*)[^\n]*}{$1<REDACTED>}gi;
    return $text;
}
sub command {
    my ($seconds,@args)=@_;
    pipe(my $read,my $write) or die "pipe: $!";
    my $pid=fork(); defined $pid or die "fork: $!";
    if (!$pid) {
        close $read;
        POSIX::setpgid(0,0);
        open STDOUT,'>&',$write; open STDERR,'>&',$write; close $write;
        open STDIN,'<','/dev/null';
        exec {$args[0]} @args or do { print STDERR "exec failed: $!\n"; POSIX::_exit(127); };
    }
    close $write;
    my ($text,$expired)=('',0);
    my $until=time()+$seconds;
    while (1) {
        if (time()>$until) { $expired=1; kill 'KILL',-$pid; kill 'KILL',$pid; last; }
        my $ready=''; vec($ready,fileno($read),1)=1;
        if (select($ready,undef,undef,.15)>0) {
            my $n=sysread($read,my $buf,16384);
            last if !defined($n) || !$n;
            $text.=$buf if length($text)<2_000_000;
        }
    }
    close $read; waitpid($pid,0);
    my $status=$?;
    return ($expired ? 124 : ($status & 127 ? 128+($status & 127) : $status>>8),clean($text));
}
sub plist {
    my ($path,$key)=@_;
    my ($rc,$value)=command(5,'/usr/libexec/PlistBuddy','-c',"Print :$key","$path/Contents/Info.plist");
    $value =~ s/\s+$//;
    return $rc ? '' : $value;
}
my $expected={};
if (open my $mf,'<',"$kit/ExpectedCode.json") {
    local $/; eval { $expected=decode_json(<$mf>); }; close $mf;
}
my @locations=("$kit/$name","$home/Applications/$name","/Applications/$name");
if (!$explicit && $expected->{build}) {
    for my $installed (@locations[1,2]) {
        if (-d $installed && plist($installed,'CFBundleVersion') eq $expected->{build}) { $app=$installed; last; }
    }
}
my $stamp=strftime('%Y%m%d-%H%M%S',localtime);
my $report="$outdir/Router-launch-$stamp-$$.txt";
sysopen(my $report_fh,$report,O_WRONLY|O_CREAT|O_EXCL,0600) or die "Не удалось сохранить отчёт: $!\n";
sub emit { print $report_fh clean(join('',@_)); }
sub run {
    my ($label,$seconds,@args)=@_;
    my ($rc,$text)=command($seconds,@args);
    emit("\n--- $label ---\n",$text,"\nexit=$rc\n");
    return ($rc,$text);
}
print "Сбор отчёта по новой поставке. Обычно 1–2 минуты.\nНе вводите пароль/OTP и не подключайтесь во время сбора.\n";
emit("Corporate VPN Router launch diagnostic v2\nTime: ",strftime('%Y-%m-%d %H:%M:%S %z',localtime),"\nSelected: $app\nExpected build: ",($expected->{build}//'manifest unavailable'),"\nNo sudo; no protection/network changes; no upload; no application settings read.\n");
run('macOS',5,'/usr/bin/sw_vers');
run('architecture',5,'/usr/bin/uname','-m');
run('hardware model (no serial)',5,'/usr/sbin/sysctl','-n','hw.model');
for my $location (@locations) {
    next unless -d $location;
    emit("\nLocation: $location\nVersion: ",plist($location,'CFBundleShortVersionString')," build=",plist($location,'CFBundleVersion'),"\n");
}
if (!-d $app) {
    emit("\nFAIL: application not found alongside collector or in installation directories.\n");
    close $report_fh; print "Отчёт: $report\n"; exit 0;
}
my $exe=plist($app,'CFBundleExecutable');
$exe='CorporateVPNRouter' unless $exe =~ /^[A-Za-z0-9_.-]+$/;
run('sealed bundle',40,'/usr/bin/codesign','--verify','--deep','--strict','--all-architectures','--verbose=3',$app);
run('main signature and entitlements',10,'/usr/bin/codesign','-d','--verbose=4','--entitlements',':-',$app);
run('minimum system version',5,'/usr/libexec/PlistBuddy','-c','Print :LSMinimumSystemVersion',"$app/Contents/Info.plist");
for my $path ($app,"$app/Contents/MacOS/$exe") {
    run('quarantine',5,'/usr/bin/xattr','-p','com.apple.quarantine',$path);
    run('FinderInfo',5,'/usr/bin/xattr','-px','com.apple.FinderInfo',$path);
}
# Parse Mach-O directly with stock Perl. otool/lipo may require developer tools.
sub macho {
    my ($path)=@_;
    open my $f,'<:raw',$path or return;
    read($f,my $data,-s $path); close $f;
    my $magic=unpack('H8',$data);
    my @offsets=(0);
    if ($magic eq 'cafebabe' || $magic eq 'cafebabf') {
        my $count=unpack('N',substr($data,4,4)); die "invalid fat count" if $count>32;
        my $size=$magic eq 'cafebabe' ? 20 : 32;
        @offsets=map { my $o=8+$_*$size+8; $size==20 ? unpack('N',substr($data,$o,4)) : unpack('Q>',substr($data,$o,8)) } 0..$count-1;
    }
    my @slices;
    for my $base (@offsets) {
        my $magic=unpack('H8',substr($data,$base,4));
        die 'bad Mach-O slice' unless $magic =~ /^(cffaedfe|cefaedfe|feedfacf|feedface)$/;
        my $endian=$magic =~ /^(cffa|cefa)/ ? 'V' : 'N';
        my $u32=sub { unpack($endian,substr($data,$base+$_[0],4)) };
        my $cpu=$u32->(4); my $count=$u32->(16);
        die 'invalid load commands' if $count>8192;
        my $offset=$magic =~ /^(cffaedfe|feedfacf)$/ ? 32 : 28;
        my $slice={arch=>$cpu==0x100000c ? (($u32->(8)&0xffffff)==2 ? 'arm64e' : 'arm64') : $cpu==0x1000007 ? 'x86_64' : sprintf('cpu-%x',$cpu),dependencies=>[],rpaths=>[]};
        for (1..$count) {
            my ($cmd,$size)=($u32->($offset),$u32->($offset+4));
            die 'invalid command size' if $size<8 || $base+$offset+$size>length($data);
            if ($cmd==0x32 || $cmd==0x24) {
                my $v=$u32->($offset+($cmd==0x32 ? 12 : 8));
                $slice->{minimum_macos}=sprintf('%d.%d.%d',$v>>16,($v>>8)&255,$v&255);
            }
            if (grep {$_==$cmd} (0xc,0x80000018,0x8000001f,0x80000023,0x8000001c)) {
                my $str_offset=$u32->($offset+8);
                die 'invalid string offset' if $str_offset >= $size;
                my $text=substr($data,$base+$offset+$str_offset,$size-$str_offset); $text =~ s/\0.*//s;
                push @{$slice->{$cmd==0x8000001c ? 'rpaths' : 'dependencies'}},$text;
            }
            $offset+=$size;
        }
        push @slices,$slice;
    }
    return \@slices;
}
my @code;
find({no_chdir=>1,wanted=>sub {
    return if -l $_ || !-f $_;
    open my $f,'<:raw',$_ or return; read($f,my $magic,4); close $f;
    push @code,$File::Find::name if unpack('H8',$magic) =~ /^(cffaedfe|cefaedfe|feedfacf|feedface|cafebabe|cafebabf)$/;
}},$app);
my %access;
my %observed;
for my $path (sort @code) {
    my $relative=substr($path,length($app)+1);
    $observed{$relative}=1;
    open my $f,'<:raw',$path or next;
    my $sha=Digest::SHA->new(256)->addfile($f)->hexdigest; close $f;
    my $expected_sha=$expected->{files}{$relative}{sha256};
    emit("\nCODE $relative\nsha256=$sha\nexpected=",defined($expected_sha) ? ($sha eq $expected_sha ? 'MATCH' : 'MISMATCH') : 'not in manifest',"\n");
    eval { emit(JSON::PP->new->canonical->pretty->encode(macho($path))); }; emit("PARSE ERROR $@\n") if $@;
    run('component signature',12,'/usr/bin/codesign','--verify','--strict','--all-architectures',$path);
    my $current=$path;
    while (length($current)>1 && !$access{$current}++) {
        run('permissions / ACL / flags',5,'/bin/ls','-ldeO',$current);
        $current=dirname($current);
    }
}
for my $relative (sort keys %{$expected->{files}//{}}) { emit("MISSING CODE $relative\n") unless $observed{$relative}; }
emit("\nMach-O files found: ",scalar @code,"\n");
my $predicate='sender == "AppleMobileFileIntegrity" OR sender == "AppleSystemPolicy" OR process == "amfid" OR process == "syspolicyd" OR process == "taskgated" OR process == "taskgated-helper" OR process BEGINSWITH "XProtect" OR (process == "kernel" AND (eventMessage CONTAINS[c] "AMFI" OR eventMessage CONTAINS[c] "code sign" OR eventMessage CONTAINS[c] "exec")) OR ((process == "launchd" OR process == "runningboardd" OR process == "CoreServicesUIAgent") AND (eventMessage CONTAINS[c] "CorporateVPNRouter" OR eventMessage CONTAINS[c] "com.geokhv.corporate-vpn-router"))';
my $bundle_id=plist($app,'CFBundleIdentifier');
$bundle_id='unreadable-router-bundle' unless $bundle_id =~ /^[A-Za-z0-9.-]+$/;
$predicate =~ s/CorporateVPNRouter/$exe/g;
$predicate =~ s/com\.geokhv\.corporate-vpn-router/$bundle_id/g;
my ($running,$running_pids)=command(5,'/usr/bin/pgrep','-x',$exe);
if ($skip_open || $running==0) {
    emit("\nLaunch skipped: ",$skip_open ? 'explicit diagnostic-only mode' : 'a process with this executable name exists; avoid disturbing a session (does not prove main ran)',"\n");
    my @pids=$running_pids =~ /^(\d+)$/mg;
    run('existing process metadata (no arguments or environment)',5,'/bin/ps','-p',join(',',@pids),'-o','pid=,stat=,etime=,comm=') if @pids;
} else {
    my $temporary=tempdir('cvr-launch-report-XXXXXX',TMPDIR=>1,CLEANUP=>1);
    my $stream=fork(); defined $stream or die "fork: $!";
    if (!$stream) {
        my ($rc,$text)=command(18,'/usr/bin/log','stream','--style','compact','--level','debug','--timeout','12','--predicate',$predicate);
        open my $s,'>',"$temporary/security.txt" or POSIX::_exit(1);
        print $s "Security daemon window (12 seconds; OS privacy remains enabled):\n$text\nexit=$rc\n"; close $s;
        POSIX::_exit(0);
    }
    sleep 1;
    emit("\nAttempt time: ",strftime('%Y-%m-%d %H:%M:%S %z',localtime),"\n");
    run('ordinary LaunchServices open (exit=0 alone does NOT prove main ran)',12,'/usr/bin/open',$app);
    waitpid($stream,0);
    if (open my $s,'<',"$temporary/security.txt") { local $/; emit(<$s>); close $s; }
    else { emit("Security stream unavailable\n"); }
    my ($status)=command(5,'/usr/bin/pgrep','-x',$exe);
    emit("\nProcess-name observation after attempt: ",$status==0 ? 'present (not a connection test)' : 'absent',"\n");
}
run('syspolicy_check distribution',45,'/usr/bin/syspolicy_check','distribution',$app);
run('Gatekeeper assessment',25,'/usr/sbin/spctl','--assess','--type','execute','--verbose=4',$app);
emit("\nEND. If macOS denied launch before main, an in-app log is not expected.\nReport stays local; share it manually with the developer.\n");
close $report_fh;
print "Готово. Один отчёт сохранён: $report\nПередайте только этот TXT разработчику.\n";
