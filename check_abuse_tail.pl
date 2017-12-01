#!/usr/bin/perl

# 207.23.184.17 i1ODFohGOVXJSxj bad_user [18/Jul/2016:20:56:41 -0700] "GET https://proxy.lib.sfu.ca:443/connect?session=si1ODFohGOVXJSxj&url=menu HTTP/1.1" 302 0


use strict;
use Date::Calc;
use Geo::IP;
use URI;
use Domain::PublicSuffix;
use Data::Dumper;

use vars qw($GEOFILE $SESSION_FILE $SESSIONS $EMAILS $DOMAIN_THRESHOLD $PERCENT_404_THRESHOLD);

$GEOFILE = '/opt/ezproxy/GeoLiteCity.dat';
$SESSION_FILE = '/opt/ezproxy/scripts/audit_sessions.dat';
$EMAILS = 'sample@gmail.com';
$DOMAIN_THRESHOLD = 8;
$PERCENT_404_THRESHOLD = 10;


my %abbr = ('Jan' => 1, 'Feb' => 2, 'Mar' => 3,  'Apr' => 4,  'May' => 5, 'Jun' => 6,  'Jul' => 7,  'Aug' => 8,  'Sep' => 9,  'Oct' => 10,  'Nov' => 11,  'Dec' => 12);

my ($starttime, $endtime, $session_id);

my $suffix = Domain::PublicSuffix->new();
my ($current_domain, $previous_domain, $domain_switch);

&main();

sub main {
	my ($line, $message, $block_user, $block_session);
	
	while ($line = <STDIN>) {
		my ($ip, $session, $user, $datetime, $url, $traffic, $httpstatus);
		my ($country, $city);

		my $gi = Geo::IP->open($GEOFILE, GEOIP_STANDARD);
	
		chomp($line);
		$line =~ s/\s+/ /go;
	
		# ($ip, $session, $user, $datetime, $url, $traffic, $httpstatus) = /^(\S+) (\S+) (\S+) \[(.+)\] \"(.+)\" (\S+) (\S+)/o;
	
		if ($line =~ m#^(.*?)\s(.*?)\s(.*?)\s\[(.*?)\].*?\"(.*?)\"\s(\d*)\s(\d*).*$#) {
			$ip = $1;
			$session = $2;
			$user = $3;
			$datetime = $4;
			$url = $5;
			$httpstatus = $6;
			$traffic = $7;
		}
		if (defined($$SESSIONS{$session}{'done'})) {
			if ($$SESSIONS{$session}{'done'} eq 'done') { print "session exists in file\n\n"; exit; }
		}
		$session_id = $session;
		
		# print "|$session|\n";
		
		if ($session ne '-') {
			# print "$line\n";
			$message .= $line . "\n";
			$block_user = $user;
			$block_session = $session;
		}
	}
	if ($message) {
		$message .= "\n user $block_user blocked in /opt/ezproxy/user.txt\n";
		$message .= "\n session $block_session killed\n";
		system("/opt/ezproxy/scripts/block_user.pl $block_user $block_session");
		&send_email($message);
	}
}

sub calc_duration {
	my ($start, $end) = @_;
	my ($duration);
	my ($syy, $smm, $sdd, $shr, $smin, $ssec);
	my ($eyy, $emm, $edd, $ehr, $emin, $esec);

	if ($start =~ m#^(\d\d)\/(.*?)\/(\d\d\d\d):(\d\d):(\d\d):(\d\d)$#) {
		$sdd = $1;
		$smm = $2;
		$syy = $3;
		$shr = $4;
		$smin = $5;
		$ssec = $6;
	}
	if ($end =~ m#^(\d\d)\/(.*?)\/(\d\d\d\d):(\d\d):(\d\d):(\d\d)$#) {
		$edd = $1;
		$emm = $2;
		$eyy = $3;
		$ehr = $4;
		$emin = $5;
		$esec = $6;
	}
	$smm = $abbr{$smm};
	$emm = $abbr{$emm};
	# print "\n";
	# print "start $start $syy, $smm, $sdd, $shr, $smin, $ssec\n";
	# print "end   $end $eyy, $emm, $edd, $ehr, $emin, $esec\n";
	my ($Dd,$Dh,$Dm,$Ds) = Date::Calc::Delta_DHMS($syy, $smm, $sdd, $shr, $smin, $ssec, $eyy, $emm, $edd, $ehr, $emin, $esec);
	
	# $duration = "$Dd,$Dh,$Dm,$Ds";
	$duration = ($Dd * 86400) + ($Dh * 3600) + ($Dm * 60) + $Ds;
	return($duration);
}

sub send_email {
	my ($message) = @_;
	my $subject = "[ezproxy] - Abuse detected";

	my $pid = open(MAILPIPE, "| /bin/mail -s '$subject' '$EMAILS'");
	print MAILPIPE "$subject\n\n";

	print MAILPIPE $message . "\n";
	close(MAILPIPE);
}

sub hms {
        my ($seconds) = @_;

        my $hh = int($seconds / 3600);
        my $leftover = $seconds % 3600;
        my $mm = int($leftover / 60);
        my $ss = int($leftover % 60);

        return sprintf("%02d:%02d:%02d", $hh, $mm, $ss);
}

sub pretty_bytes {
    my $num = shift;
    return ''    if $num < 0;
    return '0K'  if $num == 0;
    return '<1K' if $num < 1024;

    my @suffix = qw/K M G T P/;
    my $offset = -1;

    while( $num >= 1024 and $offset < scalar @suffix ) {
        ++$offset;
        $num = int( $num / 1024 );
    }
    return "$num$suffix[$offset]";
}

