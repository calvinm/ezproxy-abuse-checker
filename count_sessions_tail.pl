#!/usr/bin/perl

use strict;
use Date::Calc;
use Geo::IP;
use URI;
use Domain::PublicSuffix;
use Data::Dumper;
use Storable;

use vars qw($GEOFILE $SESSION_FILE $SESSIONS $EMAILS $DOMAIN_THRESHOLD $PERCENT_404_THRESHOLD $SWITCH_PERCENT_THRESHOLD);

$GEOFILE = '/opt/ezproxy/GeoLiteCity.dat';
$SESSION_FILE = '/opt/ezproxy/scripts/audit_sessions.dat';
$EMAILS = 'sample@gmail.com';
$DOMAIN_THRESHOLD = 10;
$PERCENT_404_THRESHOLD = 15;
$SWITCH_PERCENT_THRESHOLD = 30;



my %abbr = ('Jan' => 1, 'Feb' => 2, 'Mar' => 3,  'Apr' => 4,  'May' => 5, 'Jun' => 6,  'Jul' => 7,  'Aug' => 8,  'Sep' => 9,  'Oct' => 10,  'Nov' => 11,  'Dec' => 12);

my ($starttime, $endtime, $session_id);

my $suffix = Domain::PublicSuffix->new();
my ($current_domain, $previous_domain, $domain_switch);

&main();

sub main {
	my $line;
	
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
		
		$datetime =~ s/\s-0[7-8]00$//;
		my $ip_record = $gi->record_by_addr($ip);
		if (defined($ip_record)) { 
			$country = $ip_record->country_code;
			$city = $ip_record->city;
		}
		else {
			$country = '??';
			$city = '??';
		}


		# print "|$ip|  |$country|  |$city|  |$session|  |$user|  |$datetime| |$url| |$httpstatus|  |$traffic|  ";
		$endtime = $datetime;
		if (! $starttime) {
			$starttime = $endtime;
		}
		my $duration = &calc_duration($starttime, $endtime);

		if (defined($$SESSIONS{$session}{'ip'})) {
			if ($$SESSIONS{$session}{'ip'} != $ip) {
				# print "IP changed during session : $session\n";
				$$SESSIONS{$session}{'ip_change'}++;
			}
		}

		#
		# get domain
		#
		my $domain;
		my ($method, $parsed_url, $protocol);
		if ($url =~ m#^(.*?)\s(.*?)\s(.*?)$#) {
			$method = $1;
			$parsed_url = $2;
			$protocol = $3;
			my $url_obj = URI->new($parsed_url);
			$domain = $url_obj->host;			
		}
		$domain = $suffix->get_root_domain($domain);
		
		#
		# check for domain switching
		#
		$current_domain = $domain;
		# print "|$current_domain| compare |$previous_domain|\n";
		if ($current_domain ne $previous_domain) { $$SESSIONS{$session}{'domain_switch'}++; }
		$previous_domain = $domain;
		
		
		# print "|$method| |$parsed_url| |$protocol|\n";
		# print "|$domain|\n";

		$$SESSIONS{$session}{'starttime'} = $starttime;
		$$SESSIONS{$session}{'endtime'}   = $endtime;
		$$SESSIONS{$session}{'duration'}  = $duration;
		$$SESSIONS{$session}{'ip'} = $ip;
		$$SESSIONS{$session}{'country'} = $country;
		$$SESSIONS{$session}{'city'} = $city;
		$$SESSIONS{$session}{'user'} = $user;
		$$SESSIONS{$session}{'traffic'} += $traffic;
		$$SESSIONS{$session}{'requests'}++;
		$$SESSIONS{$session}{'http_status'}{$httpstatus}++;
		$$SESSIONS{$session}{'domains'}{$domain}++;
		$$SESSIONS{$session}{'switch_percent'} = sprintf("%02d", $$SESSIONS{$session}{'domain_switch'} / $$SESSIONS{$session}{'requests'} * 100);

		# print "duration $duration\n\n";
	}
	$$SESSIONS{$session_id}{'done'} = 'done';
	# print "sessions: " . (scalar keys %sessions) . "\n";
	# print Dumper($SESSIONS);
	
	&check_abuse();
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

sub check_abuse {
	my $message;
	foreach my $session (keys %$SESSIONS) {
		my $domain_switch = $$SESSIONS{$session}{'domain_switch'};
		my $domains = scalar (keys (%{$$SESSIONS{$session}{'domains'}}));
		my $duration = &hms($$SESSIONS{$session}{'duration'});
		my $bytes = &pretty_bytes($$SESSIONS{$session}{'traffic'});
		my $user = $$SESSIONS{$session}{'user'};
		my $city = $$SESSIONS{$session}{'city'};
		my $country = $$SESSIONS{$session}{'country'};
		my $percent = (sprintf"%02d", $$SESSIONS{$session}{'http_status'}{'404'} / $$SESSIONS{$session}{'requests'} * 100);
		my $switch_percent = $$SESSIONS{$session}{'switch_percent'};

		# print "session $session\n";
		# print "domains = $domains\n";

		if (($domains > $DOMAIN_THRESHOLD) && 
			($switch_percent > $SWITCH_PERCENT_THRESHOLD) &&
			($percent > $PERCENT_404_THRESHOLD)) {
			$message .= "session = $session  domains = $domains  404% = $percent %\n";
			$message .= "traffic: $bytes    duration: $duration   location: $country $city\n";
			$message .= Dumper($$SESSIONS{$session});
			$message .= "\n user $user blocked in /opt/ezproxy/user.txt\n";
			$message .= "\n\n\n";
			system("/opt/ezproxy/scripts/block_user.pl $user $session");
		}
	}
	if ($message) {
		# print "have message: ";
		# print "$message\n";
		
		&send_email($message);
	}
	else {
		# no message

		# print "no message\n";
	}
}


sub send_email {
	my ($message) = @_;
	my $subject = "[ezproxy] - possible abuse detected";

	my $pid = open(MAILPIPE, "| /bin/mail -s '$subject' '$EMAILS'");
	print MAILPIPE "$subject\n\n";
	print MAILPIPE "thresholds: domains =  $DOMAIN_THRESHOLD 404% = $PERCENT_404_THRESHOLD % \n";

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

