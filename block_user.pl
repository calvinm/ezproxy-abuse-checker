#!/usr/bin/perl

use strict;

my $block_user = $ARGV[0];
my $block_session = $ARGV[1];
#
# make backup of user.txt file
#
system("cp /opt/ezproxy/user.txt /opt/ezproxy/user_backup/user.txt-" . time);

open(USERTXT, "/opt/ezproxy/user.txt") || die("can't open /opt/ezproxy/user.txt for reading\n");
open(NEWUSERTXT, ">", "/opt/ezproxy/scripts/newuser.txt") || die("can't open /opt/ezproxy/scripts/newuser.txt for writing\n");


#
#
# add block user to ezproxy user.txt file after #####.....#####auto-block-start
#
# #####.....#####auto-block-start
while (my $line = <USERTXT>) {
	chomp($line);
	print NEWUSERTXT "$line\n";
	if ($line eq '#####.....#####auto-block-start') {
		print NEWUSERTXT "ifUser $block_user; deny; Stop\n";
	}
}
close(USERTXT);
close(NEWUSERTXT);

if ($block_session) {
	system("/opt/ezproxy/ezproxy kill $block_session");
}

system("cp /opt/ezproxy/scripts/newuser.txt /opt/ezproxy/user.txt");