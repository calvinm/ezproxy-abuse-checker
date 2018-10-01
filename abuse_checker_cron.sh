#!/bin/sh

#
# check for sci-hub type vacuum attack
#

/usr/bin/tail -10000 /opt/ezproxy/ezproxy.log | /opt/ezproxy/scripts/count_sessions_tail.pl


#
# check for IEEE tripwire token
#

/usr/bin/tail -10000 /opt/ezproxy/ezproxy.log | /bin/grep '{token}' | /opt/ezproxy/scripts/check_abuse_tail.pl
