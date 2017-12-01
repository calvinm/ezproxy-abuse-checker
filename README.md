# ezproxy-abuse-checker

Perl + shell scripts that actively monitors ezproxy log file for vacuum attack.

* Requires Perl Modules:
* Date::Calc
* Geo::IP
* URI
* Domain::PublicSuffix
* Data::Dumper

File Manifest:
* crontab.dat - this is the cron file used to run the abuse checker every 10 minutes.  (tune the frequency to your liking)
* count_sessions_tail.pl - this runs against <STDIN>
  * requires a geo IP file /opt/ezproxy/GeoLiteCity.dat download from: http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz and decompress
* check_abuse_tail.pl - blocks and kill session of all ezproxy log lines sent to this (used to search for IEEE token and other easily identifiable abuses detected via grep)
* block_user.pl - blocks ezproxy user by editing user.txt also kills ezproxy session
  * usage block_user.pl user_id session_id
  * this is automatically called by check_abuse_tail.pl
* abuse_checker_cron.sh - script which pipes the last 10,000 lines of the ezproxy log into the abuse checker and the IEEE token checker
