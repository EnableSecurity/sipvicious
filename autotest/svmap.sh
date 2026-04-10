#!/bin/bash
set -xu

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

# invalid ip format
do_test 10 "sipvicious_svmap 1.1..1"
# invalid host
do_test 30 "sipvicious_svmap wronghost"
# valid ip but not a sip talking host
do_test 30 "sipvicious_svmap 1.2.3.4"
# valid host but wrong port
do_test 30 "sipvicious_svmap $AUTOTEST_SIP_HOST -p 8888"
# valid host w/ wrong port range
do_test 30 "sipvicious_svmap $AUTOTEST_SIP_HOST -p 8000-9000"
# valid host w/ default port
do_test 0 "sipvicious_svmap $AUTOTEST_SIP_HOST"
# valid ip w/ default port
do_test 0 "sipvicious_svmap $AUTOTEST_SIP_IP"
# valid ip w/ different ports
do_test 30 "sipvicious_svmap $AUTOTEST_SIP_HOST -p 5060,8888"
# ipv6 hosts
do_test 30 "sipvicious_svmap -6 ::1"
do_test 30 "sipvicious_svmap -6 ::"
# commented out, GitHub actions does not appear to support ipv6.
# ip ranges & cidr ranges
do_test 30 "sipvicious_svmap 10.0.0.1-2 172.16.131.1 $AUTOTEST_SIP_CIDR 10.0.0.*"
# controlling packet rate + different method name + randomize
do_test 30 "sipvicious_svmap 10.0.0.0/30 -t 3 -m INVITE --randomize"
# ping a specific extension
do_test 0 "sipvicious_svmap $AUTOTEST_SIP_HOST -e 1000"
# non-existent file
do_test 20 "sipvicious_svmap -I nonexistent.txt"
# IPs from file testing
echo -e "1.1.1.1\n$AUTOTEST_SIP_IP" >> test.txt
do_test 30 "sipvicious_svmap -I test.txt"
rm test.txt
# scan first few IPs
do_test 30 "sipvicious_svmap 10.0.0.0/8 --first 2"
# compact mode
do_test 0 "sipvicious_svmap $AUTOTEST_SIP_HOST -c"
