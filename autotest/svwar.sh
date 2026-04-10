#!/bin/bash
set -xu

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/common.sh"

# invalid host
do_test 30 "sipvicious_svwar wronghost"
# valid host not talking SIP
do_test 30 "sipvicious_svwar 1.2.3.4"
# valid host but wrong port
do_test 30 "sipvicious_svwar $AUTOTEST_SIP_HOST -p 8888"
# valid url format but wrong extension range
do_test 0 "sipvicious_svwar udp://$AUTOTEST_SIP_HOST:5060 -e 100-200"
# valid host & valid extension range
do_test 40 "sipvicious_svwar $AUTOTEST_SIP_HOST -e 1000-1200"
# valid url format with extension range
do_test 40 "sipvicious_svwar udp://$AUTOTEST_SIP_HOST:5060 -e 1000-1200"
# valid url format but wrong port w/ valid extension range
do_test 30 "sipvicious_svwar udp://$AUTOTEST_SIP_HOST:8888 -e 1000-1200"
# non existent input dictionary files
do_test 20 "sipvicious_svwar -d test.txt $AUTOTEST_SIP_HOST"
# valid dictionary file for extensions
echo 1100 > test2.txt
do_test 40 "sipvicious_svwar -d test2.txt $AUTOTEST_SIP_HOST"
rm test2.txt
# enable defaults mode
do_test 40 "sipvicious_svwar udp://$AUTOTEST_SIP_HOST:5060 -D -m OPTIONS"
# compact mode + packet rate
do_test 40 "sipvicious_svwar $AUTOTEST_SIP_HOST -e 1000-1005 -c -t 2"
