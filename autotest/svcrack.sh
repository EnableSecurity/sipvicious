#!/bin/bash
set -xu

source common.sh

# no -u supplied
do_test 10 "sipvicious_svcrack nouser-syntaxerr"
# invalid hostname syntax
do_test 10 "sipvicious_svcrack udp://pew.pew"
# again invalid syntax
do_test 10 "sipvicious_svcrack pew.pew:5060"
# multiple hosts (svcrack doesn't support it rn)
do_test 10 "sipvicious_svcrack pew.pew:5060 ws://pew.pew:5060"
# negative maximumtime
do_test 10 "sipvicious_svcrack demo.sipvicious.pro --maximumtime -1"
# just the scheme with no URL (technically a valid URL)
do_test 20 "sipvicious_svcrack blabla://"
# non existent host
do_test 30 "sipvicious_svcrack 1.2.3.4 -u 100"
# invalid port on host
do_test 30 "sipvicious_svcrack demo.sipvicious.pro -p 8888 -u 100"
# valid user & hostname but wrong range
do_test 0 "sipvicious_svcrack demo.sipvicious.pro -u 1000 -r 100-200"
# valid user & hostname with valid range
do_test 40 "sipvicious_svcrack demo.sipvicious.pro -u 1000 -r 1400-1600"
# non-existent dictionary file
do_test 20 "sipvicious_svcrack demo.sipvicious.pro -d test.txt -u 1000"
# valif dictionary file
echo 1500 > test2.txt
do_test 40 "sipvicious_svcrack demo.sipvicious.pro -d test2.txt -u 1000"
rm test2.txt
# enabling defaults
do_test 40 "sipvicious_svcrack demo.sipvicious.pro -D -u 1000"
