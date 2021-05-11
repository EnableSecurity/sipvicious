#!/bin/bash
set -xu

source common.sh

do_test 10 "sipvicious_svcrack nouser-syntaxerr"
do_test 30 "sipvicious_svcrack 1.2.3.4 -u 100"
do_test 30 "sipvicious_svcrack demo.sipvicious.pro -p 8888 -u 100"
do_test 0 "sipvicious_svcrack demo.sipvicious.pro -u 1000 -r 100-200"
do_test 40 "sipvicious_svcrack demo.sipvicious.pro -u 1000 -r 1400-1600"
do_test 20 "sipvicious_crack demo.sipvicious.pro -d test.txt -u 1000"
echo 1500 > test2.txt
do_test 40 "sipvicious_crack demo.sipvicious.pro -d test2.txt -u 1000"
rm test2.txt
