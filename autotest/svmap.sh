#!/bin/bash
set -xu

source common.sh

do_test 10 "sipvicious_svmap 1.1..1"
do_test 30 "sipvicious_svmap wronghost"
do_test 30 "sipvicious_svmap 1.2.3.4"
do_test 30 "sipvicious_svmap demo.sipvicious.pro -p 8888"
do_test 30 "sipvicious_svmap demo.sipvicious.pro -p 8000-9000"
do_test 0 "sipvicious_svmap demo.sipvicious.pro"
do_test 0 "sipvicious_svmap 172.104.142.43" # demo.sipvicious.pro; this might change
do_test 30 "sipvicious_svmap demo.sipvicious.pro -p 5060,8888"
do_test 30 "sipvicious_svmap -6 ::1"
do_test 30 "sipvicious_svmap -6 ::"
do_test 0 "sipvicious_svmap -6 2a01:7e01::f03c:92ff:fecf:60a8" # demo.sipvicious.pro; this might change
do_test 30 "sipvicious_svmap 10.0.0.1-2 172.16.131.1 demo.sipvicious.pro/32 10.0.0.*"
