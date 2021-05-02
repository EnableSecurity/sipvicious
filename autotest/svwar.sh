#!/bin/bash
set -xu

source common.sh

do_test 30 "sipvicious_svwar wronghost"
do_test 30 "sipvicious_svwar 1.2.3.4"
do_test 30 "sipvicious_svwar demo.sipvicious.pro -p 8888"
do_test 0 "sipvicious_svwar udp://demo.sipvicious.pro:5060 -e 100-200"
do_test 40 "sipvicious_svmap demo.sipvicious.pro -e 1000-1200"

