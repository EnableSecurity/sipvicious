#!/bin/bash
set -xu

source common.sh

do_test 30 "sipvicious_svcrack wronghost"
do_test 30 "sipvicious_svcrack 1.2.3.4"
do_test 30 "sipvicious_svcrack demo.sipvicious.pro -p 8888"
do_test 0 "sipvicious_svcrack demo.sipvicious.pro -u -r 100-200"
do_test 40 "sipvicious_svcrack demo.sipvicious.pro -u -r 1400-1600"

