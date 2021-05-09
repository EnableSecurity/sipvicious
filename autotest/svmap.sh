#!/bin/bash
set -xu

source common.sh

do_test 10 "sipvicious_svmap 1.1..1"
do_test 30 "sipvicious_svmap wronghost"
do_test 30 "sipvicious_svmap 1.2.3.4"
do_test 30 "sipvicious_svmap demo.sipvicious.pro -p 8888"
do_test 0 "sipvicious_svmap demo.sipvicious.pro"

