do_test() {
    $2
    if [ $? -ne $1 ]; then exit 1; fi
}

