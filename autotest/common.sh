AUTOTEST_SIP_HOST="${AUTOTEST_SIP_HOST:-pbx1.dvrtc.net}"

if [ -z "${AUTOTEST_SIP_IP:-}" ]; then
    AUTOTEST_SIP_IP="$(
        AUTOTEST_SIP_HOST="$AUTOTEST_SIP_HOST" python - <<'PY'
import os
import socket
import sys

host = os.environ["AUTOTEST_SIP_HOST"]
try:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
except socket.gaierror:
    sys.exit(1)

seen = set()
for _, _, _, _, sockaddr in infos:
    ip = sockaddr[0]
    if ip in seen:
        continue
    seen.add(ip)
    print(ip)
    break
PY
    )"
fi

if [ -z "${AUTOTEST_SIP_IP:-}" ]; then
    echo "failed to resolve AUTOTEST_SIP_HOST='$AUTOTEST_SIP_HOST' to an IPv4 address" >&2
    exit 1
fi

AUTOTEST_SIP_CIDR="${AUTOTEST_SIP_CIDR:-${AUTOTEST_SIP_IP}/32}"

do_test() {
    $2
    if [ $? -ne $1 ]; then exit 1; fi
}
