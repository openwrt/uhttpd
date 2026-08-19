#!/usr/bin/env bash
#
# Functional tests for the uhttpd reverse proxy handler (-Y).
#
# Usage: tests/proxy/run.sh [path/to/uhttpd]
#
# The binary is taken from the argument, from $UHTTPD, or from the usual
# in-tree build locations. Needs curl and python3.
#
set -u

cd "$(dirname "$0")" || exit 1
here=$PWD

uhttpd=${1:-${UHTTPD:-}}
if [ -z "$uhttpd" ]; then
	for cand in ../../uhttpd ../../build/uhttpd; do
		if [ -x "$cand" ]; then
			uhttpd=$cand
			break
		fi
	done
fi

if [ ! -x "${uhttpd:-}" ]; then
	echo "no uhttpd binary: pass one as an argument or set UHTTPD" >&2
	exit 1
fi

uhttpd=$(cd "$(dirname "$uhttpd")" && pwd)/$(basename "$uhttpd")

fport=${UH_TEST_PORT:-18080}
bport=${UH_TEST_BACKEND_PORT:-18081}

work=$(mktemp -d) || exit 1
bpid=
upid=

cleanup() {
	[ -n "$upid" ] && kill "$upid" 2>/dev/null
	[ -n "$bpid" ] && kill "$bpid" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT

wait_port() {
	local i
	for i in $(seq 100); do
		if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
			return 0
		fi
		sleep 0.05
	done
	return 1
}

pass=0
fail=0

check() { # name expected actual
	if [ "$2" = "$3" ]; then
		pass=$((pass + 1))
		echo "ok   - $1"
	else
		fail=$((fail + 1))
		echo "FAIL - $1"
		echo "       want: $2"
		echo "       got:  $3"
	fi
}

mkdir "$work/docroot"
echo "static file" > "$work/docroot/index.html"
echo "/authapi:bob:secret" > "$work/httpd.conf"
dd if=/dev/urandom of="$work/blob" bs=1024 count=2048 2>/dev/null

python3 "$here/backend.py" $bport &
bpid=$!
wait_port $bport || { echo "backend did not start" >&2; exit 1; }

# /api      passes the URL through unchanged
# /strip    replaces the prefix with /
# /sub      replaces the prefix with /deep
# /dead     points at a port nothing listens on
# /authapi  is covered by an auth realm in httpd.conf
"$uhttpd" -f -p 127.0.0.1:$fport -h "$work/docroot" \
	-Y /api=127.0.0.1:$bport \
	-Y /strip=127.0.0.1:$bport/ \
	-Y /sub=127.0.0.1:$bport/deep \
	-Y /dead=127.0.0.1:1 \
	-Y /authapi=127.0.0.1:$bport \
	-c "$work/httpd.conf" &
upid=$!
wait_port $fport || { echo "uhttpd did not start" >&2; exit 1; }

U=http://127.0.0.1:$fport

check "static file still served" "static file" "$(curl -s $U/)"

check "request line passed through" "GET /api/x?q=1 HTTP/1.1" \
	"$(curl -s "$U/api/x?q=1" | head -1)"

check "prefix stripped" "GET /x?q=1 HTTP/1.1" \
	"$(curl -s "$U/strip/x?q=1" | head -1)"

check "prefix stripped, bare prefix" "GET / HTTP/1.1" \
	"$(curl -s "$U/strip" | head -1)"

check "prefix replaced" "GET /deep/x HTTP/1.1" \
	"$(curl -s "$U/sub/x" | head -1)"

check "host header forwarded" "host: 127.0.0.1:$fport" \
	"$(curl -s $U/api/ | grep '^host:')"

check "x-forwarded-for set" "x-forwarded-for: 127.0.0.1" \
	"$(curl -s $U/api/ | grep '^x-forwarded-for:')"

check "x-forwarded-proto set" "x-forwarded-proto: http" \
	"$(curl -s $U/api/ | grep '^x-forwarded-proto:')"

check "client x-forwarded-for not trusted" "x-forwarded-for: 127.0.0.1" \
	"$(curl -s -H 'X-Forwarded-For: 1.2.3.4' $U/api/ | grep '^x-forwarded-for:')"

# the client's Connection/Upgrade fields must not reach the backend; the
# proxy's own "Connection: close" is what it should see instead
check "hop-by-hop request headers dropped" "connection: close" \
	"$(curl -s -H 'Connection: keep-alive, foo' -H 'Upgrade: h2c' $U/api/ \
		| grep -E '^(connection|keep-alive|upgrade):')"

check "POST body forwarded" "hello body" \
	"$(curl -s -d 'hello body' $U/strip/echo)"

check "chunked request body forwarded" "chunky" \
	"$(curl -s -H 'Transfer-Encoding: chunked' -d 'chunky' $U/strip/echo)"

check "chunked response relayed" "alphabetagamma" "$(curl -s $U/strip/chunked)"

check "close-delimited response relayed" "delimited-by-close" \
	"$(curl -s $U/strip/noframing)"

check "204 relayed" "204" \
	"$(curl -s -o /dev/null -w '%{http_code}' $U/strip/204)"

check "dead backend gives 502" "502" \
	"$(curl -s -o /dev/null -w '%{http_code}' $U/dead/)"

check "unmatched url still 404" "404" \
	"$(curl -s -o /dev/null -w '%{http_code}' $U/nothing)"

# keep-alive: the second request must reuse the connection (1 connect, then 0)
check "keep-alive preserved across proxied requests" "10" \
	"$(curl -s -o /dev/null -o /dev/null $U/api/x $U/api/y -w '%{num_connects}')"

# a response the proxy has to frame itself must still allow reuse
check "keep-alive with chunked backend response" "10" \
	"$(curl -s -o /dev/null -o /dev/null $U/strip/chunked $U/strip/chunked \
		-w '%{num_connects}')"

# backpressure: 2 MiB uploaded to a backend that reads it slowly
check "large body to a slow backend" "$(md5sum < "$work/blob")" \
	"$(curl -s --data-binary @"$work/blob" $U/strip/slowecho | md5sum)"

# backpressure the other way: 2 MiB response to a slow client
check "large response to a slow client" "2097152" \
	"$(curl -s --limit-rate 4M $U/strip/big | wc -c)"

check "proxy prefix requires auth" "401" \
	"$(curl -s -o /dev/null -w '%{http_code}' $U/authapi/)"

check "proxy prefix accepts credentials" "200" \
	"$(curl -s -o /dev/null -w '%{http_code}' -u bob:secret $U/authapi/)"

check "credentials not forwarded to the backend" "" \
	"$(curl -s -u bob:secret $U/authapi/ | grep -E '^http-auth-')"

check "websocket tunnel" "" "$(python3 "$here/ws_client.py" $fport 2>&1)"

check "survives abrupt teardowns" "" \
	"$(python3 "$here/abort_client.py" $fport 2>&1)"

echo
echo "passed: $pass  failed: $fail"

test $fail -eq 0
