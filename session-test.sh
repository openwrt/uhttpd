#!/usr/bin/env bash
. /usr/share/libubox/jshn.sh

json_load "$(ubus call session create)"
json_get_var sid sid


json_init
json_add_string sid "$sid"
json_add_array "objects"
json_add_array ""
json_add_string "" "session"
json_add_string "" "list"
json_close_array
json_close_array

ubus call session grant "$(json_dump)"

echo "Session: $sid"
wget -O- "http://localhost:8080/ubus/$sid/session/list"
