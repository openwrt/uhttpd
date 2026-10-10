# HTTP keep-alive regression check

Run `python3 tests/test-keepalive.py /path/to/built/uhttpd`.
The test starts temporary loopback servers and serves a temporary static file;
it does not contact a modem or require third-party Python modules.

Eight UA cases (Safari, CriOS, older versions, desktop Chrome, old IE, unknown,
and absent) exercise GET/POST socket reuse and ETag 304. Every case must still
honor explicit close, HTTP/1.0 and `-k 0`. Idle expiry and reconnection are also
checked. UA strings simulate header policy; they do not test obsolete browsers.

The same checks run against current upstream and the 3abcc891 source backport.
Linux builds use TLS support with Lua/ubus/ucode plugins disabled; these HTTP
checks do not establish TLS/plugin behavior. Earlier device experiments and
their limitations are recorded in https://github.com/openwrt/uhttpd/issues/42.
Removing the unused request field requires rebuilding any external modules
against the updated headers rather than reusing old binary modules.
