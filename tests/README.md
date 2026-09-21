# Safari keep-alive checks

Related report: https://github.com/openwrt/uhttpd/issues/42

```sh
python3 tests/test-safari.py
python3 tests/runtime-safari.py /path/to/built/uhttpd
```

The first command compiles the actual UA parser and close-policy switch in a
small C harness. It checks 28 cases covering Safari 27+, older/malformed
versions, known alternative iOS-browser tokens, explicit/pre-existing close
and old IE POST behavior. Transport/header helper stubs make it a focused
compatibility test, not a general HTTP parser/security test. It needs Python 3
and a host C compiler.

The second command starts the built server on a free IPv4 loopback port and
serves a temporary static file. It tests actual same-socket requests, ETag 304,
Safari 26/27/28 classification, desktop Chrome and CriOS behavior, explicit
close, HTTP/1.0 and legacy IE POST close. It stops the process afterwards and
never contacts a modem. It needs Python 3 and the binary's runtime libraries.

The patch was built against base 373145f72c884c36a2b16f7f47e74ffae06bd754,
libubox e7608b69283d919d031d13cc8e21692503f5dbea and the ustream-ssl header from
cea28c5bc43ae80c3531c98f4e4dc67b7dcf0ebb, on Linux amd64 with TLS support ON
and Lua/ubus/ucode plugins OFF. A TLS-disabled configuration exposed an
unrelated pre-existing unguarded `cl->ssl` reference; this patch does not alter
that code or claim validation of TLS-disabled builds.

## Hardware evidence versus patch validation

The issue records separate Safari 27 and CriOS 153.0.8010.24 off/on/off
experiments on iOS 27.0. Those used the older 3abcc891 source shipped by the
WAS-110 and a process-local switch skipping only Safari's forced-close decision.
They did not run this version parser or current master on the device.

Safari's minimum is proposed as product `Version/27.0` or greater, matching the
browser tested. Future versions are a compatibility policy, not measured
coverage. The enum name `UH_UA_SAFARI_27_PLUS` is deliberately explicit about
that range. Existing close decisions and the older-browser workaround remain.

CriOS also improved substantially in the hardware experiment. This initial
patch still excludes it, because its application version does not establish
its WebKit version; a separate conservative eligibility policy needs agreement.
Desktop Safari, older iOS combinations, current-master device behavior,
long-duration stability and the full plugin build matrix remain unverified.
