#!/usr/bin/env python3
"""Check the actual UA parser and close-policy switch using a small C harness.
Run: python3 tests/test-safari.py
The header helpers/transport are stubs; this is not a full HTTP protocol test.
Requires Python 3 and a host C compiler. No network or device access.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def function(text, start):
    pos = text.index(start)
    brace = text.index('{', pos)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[pos:end]


def main():
    source = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        client = (source / 'client.c').read_text()
        enum = re.search(r'enum http_user_agent\s*\{[^}]+\};', (source / 'uhttpd.h').read_text()).group()
        helper = function(client, 'static bool ua_version_at_least(') + '\n' + function(client, 'static bool webkit_keepalive_supported(')
        parser = function(client, 'static void client_parse_header(')
        policy = function(client, 'switch(r->ua)')
        preamble = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#define UH_LIMIT_HEADER_COUNT 100
#define UH_LIMIT_HEADER_BYTES 32768
#define CHUNKED_FIRST 1
#define uh_is_tchar(c) (isalnum((unsigned char)(c)) || (c) == '-')
#define uh_is_ctl(c) (((unsigned char)(c) < 32 && (c) != '\t') || (unsigned char)(c) == 127)
#define UH_HTTP_MSG_POST 1
#define CLIENT_STATE_DATA 1
#define CLIENT_STATE_DONE 2
#define CLIENT_STATE_HEADER 3
struct http_request { int ua, method, content_length, header_count, header_bytes; bool connection_close, expect_cont, transfer_chunked; };
struct client { struct http_request request; int timeout, state, hdr; };
#define uloop_timeout_cancel(x) ((void)(x))
#define blobmsg_add_string(x,y,z) ((void)(x), (void)(y), (void)(z))
#define uh_header_error(x,y,z) ((void)(x), (void)(y), (void)(z))
static char *uh_split_header(char *data, size_t len) {
    (void)len;
    char *p = strchr(data, ':');
    if (!p) return NULL;
    *p++ = 0;
    while (*p == ' ') p++;
    return p;
}
'''
        harness = preamble + enum + '\nstatic void client_header_complete(struct client *cl) {\nstruct http_request *r = &cl->request;\n' + policy + '\n}\n' + helper + '\n' + parser
        harness += r'''
static void check(const char *ua, int expected, bool prior_close, bool explicit_close, bool post, bool want_close) {
    struct client cl = {0};
    char line[4096];
    cl.request.connection_close = prior_close;
    cl.request.method = post ? UH_HTTP_MSG_POST : 0;
    snprintf(line, sizeof(line), "User-Agent: %s", ua);
    client_parse_header(&cl, line, strlen(line) + 2);
    assert(cl.request.ua == expected);
    if (explicit_close) {
        strcpy(line, "Connection: close");
        client_parse_header(&cl, line, strlen(line) + 2);
    }
    client_header_complete(&cl);
    assert(cl.request.connection_close == want_close);
}
int main(void) {
'''
        prefix = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 '
        suffix = ' Mobile/15E148 Safari/604.1'
        cases = []
        for version in ['27.0', '27.0.1', '27.1', '28.0', '100.0']:
            cases.append((prefix+'Version/'+version+suffix, 'UH_UA_WEBKIT_KEEPALIVE', False))
        for version in ['26.9', '17.6', '', '27', '27.', '27..0', '27.0x', '-27.0', '999999999999999999999.0']:
            cases.append((prefix+'Version/'+version+suffix, 'UH_UA_SAFARI', True))
        cases += [(prefix+suffix, 'UH_UA_SAFARI', True),
                  (prefix+'XVersion/27.0'+suffix, 'UH_UA_SAFARI', True),
                  (prefix+'Version/27.0 Version/28.0'+suffix, 'UH_UA_SAFARI', True),
                  ('Mac OS X Version/27.0 Safari/604.1', 'UH_UA_SAFARI', True)]
        for alt in ['CriOS/150.0', 'FxiOS/150.0', 'EdgiOS/150.0', 'OPiOS/150.0']:
            cases.append((prefix+alt+' Version/27.0'+suffix, 'UH_UA_SAFARI', True))
        cases.append((prefix+'Chrome/150.0 Version/27.0'+suffix, 'UH_UA_CHROME', False))
        def chrome(version='153.0.8010.24', ios='27_0_0'):
            return ('Mozilla/5.0 (iPhone; CPU iPhone OS '+ios+' like Mac OS X) '
                    'AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/'+version+suffix)
        for version, ios in [('153.0.8010.24','27_0_0'), ('153.0.8010.25','27_0'),
                             ('153.1.0.0','27_1'), ('154.0.0.0','28_0')]:
            cases.append((chrome(version,ios), 'UH_UA_WEBKIT_KEEPALIVE', False))
        for version in ['152.9.99999.99','153.0.8010.23','153.0.8009.99',
                        '153','153.0','153.0.8010','153.0.8010.24.1',
                        '153..8010.24','153.0.8010.24x','9999999.0.0.0','-153.0.8010.24']:
            cases.append((chrome(version), 'UH_UA_SAFARI', True))
        for ios in ['26_9_9','18_7','27','27_','27__0','27_0x','9999999_0','27_0_0_0_0']:
            cases.append((chrome(ios=ios), 'UH_UA_SAFARI', True))
        for ua in [chrome().replace('CPU iPhone OS 27_0_0', 'CPU iPhone OS'),
                   chrome().replace('(iPhone;', '(iPad;'),
                   chrome().replace('CPU iPhone OS 27_0_0', 'CPU OS 27_0_0'),
                   chrome()+' CriOS/154.0.0.0',
                   chrome()+' CPU iPhone OS 28_0',
                   chrome()+' FxiOS/153.0',
                   chrome(ios='26_0')+' Version/27.0',
                   chrome('152.0.0.0')+' Version/27.0',
                   chrome().replace('CriOS/', 'XCriOS/')]:
            cases.append((ua, 'UH_UA_SAFARI', True))
        for ua, classification, closes in cases:
            harness += f'check({json.dumps(ua)}, {classification}, false, false, false, {str(closes).lower()});\n'
        modern = json.dumps(prefix+'Version/27.0'+suffix)
        harness += f'check({modern}, UH_UA_WEBKIT_KEEPALIVE, true, false, false, true);\n'  # HTTP/1.0/global close already set
        harness += f'check({modern}, UH_UA_WEBKIT_KEEPALIVE, false, true, false, true);\n'
        harness += f'check({modern}, UH_UA_WEBKIT_KEEPALIVE, false, false, true, false);\n'
        crios = json.dumps(chrome())
        harness += f'check({crios}, UH_UA_WEBKIT_KEEPALIVE, true, false, false, true);\n'
        harness += f'check({crios}, UH_UA_WEBKIT_KEEPALIVE, false, true, false, true);\n'
        harness += f'check({crios}, UH_UA_WEBKIT_KEEPALIVE, false, false, true, false);\n'
        harness += 'check("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", UH_UA_MSIE_OLD, false, false, true, true);\n'
        harness += 'check("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", UH_UA_MSIE_OLD, false, false, false, false);\n'
        harness += f'puts("Passed {len(cases)+8} actual-parser/policy checks"); return 0; }}\n'
        (work / 'test.c').write_text(harness)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c99', '-Wall', '-Wextra', '-Werror', '-Wno-implicit-fallthrough', str(work/'test.c'), '-o', str(work/'test')], check=True)
        subprocess.run([str(work/'test')], check=True)

if __name__ == '__main__':
    main()
