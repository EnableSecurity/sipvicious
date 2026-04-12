# svwar.py - SIPvicious extension line scanner

__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
   Copyright (C) 2007-2026 Sandro Gauci <sandro@enablesecurity.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import random
import select
import pickle
import socket
import sys
import time
import dbm
import os
from collections import deque
from datetime import datetime
from sipvicious.libs.pptable import to_string
from sipvicious.libs.svhelper import (
    __version__, numericbrute, dictionaryattack, mysendto,
    createTag, check_ipv6, makeRequest, getTag, parseHeader, resolveexitcode,
    getRealm, standardoptions, standardscanneroptions, calcloglevel,
    resumeFrom, getRange, reportBugToAuthor, packetcounter, ArgumentParser,
    parse_scan_target,
)

__prog__ = 'svwar'
__exitcode__ = 0

class TakeASip:

    def __init__(self, host='localhost', bindingip='', externalip=None, localport=5060,
                 method='REGISTER', guessmode=1, guessargs=None, selecttime=0.005,
                 sessionpath=None, compact=False, socktimeout=3, initialcheck=True,
                 enableack=False, enablecancel=None, maxlastrecvtime=15, domain=None, printdebug=False,
                 ipv6=False, port=5060):
        self.log = logging.getLogger('TakeASip')
        self.maxlastrecvtime = maxlastrecvtime
        self.sessionpath = sessionpath
        self.dbsyncs = False
        self.method = method.upper()
        self.enableack = enableack
        if enablecancel is None:
            self.enablecancel = self.method == 'INVITE'
        else:
            self.enablecancel = enablecancel
        self.cancelled = set()
        self.invite_transactions = dict()
        self.seen_final_invites = set()
        self.pending_invites = set()
        self.max_pending_invites = 32
        self.retry_extensions = deque()
        self.retry_counts = dict()
        self.retry_backoff_until = 0
        self.max_retries = 2
        if self.sessionpath is not None:
            self.resultauth = dbm.open(os.path.join(
                self.sessionpath, 'resultauth'), 'c')
            try:
                self.resultauth.sync()
                self.dbsyncs = True
                self.log.info("Db does sync")
            except AttributeError:
                self.log.info("Db does not sync")
                pass
        else:
            self.resultauth = dict()
        family = socket.AF_INET
        if ipv6:
            family = socket.AF_INET6
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.settimeout(socktimeout)
        self.bindingip = bindingip
        self.localport = localport
        self.ipv6 = ipv6
        self.originallocalport = localport
        self.rlist = [self.sock]
        self.wlist = list()
        self.xlist = list()
        self.challenges = list()
        self.realm = None
        try:
            if int(port) >= 1 and int(port) <= 65535:
                self.dsthost, self.dstport = host, int(port)
            else:
                raise ValueError
        except (ValueError, TypeError):
            self.log.error('port should strictly be an integer between 1 and 65535')
            exit(10)
        self.domain = self.dsthost
        if domain:
            self.domain = domain
        self.guessmode = guessmode
        self.guessargs = guessargs
        if self.guessmode == 1:
            self.usernamegen = numericbrute(*self.guessargs)
        elif guessmode == 2:
            self.usernamegen = dictionaryattack(self.guessargs)
        self.selecttime = selecttime
        self.compact = compact
        self.nomore = False
        self.BADUSER = None
        if self.method == 'INVITE':
            self.log.warning(
                'using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night')
        if self.sessionpath is not None:
            self.packetcount = packetcounter(50)
        self.initialcheck = initialcheck
        self.lastrecvtime = time.time()
        if externalip is None:
            self.log.debug("external ip was not set")
            if (self.bindingip != '0.0.0.0') and (len(self.bindingip) > 0):
                self.log.debug(
                    "but bindingip was set! we'll set it to the binding ip")
                self.externalip = self.bindingip
            else:
                try:
                    self.log.info(
                        "trying to get self ip .. might take a while")
                    self.externalip = socket.gethostbyname(
                        socket.gethostname())
                except socket.error:
                    self.externalip = '127.0.0.1'
        else:
            self.log.debug("external ip was set")
            self.externalip = externalip
        self.printdebug = printdebug


#   SIP response codes, also mapped to ISDN Q.931 disconnect causes.

    PROXYAUTHREQ = 'SIP/2.0 407 '
    AUTHREQ = 'SIP/2.0 401 '
    OKEY = 'SIP/2.0 200 '
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
    DECLINED = 'SIP/2.0 603 '
    INEXISTENTTRANSACTION = 'SIP/2.0 481'

    # Mapped to ISDN Q.931 codes - 88 (Incompatible destination), 95 (Invalid message), 111 (Protocol error)
    # If we get something like this, then most probably the remote device SIP stack has troubles with
    # understanding / parsing our messages (a.k.a. interopability problems).
    BADREQUEST = 'SIP/2.0 400 '

    # Mapped to ISDN Q.931 codes - 34 (No circuit available), 38 (Network out of order), 41 (Temporary failure),
    # 42 (Switching equipment congestion), 47 (Resource unavailable)
    # Should be handled in the very same way as SIP response code 404 - the prefix is not correct and we should
    # try with the next one.
    INTERNALERROR = 'SIP/2.0 500 '
    SERVICEUN = 'SIP/2.0 503 '

    def _parse_response(self, buff):
        parsed = parseHeader(buff)
        if parsed and 'code' in parsed:
            return parsed
        return dict()

    def _parse_request(self, buff):
        try:
            firstline = buff.splitlines()[0]
        except (ValueError, IndexError, AttributeError):
            return dict()
        if firstline.startswith('SIP/2.0'):
            return dict()
        parsed = parseHeader(buff, type='request')
        if not parsed or 'headers' not in parsed:
            return dict()
        parts = firstline.split(' ', 2)
        if len(parts) != 3:
            return dict()
        parsed['method'] = parts[0]
        parsed['uri'] = parts[1]
        return parsed

    def _is_provisional(self, parsed):
        try:
            return 100 <= parsed['code'] < 200
        except (KeyError, TypeError):
            return False

    def _response_fingerprint(self, buff, parsed=None):
        if parsed is None:
            parsed = self._parse_response(buff)
        try:
            firstline = buff.splitlines()[0]
        except (ValueError, IndexError, AttributeError):
            return None

        if self.method == 'INVITE' and parsed.get('code', 0) >= 200:
            headers = parsed.get('headers', dict())
            reason = ''
            if 'reason' in headers and headers['reason']:
                reason = headers['reason'][0]
            return (firstline, reason)
        return (firstline,)

    def _response_cseq_method(self, parsed):
        try:
            return parsed['headers']['cseq'][0].split()[1]
        except (KeyError, IndexError, AttributeError, TypeError):
            return None

    def _response_call_id(self, parsed):
        try:
            return parsed['headers']['call-id'][0]
        except (KeyError, IndexError, AttributeError, TypeError):
            return None

    def _final_drain_timeout(self):
        socktimeout = self.sock.gettimeout()
        if socktimeout is None:
            socktimeout = 3
        return min(socktimeout, max(self.selecttime * 20, 0.5))

    def _invite_body(self):
        addrtype = 'IP6' if self.ipv6 else 'IP4'
        mediaport = self.localport + 1000
        body = (
            'v=0\r\n'
            'o=- %s %s IN %s %s\r\n'
            's=svwar\r\n'
            'c=IN %s %s\r\n'
            't=0 0\r\n'
            'm=audio %s RTP/AVP 0 8\r\n'
            'a=rtpmap:0 PCMU/8000\r\n'
            'a=rtpmap:8 PCMA/8000\r\n'
            'a=sendrecv\r\n'
        ) % (
            random.randint(1000000, 9999999),
            random.randint(1000000, 9999999),
            addrtype,
            self.externalip,
            addrtype,
            self.externalip,
            mediaport,
        )
        return body

    def _via_branch(self, viaheader):
        if viaheader is None:
            return None
        try:
            branchpart = viaheader.split('branch=', 1)[1]
        except IndexError:
            return None
        branch = branchpart.split(';', 1)[0].strip()
        if branch.startswith('z9hG4bK-'):
            branch = branch[len('z9hG4bK-'):]
        return branch

    def _tagged_header(self, header_value, localtag):
        if localtag is None or ';tag=' in header_value.lower():
            return header_value
        return '%s;tag=%s' % (header_value, localtag.decode('utf-8', 'ignore'))

    def _request_uri(self, extension, domain=None):
        if domain is None:
            domain = self.domain
            if self.ipv6 and check_ipv6(domain):
                domain = '[' + self.domain + ']'
        if extension is None:
            return 'sip:%s' % domain
        return 'sip:%s@%s' % (extension, domain)

    def _extract_uri(self, header_value):
        if header_value is None:
            return None
        header_value = header_value.strip()
        if '<' in header_value and '>' in header_value:
            return header_value.split('<', 1)[1].split('>', 1)[0].strip()
        return header_value.split(';', 1)[0].strip()

    def _dialog_route_headers(self, parsed):
        headers = parsed.get('headers', dict())
        record_route = headers.get('record-route', list())
        return list(reversed(record_route))

    def _cache_invite_route_headers(self, parsed):
        response_call_id = self._response_call_id(parsed)
        if response_call_id not in self.invite_transactions:
            return None
        route_headers = self._dialog_route_headers(parsed)
        if route_headers:
            self.invite_transactions[response_call_id]['route_headers'] = route_headers
        return response_call_id

    def _send_dialog_request(self, method, requesturi, callid, fromaddr, toaddr,
                             cseq, branchunique=None, route_headers=None, contact=None):
        additional_headers = None
        if route_headers:
            additional_headers = [('Route', route_header) for route_header in route_headers]
        request = makeRequest(
            method,
            fromaddr,
            toaddr,
            self.domain,
            self.dstport,
            callid,
            self.externalip,
            branchunique,
            cseq,
            None,
            None,
            self.compact,
            contact=contact,
            accept=None,
            localport=self.localport,
            extension=None,
            requesturi=requesturi,
            additional_headers=additional_headers,
        )
        mysendto(self.sock, request, (self.dsthost, self.dstport))
        return request

    def _send_simple_response(self, parsed, srcaddr, code, reason):
        headers = parsed.get('headers', dict())
        required = ('via', 'to', 'from', 'call-id', 'cseq')
        if any(header not in headers or not headers[header] for header in required):
            return
        response = 'SIP/2.0 %s %s\r\n' % (code, reason)
        for via in headers['via']:
            response += 'Via: %s\r\n' % via
        response += 'To: %s\r\n' % headers['to'][0]
        response += 'From: %s\r\n' % headers['from'][0]
        response += 'Call-ID: %s\r\n' % headers['call-id'][0]
        response += 'CSeq: %s\r\n' % headers['cseq'][0]
        response += 'Content-Length: 0\r\n'
        response += '\r\n'
        mysendto(self.sock, response, srcaddr)

    def _handle_incoming_request(self, parsed, srcaddr):
        method = parsed.get('method')
        if method == 'ACK':
            return True
        if method in ('BYE', 'CANCEL'):
            self._send_simple_response(parsed, srcaddr, 200, 'OK')
            return True
        if method is not None:
            self._send_simple_response(parsed, srcaddr, 481, 'Call/Transaction Does Not Exist')
            return True
        return False

    def _send_cancel(self, parsed, extension):
        headers = parsed.get('headers', dict())
        if 'call-id' not in headers or 'via' not in headers or 'cseq' not in headers:
            return
        cid = headers['call-id'][0]
        if cid in self.cancelled:
            return
        transaction = self.invite_transactions.get(cid)
        if transaction is None:
            return
        cancelreq = self._send_dialog_request(
            'CANCEL',
            transaction['requesturi'],
            cid,
            transaction['fromaddr'],
            transaction['toaddr'],
            transaction['cseq'],
            branchunique=transaction['branchunique'],
            route_headers=transaction['route_headers'],
            contact=None,
        )
        self.log.debug('sending a CANCEL to the INVITE transaction')
        self.cancelled.add(cid)

    def _record_extension_result(self, extension, classification, log_method, message):
        existing = self.resultauth.get(extension)
        if existing == classification:
            return
        self.retry_counts.pop(extension, None)
        log_method(message)
        self.resultauth[extension] = classification
        if self.sessionpath is not None and self.dbsyncs:
            self.resultauth.sync()

    def _queue_retry(self, extension, backoff=0.05):
        if extension is None or extension in self.resultauth:
            return False
        retries = self.retry_counts.get(extension, 0)
        if retries >= self.max_retries:
            return False
        self.retry_counts[extension] = retries + 1
        self.retry_extensions.append(extension)
        self.retry_backoff_until = max(self.retry_backoff_until, time.time() + backoff)
        return True

    def _drain_responses(self):
        quiet_period = self._final_drain_timeout()
        deadline = time.time() + quiet_period
        while 1:
            remaining = deadline - time.time()
            if remaining <= 0:
                return
            r, _, _ = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                remaining
            )
            if not r:
                return
            self.getResponse()
            self.lastrecvtime = time.time()
            deadline = self.lastrecvtime + quiet_period

    def _handle_invite_final_response(self, parsed):
        response_method = self._response_cseq_method(parsed)
        if response_method not in (None, 'INVITE'):
            return True
        if parsed.get('code', 0) < 200:
            return False

        cid = self._cache_invite_route_headers(parsed)
        self.pending_invites.discard(cid)
        if cid in self.seen_final_invites:
            return True
        if not self.enableack:
            self.seen_final_invites.add(cid)
            return False

        headers = parsed.get('headers', dict())
        transaction = self.invite_transactions.get(cid)
        if transaction is None:
            return True
        if 'to' not in headers or 'cseq' not in headers:
            return True

        response_to = headers['to'][0]
        cseq = headers['cseq'][0]
        cseqnum = cseq.split()[0]
        if parsed['code'] < 300:
            requesturi = self._extract_uri(
                headers.get('contact', [None])[0]
            ) or transaction['requesturi']
            route_headers = self._dialog_route_headers(parsed)
            ackreq = self._send_dialog_request(
                'ACK',
                requesturi,
                cid,
                transaction['fromaddr'],
                response_to,
                cseqnum,
                route_headers=route_headers,
                contact=None,
            )
        else:
            requesturi = transaction['requesturi']
            route_headers = self._dialog_route_headers(parsed) or transaction['route_headers']
            ackreq = self._send_dialog_request(
                'ACK',
                requesturi,
                cid,
                transaction['fromaddr'],
                response_to,
                cseqnum,
                branchunique=transaction['branchunique'],
                route_headers=route_headers,
                contact=None,
            )
        self.log.debug('here is your ack request: %s' % ackreq)
        if parsed['code'] == 200:
            byemsg = self._send_dialog_request(
                'BYE',
                requesturi,
                cid,
                transaction['fromaddr'],
                response_to,
                str(int(transaction['cseq']) + 1),
                route_headers=route_headers,
                contact=None,
            )
            self.log.debug('sending a BYE to the 200 OK for the INVITE')
        self.seen_final_invites.add(cid)
        return False

    def createRequest(self, m, username=None, auth=None, cid=None,
                        cseq=1, fromaddr=None, toaddr=None, contact=None):
        if cid is None:
            cid = '%s' % str(random.getrandbits(32))
        branchunique = '%s' % random.getrandbits(32)
        localtag = createTag(username)
        domain = self.domain
        if self.ipv6 and check_ipv6(domain):
            domain = '[' + self.domain + ']'
        if not contact:
            contact = 'sip:%s@%s' % (username, domain)
        if not fromaddr:
            fromaddr = '"%s"<sip:%s@%s>' % (username, username, domain)
        if not toaddr:
            toaddr = '"%s"<sip:%s@%s>' % (username, username, domain)
        body = ''
        contenttype = None
        if m == 'INVITE':
            body = self._invite_body()
            contenttype = 'application/sdp'
        requesturi = self._request_uri(username, domain)
        request = makeRequest(
            m,
            fromaddr,
            toaddr,
            domain,
            self.dstport,
            cid,
            self.externalip,
            branchunique,
            cseq,
            auth,
            localtag,
            self.compact,
            contact=contact,
            localport=self.localport,
            extension=username,
            body=body,
            contenttype=contenttype,
        )
        if m == 'INVITE':
            self.invite_transactions[cid] = {
                'requesturi': requesturi,
                'branchunique': branchunique,
                'cseq': str(cseq),
                'fromaddr': self._tagged_header(fromaddr, localtag),
                'toaddr': toaddr,
                'route_headers': list(),
            }
            self.pending_invites.add(cid)
        return request

    def getResponse(self):
        # we got stuff to read off the socket
        global __exitcode__
        buff, srcaddr = self.sock.recvfrom(8192)
        if self.printdebug:
            print(srcaddr)
            print(buff)
        buff = buff.decode('utf-8')
        request = self._parse_request(buff)
        if self._handle_incoming_request(request, srcaddr):
            return
        _tmp = self._parse_response(buff)
        try:
            extension = getTag(buff).decode('utf-8', 'ignore')
        except (TypeError, AttributeError):
            self.log.error('could not decode to tag')
            __exitcode__ = resolveexitcode(20, __exitcode__)
            extension = None
        if extension is None:
            self.nomore = True
            return
        if self._is_provisional(_tmp):
            self._cache_invite_route_headers(_tmp)
            if self.enablecancel and _tmp.get('code') == 180:
                self._send_cancel(_tmp, extension)
            return
        if self.method == 'INVITE' and _tmp and 'headers' in _tmp and 'cseq' in _tmp['headers']:
            if self._handle_invite_final_response(_tmp):
                return
        try:
            firstline = buff.splitlines()[0]
        except (ValueError, IndexError, AttributeError):
            self.log.error("could not get the 1st line")
            __exitcode__ = resolveexitcode(20, __exitcode__)
            return

        response_fingerprint = self._response_fingerprint(buff, _tmp)
        if response_fingerprint != self.BADUSER:
            __exitcode__ = resolveexitcode(40, __exitcode__)
            if buff.startswith(self.PROXYAUTHREQ) \
                    or buff.startswith(self.INVALIDPASS) \
                    or buff.startswith(self.AUTHREQ):
                if self.realm is None:
                    self.realm = getRealm(buff)
                self._record_extension_result(
                    extension,
                    'reqauth',
                    self.log.info,
                    "extension '%s' exists - requires authentication" % extension,
                )
            elif buff.startswith(self.TRYING):
                pass
            elif buff.startswith(self.RINGING):
                pass
            elif buff.startswith(self.OKEY):
                self._record_extension_result(
                    extension,
                    'noauth',
                    self.log.info,
                    "extension '%s' exists - authentication not required" % extension,
                )
            elif buff.startswith(self.INTERNALERROR):
                if self._queue_retry(extension):
                    self.log.debug("Transient server error for '%s': %s" % (extension, firstline))
                else:
                    self.log.debug("Transient server error for '%s' after retries exhausted: %s" % (extension, firstline))
            else:
                self._record_extension_result(
                    extension,
                    'weird',
                    self.log.warning,
                    "extension '%s' probably exists but the response is unexpected" % extension,
                )
                self.log.debug("response: %s" % firstline)

        elif buff.startswith(self.NOTFOUND):
            self.log.debug("User '%s' not found" % extension)

        elif buff.startswith(self.INEXISTENTTRANSACTION):
            pass

        # Prefix not found, lets go to the next one. Should we add a warning
        # here???
        elif buff.startswith(self.SERVICEUN):
            pass

        elif buff.startswith(self.TRYING):
            pass

        elif buff.startswith(self.RINGING):
            pass

        elif buff.startswith(self.OKEY):
            pass

        elif buff.startswith(self.UNAVAILABLE):
            pass

        elif buff.startswith(self.DECLINED):
            pass

        elif buff.startswith(self.NOTALLOWED):
            self.log.warning("method not allowed")
            self.nomore = True

        elif buff.startswith(self.BADREQUEST):
            self.log.error(
                "Protocol / interopability error! The remote side most probably has problems with parsing your SIP messages!")
            self.nomore = True

        else:
            self.log.warning("We got an unknown response")
            self.log.error("Response: %s" % buff.__repr__())
            self.log.debug("1st line: %s" % firstline.__repr__())
            self.log.debug("Bad user: %s" % self.BADUSER.__repr__())
            self.nomore = True

    def start(self):
        global __exitcode__
        if self.bindingip == '':
            bindingip = 'any'
        else:
            bindingip = self.bindingip
        self.log.debug("binding to %s:%s" % (bindingip, self.localport))

        while 1:
            if self.localport > 65535:
                self.log.critical("Could not bind to any port")
                __exitcode__ = resolveexitcode(30, __exitcode__)
                return
            try:
                self.sock.bind((self.bindingip, self.localport))
                break
            except socket.error:
                self.log.debug("could not bind to %s" % self.localport)
                self.localport += 1

        if self.originallocalport != self.localport:
            self.log.warning("could not bind to %s:%s - some process might already be listening on this port. Listening on port %s instead" %
                          (self.bindingip, self.originallocalport, self.localport))
            self.log.info(
                "Make use of the -P option to specify a port to bind to yourself")

        # perform a test 1st .. we want to see if we get a 404
        # some other error for unknown users
        self.nextuser = random.getrandbits(32)
        data = self.createRequest(self.method, self.nextuser)
        try:
            mysendto(self.sock, data, (self.dsthost, self.dstport))
            # self.sock.sendto(data,(self.dsthost,self.dstport))
        except socket.error as err:
            self.log.error("socket error: %s" % err)
            __exitcode__ = resolveexitcode(30, __exitcode__)
            return

        # first we identify the assumed reply for an unknown extension
        gotbadresponse = False
        try:
            while 1:
                try:
                    buff, srcaddr = self.sock.recvfrom(8192)
                    if self.printdebug:
                        print(srcaddr)
                        print(buff)
                except socket.error as err:
                    self.log.error("socket error: %s" % err)
                    __exitcode__ = resolveexitcode(30, __exitcode__)
                    return

                buff = buff.decode('utf-8', 'ignore')
                parsed = self._parse_response(buff)
                if self._is_provisional(parsed):
                    self._cache_invite_route_headers(parsed)
                    if self.enablecancel and parsed.get('code') == 180 and self.method == 'INVITE':
                        self._send_cancel(parsed, str(self.nextuser))
                    gotbadresponse = True
                    continue
                if self.method == 'INVITE' and parsed and 'headers' in parsed and 'cseq' in parsed['headers']:
                    if self._handle_invite_final_response(parsed):
                        continue
                if self.enableack and self._response_cseq_method(parsed) not in (None, 'INVITE'):
                    continue
                elif buff.startswith(self.UNAVAILABLE) and self.method != 'INVITE':
                    gotbadresponse = True

                elif (buff.startswith(self.PROXYAUTHREQ)
                      or buff.startswith(self.INVALIDPASS)
                      or buff.startswith(self.AUTHREQ)) \
                        and self.initialcheck:
                    self.log.error(
                        "SIP server replied with an authentication request for an unknown extension. Set --force to force a scan.")
                    return

                else:
                    self.BADUSER = self._response_fingerprint(buff, parsed)
                    self.log.debug("Bad user = %r" % (self.BADUSER,))
                    gotbadresponse = False
                    break

        except socket.timeout:
            if gotbadresponse:
                self.log.error("The response we got was not good: %s" % buff.__repr__())
            else:
                self.log.error("No server response - are you sure that this PBX is listening? run svmap against it to find out")
                __exitcode__ = resolveexitcode(30, __exitcode__)
            return

        except (AttributeError, ValueError, IndexError):
            self.log.error("bad response .. bailing out")
            return

        except socket.error as err:
            self.log.error("socket error: %s" % err)
            __exitcode__ = resolveexitcode(30, __exitcode__)
            return

        if self.BADUSER is not None and self.BADUSER[0].startswith(self.AUTHREQ):
            self.log.warning(
                "Bad user = %s - svwar will probably not work!" % self.AUTHREQ)
        # let the fun commence
        self.log.info('Ok SIP device found')
        while 1:
            if self.nomore:
                self._drain_responses()
                return
            r, _, _ = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                self.selecttime
            )
            if r:
                # we got stuff to read off the socket
                self.getResponse()
                self.lastrecvtime = time.time()
            else:
                # check if its been a while since we had a response to prevent
                # flooding - otherwise stop
                timediff = time.time() - self.lastrecvtime
                if timediff > self.maxlastrecvtime:
                    self.nomore = True
                    self.log.warning(
                        'It has been %s seconds since we last received a response - stopping' % timediff)
                    __exitcode__ = resolveexitcode(30, __exitcode__)
                    continue

                # no stuff to read .. its our turn to send back something
                if self.method == 'INVITE' and time.time() < self.retry_backoff_until:
                    continue
                if self.method == 'INVITE' and len(self.pending_invites) >= self.max_pending_invites:
                    continue
                try:
                    if self.retry_extensions:
                        self.nextuser = self.retry_extensions.popleft()
                    else:
                        self.nextuser = next(self.usernamegen)
                except StopIteration:
                    self.nomore = True
                    continue
                except TypeError:
                    self.nomore = True
                    self.log.exception('Bad format string')
                    __exitcode__ = resolveexitcode(20, __exitcode__)

                data = self.createRequest(self.method, self.nextuser)
                try:
                    self.log.debug("sending request for %s" % self.nextuser)
                    mysendto(self.sock, data, (self.dsthost, self.dstport))

                    # self.sock.sendto(data,(self.dsthost,self.dstport))
                    if self.sessionpath is not None:
                        if next(self.packetcount):
                            try:
                                if self.guessmode == 1:
                                    pickle.dump(self.nextuser, open(os.path.join(
                                        self.sessionpath, 'lastextension.pkl'), 'wb+'))
                                    self.log.debug(
                                        'logged last extension %s' % self.nextuser)

                                elif self.guessmode == 2:
                                    pickle.dump(self.guessargs.tell(), open(
                                        os.path.join(self.sessionpath, 'lastextension.pkl'), 'wb+'))
                                    self.log.debug('logged last position %s' % self.guessargs.tell())

                            except IOError:
                                self.log.warning('could not log the last extension scanned')
                                __exitcode__ = resolveexitcode(20, __exitcode__)

                except socket.error as err:
                    __exitcode__ = resolveexitcode(30, __exitcode__)
                    self.log.error("socket error: %s" % err)
                    break


def main():
    global __exitcode__
    usage = "usage: %prog [options] target\r\n"
    usage += "examples:\r\n"
    usage += "%prog -e100-999 udp://10.0.0.1:5080\r\n"
    usage += "%prog -d dictionary.txt 10.0.0.2\r\n"
    parser = ArgumentParser(usage, version="%prog v" + str(__version__) + __GPL__)
    parser.add_option("-p", "--port", dest="port", default="5060",
        help="Destination port of the SIP device - eg -p 5060", metavar="PORT")
    parser = standardoptions(parser)
    parser = standardscanneroptions(parser)
    parser.add_option("-d", "--dictionary", dest="dictionary", type="string", metavar="DICTIONARY",
        help="specify a dictionary file with possible extension names or - for stdin")
    parser.add_option("-m", "--method", dest="method", type="string",
        help="specify a request method. The default is REGISTER. Other possible methods are OPTIONS and INVITE",
        default="REGISTER",	metavar="OPTIONS")
    parser.add_option("-e", "--extensions", dest="range", default='100-999',
        help="specify an extension or extension range\r\nexample: -e 100-999,1000-1500,9999",
        metavar="RANGE")
    parser.add_option("-z", "--zeropadding", dest="zeropadding", type="int",
        help="the number of zeros used to padd the username." \
            "the options \"-e 1-9999 -z 4\" would give 0001 0002 0003 ... 9999",
          default=0, metavar="PADDING")
    parser.add_option('--force', dest="force", action="store_true",
        default=False, help="Force scan, ignoring initial sanity checks.")
    parser.add_option('--disablecancel', dest="disablecancel", action="store_true",
        default=False, help="For INVITE scans, do not send CANCEL after 180 Ringing")
    parser.add_option('--template', '-T', action="store", dest="template",
        help="A format string which allows us to specify a template for the extensions. " \
            "example sipvicious_svwar -e 1-999 --template=\"123%#04i999\" would scan between 1230001999 to 1230999999\"")
    parser.add_option('--enabledefaults', '-D', action="store_true", dest="defaults",
        default=False, help="Scan for default / typical extensions such as " \
            "1000,2000,3000 ... 1100, etc. This option is off by default." \
            "Use --enabledefaults to enable this functionality")
    parser.add_option('--maximumtime', action='store', dest='maximumtime', type="int",
        default=10, help="Maximum time in seconds to keep sending requests without receiving a response back")
    parser.add_option('--domain', dest="domain",
        help="force a specific domain name for the SIP message, eg. -d example.org")
    parser.add_option("--debug", dest="printdebug",
        help="Print SIP messages received", default=False, action="store_true")
    parser.add_option('-6', dest="ipv6", action="store_true", help="scan an IPv6 address")

    options, args = parser.parse_args()

    exportpath = None
    logging.basicConfig(level=calcloglevel(options))
    logging.debug('started logging')

    if options.force:
        initialcheck = False
    else:
        initialcheck = True

    if options.template is not None:
        try:
            options.template % 1
        except TypeError:
            parser.error("The format string template is not correct. Please provide an appropiate one", 10)

    if options.resume is not None:
        exportpath = os.path.join(os.path.expanduser(
            '~'), '.sipvicious', __prog__, options.resume)
        if os.path.exists(os.path.join(exportpath, 'closed')):
            parser.error("Cannot resume a session that is complete", 20)

        if not os.path.exists(exportpath):
            parser.error('A session with the name %s was not found' % options.resume, 20)

        optionssrc = os.path.join(exportpath, 'options.pkl')
        previousresume = options.resume
        previousverbose = options.verbose
        options, args = pickle.load(open(optionssrc, 'rb'), encoding='bytes')
        options.resume = previousresume
        options.verbose = previousverbose

    elif options.save is not None:
        exportpath = os.path.join(os.path.expanduser(
            '~'), '.sipvicious', __prog__, options.save)

    if len(args) < 1:
        parser.error("Please provide at least one hostname which talks SIP!", 10)
    elif len(args) > 1:
        parser.error("Currently svwar supports exactly one hostname.", 10)

    destport = options.port
    try:
        host, destport = parse_scan_target(args[0], destport)
    except ValueError as exc:
        parser.error(str(exc), 20)

    if options.dictionary is not None:
        guessmode = 2
        if options.dictionary == "-":
            dictionary = sys.stdin
        else:
            try:
                dictionary = open(options.dictionary, 'r', encoding='utf-8', errors='ignore')
            except IOError:
                parser.error("could not open %s" % options.dictionary, 20)

            if options.resume is not None:
                lastextensionsrc = os.path.join(exportpath, 'lastextension.pkl')
                previousposition = pickle.load(open(lastextensionsrc, 'rb'), encoding='bytes')
                dictionary.seek(previousposition)

        guessargs = dictionary

    else:
        guessmode = 1
        if options.resume is not None:
            lastextensionsrc = os.path.join(exportpath, 'lastextension.pkl')
            try:
                previousextension = pickle.load(open(lastextensionsrc, 'rb'), encoding='bytes')
            except IOError:
                parser.error('Could not read from %s' % lastextensionsrc, 20)

            logging.debug('Previous range: %s' % options.range)
            options.range = resumeFrom(previousextension, options.range)
            logging.debug('New range: %s' % options.range)
            logging.info('Resuming from %s' % previousextension)

        extensionstotry = getRange(options.range)
        guessargs = (extensionstotry, options.zeropadding, options.template, options.defaults)

    if options.save is not None:
        if options.resume is None:
            exportpath = os.path.join(os.path.expanduser(
                '~'), '.sipvicious', __prog__, options.save)
            if os.path.exists(exportpath):
                parser.error('we found a previous scan with the same name. Please choose a new session name', 20)

            logging.debug('creating an export location %s' % exportpath)
            try:
                os.makedirs(exportpath, mode=0o700)
            except OSError:
                parser.error('could not create the export location %s' % exportpath, 20)

            optionsdst = os.path.join(exportpath, 'options.pkl')
            logging.debug('saving options to %s' % optionsdst)
            pickle.dump([options, args], open(optionsdst, 'wb+'))

    if options.autogetip:
        tmpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmpsocket.connect(("msn.com", 80))
        options.externalip = tmpsocket.getsockname()[0]
        tmpsocket.close()

    enableack = False
    enablecancel = False
    if options.method.upper() == 'INVITE':
        enableack = True
        enablecancel = not options.disablecancel

    sipvicious = TakeASip(
        host,
        port=destport,
        selecttime=options.selecttime,
        method=options.method,
        compact=options.enablecompact,
        guessmode=guessmode,
        guessargs=guessargs,
        sessionpath=exportpath,
        initialcheck=initialcheck,
        externalip=options.externalip,
        enableack=enableack,
        enablecancel=enablecancel,
        maxlastrecvtime=options.maximumtime,
        localport=options.localport,
        domain=options.domain,
        printdebug=options.printdebug,
        ipv6=options.ipv6,
    )
    start_time = datetime.now()
    logging.info("scan started at %s" % str(start_time))
    logging.info("start your engines")
    try:
        sipvicious.start()
        if exportpath is not None:
            open(os.path.join(exportpath, 'closed'), 'w').close()

    except KeyboardInterrupt:
        logging.warning('caught your control^c - quiting')

    except Exception as err:
        logging.critical(
            "Got unhandled exception : %s", err.__str__())
        reportBugToAuthor(err)
    if options.save is not None and sipvicious.nextuser is not None:
        lastextensiondst = os.path.join(exportpath, 'lastextension.pkl')
        logging.debug('saving state to %s' % lastextensiondst)
        try:
            if guessmode == 1:
                pickle.dump(sipvicious.nextuser, open(
                    os.path.join(exportpath, 'lastextension.pkl'), 'wb'))
                logging.debug('logged last extension %s' % sipvicious.nextuser)
            elif guessmode == 2:
                pickle.dump(sipvicious.guessargs.tell(), open(
                    os.path.join(exportpath, 'lastextension.pkl'), 'wb'))
                logging.debug('logged last position %s' % sipvicious.guessargs.tell())
        except IOError:
            logging.warning('could not log the last extension scanned')
            __exitcode__ = resolveexitcode(20, __exitcode__)

    # display results
    if not options.quiet:
        lenres = len(sipvicious.resultauth)
        if lenres > 0:
            logging.info("we have %s extensions" % lenres)
            if (lenres < 400 and options.save is not None) or options.save is None:
                labels = ('Extension', 'Authentication')
                rows = list()

                try:
                    for k in sipvicious.resultauth.keys():
                        rows.append((k.decode(), sipvicious.resultauth[k].decode()))
                except AttributeError:
                    for k in sipvicious.resultauth.keys():
                        rows.append((k, sipvicious.resultauth[k]))

                print(to_string(rows, header=labels))

            else:
                logging.warning("too many to print - use svreport for this")

        else:
            logging.warning("found nothing")

    end_time = datetime.now()
    total_time = end_time - start_time
    logging.info("Total time: %s" % total_time)
    sys.exit(__exitcode__)

if __name__ == '__main__':
    main()
