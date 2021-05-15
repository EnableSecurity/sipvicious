# svwar.py - SIPvicious extension line scanner

__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
   Copyright (C) 2007-2021 Sandro Gauci <sandro@enablesecurity.com>

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
import traceback
from datetime import datetime
from urllib.parse import urlparse
from sipvicious.libs.pptable import to_string
from sipvicious.libs.svhelper import (
    __version__, numericbrute, dictionaryattack, mysendto,
    createTag, check_ipv6, makeRequest, getTag, parseHeader, resolveexitcode,
    getRealm, standardoptions, standardscanneroptions, calcloglevel,
    resumeFrom, getRange, reportBugToAuthor, packetcounter, ArgumentParser
)

__prog__ = 'svwar'
__exitcode__ = 0

class TakeASip:

    def __init__(self, host='localhost', bindingip='', externalip=None, localport=5060,
                 method='REGISTER', guessmode=1, guessargs=None, selecttime=0.005,
                 sessionpath=None, compact=False, socktimeout=3, initialcheck=True,
                 enableack=False, maxlastrecvtime=15, domain=None, printdebug=False,
                 ipv6=False, port=5060):
        self.log = logging.getLogger('TakeASip')
        self.maxlastrecvtime = maxlastrecvtime
        self.sessionpath = sessionpath
        self.dbsyncs = False
        self.enableack = enableack
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
        self.method = method.upper()
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
    SERVICEUN = 'SIP/2.0 503 '

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
            extension=username
        )
        return request

    def getResponse(self):
        # we got stuff to read off the socket
        global __exitcode__
        buff, srcaddr = self.sock.recvfrom(8192)
        if self.printdebug:
            print(srcaddr)
            print(buff)
        buff = buff.decode('utf-8')
        try:
            extension = getTag(buff).decode('utf-8', 'ignore')
        except (TypeError, AttributeError):
            self.log.error('could not decode to tag')
            __exitcode__ = resolveexitcode(20, __exitcode__)
            extension = None
        if extension is None:
            self.nomore = True
            return
        try:
            firstline = buff.splitlines()[0]
        except (ValueError, IndexError, AttributeError):
            self.log.error("could not get the 1st line")
            __exitcode__ = resolveexitcode(20, __exitcode__)
            return
        if self.enableack:
            # send an ack to any responses which match
            _tmp = parseHeader(buff)
            if not (_tmp and 'code' in _tmp):
                return
            if 699 > _tmp['code'] >= 200:
                self.log.debug('will try to send an ACK response')
                if 'headers' not in _tmp:
                    self.log.debug('no headers?')
                    __exitcode__ = resolveexitcode(20, __exitcode__)
                    return
                if 'from' not in _tmp['headers']:
                    self.log.debug('no from?')
                    __exitcode__ = resolveexitcode(20, __exitcode__)
                    return
                if 'cseq' not in _tmp['headers']:
                    self.log.debug('no cseq')
                    __exitcode__ = resolveexitcode(20, __exitcode__)
                    return
                if 'call-id' not in _tmp['headers']:
                    self.log.debug('no caller id')
                    __exitcode__ = resolveexitcode(20, __exitcode__)
                    return

                try:
                    # _tmp['headers']['from'][0].split('"')[1]
                    getTag(buff)
                except IndexError:
                    self.log.warning('could not parse the from address %s' % _tmp['headers']['from'])
                    __exitcode__ = resolveexitcode(20, __exitcode__)

                cseq = _tmp['headers']['cseq'][0]
                cseqmethod = cseq.split()[1]
                if 'INVITE' == cseqmethod:
                    cid = _tmp['headers']['call-id'][0]
                    fromaddr = _tmp['headers']['from'][0]
                    toaddr = _tmp['headers']['to'][0]
                    ackreq = self.createRequest(
                        'ACK',
                        cid=cid,
                        cseq=cseq.replace(cseqmethod, ''),
                        fromaddr=fromaddr,
                        toaddr=toaddr,
                    )
                    self.log.debug('here is your ack request: %s' % ackreq)
                    mysendto(self.sock, ackreq, (self.dsthost, self.dstport))
                    # self.sock.sendto(ackreq,(self.dsthost,self.dstport))
                    if _tmp['code'] == 200:
                        byemsg = self.createRequest(
                            'BYE',
                            cid=cid,
                            cseq='2',
                            fromaddr=fromaddr,
                            toaddr=toaddr,
                        )
                        self.log.debug('sending a BYE to the 200 OK for the INVITE')
                        mysendto(self.sock, byemsg,(self.dsthost, self.dstport))

        if firstline != self.BADUSER:
            __exitcode__ = resolveexitcode(40, __exitcode__)
            if buff.startswith(self.PROXYAUTHREQ) \
                    or buff.startswith(self.INVALIDPASS) \
                    or buff.startswith(self.AUTHREQ):
                if self.realm is None:
                    self.realm = getRealm(buff)
                self.log.info("extension '%s' exists - requires authentication" % extension)
                self.resultauth[extension] = 'reqauth'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()
            elif buff.startswith(self.TRYING):
                pass
            elif buff.startswith(self.RINGING):
                pass
            elif buff.startswith(self.OKEY):
                self.log.info(
                    "extension '%s' exists - authentication not required" % extension)
                self.resultauth[extension] = 'noauth'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()
            else:
                self.log.warning(
                    "extension '%s' probably exists but the response is unexpected" % extension)
                self.log.debug("response: %s" % firstline)
                self.resultauth[extension] = 'weird'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()

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
                if buff.startswith(self.TRYING) \
                        or buff.startswith(self.RINGING) \
                        or buff.startswith(self.UNAVAILABLE):
                    gotbadresponse = True

                elif (buff.startswith(self.PROXYAUTHREQ)
                      or buff.startswith(self.INVALIDPASS)
                      or buff.startswith(self.AUTHREQ)) \
                        and self.initialcheck:
                    self.log.error(
                        "SIP server replied with an authentication request for an unknown extension. Set --force to force a scan.")
                    return

                else:
                    self.BADUSER = buff.splitlines()[0]
                    self.log.debug("Bad user = %s" % self.BADUSER)
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

        if self.BADUSER.startswith(self.AUTHREQ):
            self.log.warning(
                "Bad user = %s - svwar will probably not work!" % self.AUTHREQ)
        # let the fun commence
        self.log.info('Ok SIP device found')
        while 1:
            if self.nomore:
                while 1:
                    try:
                        self.getResponse()
                    except socket.timeout:
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
                try:
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
    parser.add_option('--template', '-T', action="store", dest="template",
        help="A format string which allows us to specify a template for the extensions. " \
            "example svwar.py -e 1-999 --template=\"123%#04i999\" would scan between 1230001999 to 1230999999\"")
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
    parsed = urlparse(args[0])

    if not parsed.scheme:
        host = args[0]

    else:
        if any(parsed.scheme == i for i in ('tcp', 'tls', 'ws', 'wss')):
            parser.error('Protocol scheme %s is not supported in SIPVicious OSS' % parsed.scheme, 20)

        if parsed.scheme != 'udp':
            parser.error('Invalid protocol scheme: %s' % parsed.scheme, 20)

        if ':' not in parsed.netloc:
            parser.error('You have to supply hosts in format of scheme://host:port when using newer convention.', 10)

        if int(destport) != 5060:
            parser.error('You cannot supply additional -p when already including a port in URI. Please use only one.', 20)

        host = parsed.netloc.split(':')[0]
        destport = parsed.netloc.split(':')[1]

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
    if options.method.upper() == 'INVITE':
        enableack = True

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
        if options.reportBack:
            logging.critical(
                "Got unhandled exception : %s\nSending report to author" % err.__str__())
            reportBugToAuthor(traceback.format_exc())
        else:
            logging.critical(
                "Unhandled exception - please run same command with the -R option to send me an automated report")
            pass
        logging.exception("Exception")
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
