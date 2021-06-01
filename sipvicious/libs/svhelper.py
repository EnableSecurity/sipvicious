#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#   Helper.py keeps the rest of the tools clean - part of SIPVicious tools
#   Copyright (C) 2007-2021 Sandro Gauci <sandro@enablesecurity.com>
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


__author__ = "Sandro Gauci <sandro@enablesecurity.com>"
__version__ = '0.3.4'


import re
import sys
import uuid
import os
import dbm
import socket
import random
import struct
import shutil
import optparse
import logging
from random import getrandbits
from urllib.request import urlopen
from urllib.error import URLError
from urllib.parse import urlencode
from binascii import Error as b2aerr
from .pptable import to_string
from binascii import b2a_hex, a2b_hex, hexlify

if sys.hexversion < 0x03060000:
    sys.stderr.write(
        "Please update to python 3.6 or greater to run SIPVicious\r\n")
    sys.exit(1)


class ArgumentParser(optparse.OptionParser):
    def error(self, message, code=10):
        print(self.get_usage())
        sys.stderr.write('error: %s\r\n' % message)
        sys.exit(code)


def standardoptions(parser):
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False, help="Quiet mode")
    parser.add_option("-P", "--localport", dest="localport", default=5060, type="int",
                      help="Source port for our packets", metavar="PORT")
    parser.add_option("-x", "--externalip", dest="externalip",
                      help="IP Address to use as the external ip. Specify this if you have multiple interfaces or if you are behind NAT", metavar="IP")
    parser.add_option("-b", "--bindingip", dest="bindingip", default='',
                      help="By default we bind to all interfaces. This option overrides that and binds to the specified ip address")
    parser.add_option("-t", "--timeout", dest="selecttime", type="float", default=0.005,
                      help="This option allows you to trottle the speed at which packets are sent. Change this if you're losing packets. For example try 0.5.",
                      metavar="SELECTTIME")
    parser.add_option("-R", "--reportback", dest="reportBack", default=False, action="store_true",
                      help="Send the author an exception traceback. Currently sends the command line parameters and the traceback",
                      )
    parser.add_option("-A", "--autogetip", dest="autogetip", default=False, action="store_true",
                      help="Automatically get the current IP address. This is useful when you are not getting any responses back due to SIPVicious not resolving your local IP.")
    return parser


def standardscanneroptions(parser):
    parser.add_option("-s", "--save", dest="save",  metavar="NAME",
                      help="save the session. Has the benefit of allowing you to resume a previous scan and allows you to export scans")
    parser.add_option("--resume", dest="resume", help="resume a previous scan", metavar="NAME")
    parser.add_option("-c", "--enablecompact", dest="enablecompact", default=False, action="store_true",
                      help="enable compact mode. Makes packets smaller but possibly less compatible")
    return parser


def resolveexitcode(newint, existingcode):
    if existingcode > newint:
        return existingcode
    return newint


def calcloglevel(options):
    logginglevel = 30
    if options.verbose is not None:
        if options.verbose >= 3:
            logginglevel = 10
        else:
            logginglevel = 30 - (options.verbose * 10)
    if options.quiet:
        logginglevel = 50
    return logginglevel


def bindto(bindingip, startport, s):
    log = logging.getLogger('bindto')
    localport = startport
    log.debug("binding to %s:%s" % (bindingip, localport))
    while 1:
        if localport > 65535:
            log.critical("Could not bind to any port")
            return
        try:
            s.bind((bindingip, localport))
            break
        except socket.error:
            log.debug("could not bind to %s" % localport)
            localport += 1
    if startport != localport:
        log.warn("could not bind to %s:%s - some process might already be listening on this port. Listening on port %s instead" %
                 (bindingip, startport, localport))
        log.info("Make use of the -P option to specify a port to bind to yourself")
    return localport, s


def getRange(rangestr):
    _tmp1 = rangestr.split(',')
    numericrange = list()
    for _tmp2 in _tmp1:
        _tmp3 = _tmp2.split('-', 1)
        if len(_tmp3) > 1:
            if not (_tmp3[0].isdigit() or _tmp3[1].isdigit()):
                raise ValueError("the ranges need to be digits")
            startport, endport = list(map(int, [_tmp3[0], _tmp3[1]]))
            endport += 1
            numericrange.append(range(startport, endport))
        else:
            if not _tmp3[0].isdigit():
                raise ValueError("the ranges need to be digits")
            singleport = int(_tmp3[0])
            numericrange.append(anotherxrange(singleport, singleport + 1))
    return numericrange


def numericbrute(rangelist, zeropadding=0, template=None, defaults=False, staticbrute=[]):
    """numericbrute gives a yield generator. accepts either zeropadding or template as optional argument"""
    for statictry in staticbrute:
        yield(statictry)
    if defaults:
        for i in range(1000, 9999, 100):
            yield('%04i' % i)

        for i in range(1001, 9999, 100):
            yield('%04i' % i)

        for i in range(0, 9):
            for l in range(1, 8):
                yield(('%s' % i) * l)

        for i in range(100, 999):
            yield('%s' % i)

        for i in range(10000, 99999, 100):
            yield('%04i' % i)

        for i in range(10001, 99999, 100):
            yield('%04i' % i)

        for i in ['1234', '2345', '3456', '4567', '5678', '6789', '7890', '0123']:
            yield(i)

        for i in ['12345', '23456', '34567', '45678', '56789', '67890', '01234']:
            yield(i)

    if zeropadding > 0:
        format = '%%0%su' % zeropadding
    elif template is not None:
        format = template
    else:
        format = '%u'
    # format string test
    format % 1
    for x in rangelist:
        for y in x:
            r = format % y
            yield(r)


def dictionaryattack(dictionaryfile):
    while 1:
        r = dictionaryfile.readline()
        if len(r) == 0:
            break
        yield(r.strip())
    dictionaryfile.flush()
    dictionaryfile.close()


class genericbrute:
    pass


def getNonce(pkt):
    nonceRE = 'nonce="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None


def getOpaque(pkt):
    nonceRE = 'opaque="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None


def getAlgorithm(pkt):
    nonceRE = 'algorithm=(.+?)[,\r]'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0].lower())
    return None


def getQop(pkt):
    nonceRE = 'qop="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None


def getRealm(pkt):
    nonceRE = 'realm="(.+?)"'
    _tmp = re.findall(nonceRE, pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None


def getCID(pkt):
    cidRE = 'Call-ID: ([:a-zA-Z0-9]+)'
    _tmp = re.findall(cidRE, pkt, re.I)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None


def mysendto(sock, data, dst):
    while data:
        # SIP RFC states the default serialized encoding is utf-8
        bytes_sent = sock.sendto(bytes(data[:8192], 'utf-8'), dst)
        data = data[bytes_sent:]


def parseSDP(buff):
    r = dict()
    for line in buff.splitlines():
        _tmp = line.split('=', 1)
        if len(_tmp) == 2:
            k, v = _tmp
            if k not in r:
                r[k] = list()
            r[k].append(v)
    return r


def getAudioPort(sdp):
    if 'm' in sdp:
        for media in sdp['m']:
            if media.startswith('audio'):
                mediasplit = media.split()
                if len(mediasplit) > 2:
                    port = mediasplit[1]
                    return port


def getAudioIP(sdp):
    if 'c' in sdp:
        for connect in sdp['c']:
            if connect.startswith('IN IP4'):
                connectsplit = connect.split()
                if len(connectsplit) > 2:
                    ip = connectsplit[2]
                    return ip


def getSDP(buff):
    sip = parseHeader(buff)
    if 'body' in sip:
        body = sip['body']
        sdp = parseSDP(body)
        return sdp


def getAudioIPFromBuff(buff):
    sdp = getSDP(buff)
    if sdp is not None:
        return getAudioIP(sdp)


def getAudioPortFromBuff(buff):
    sdp = getSDP(buff)
    if sdp is not None:
        return getAudioPort(sdp)


def parseHeader(buff, type='response'):
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header, body = buff.split(SEP, 1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)

    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ', 2)
            if len(_t) == 3:
                _, _code, _ = _t
            else:
                log.warn('Could not parse the first header line: %s' % _t.__repr__())
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ', 2)
            #if len(_t) == 3:
            #    method, uri, sipversion = _t
        else:
            log.warn('Could not parse the first header line: %s' % headerlines[0])
            return r
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname, tmpval = headerline.split(SEP, 1)
                name = tmpname.lower().strip()
                val = list(map(lambda x: x.strip(), tmpval.split(',')))
            else:
                name, val = headerline.lower(), None
            r['headers'][name] = val
        r['body'] = body
        return r


def fingerPrint(request, src=None, dst=None):
    # work needs to be done here
    server = dict()
    if 'headers' in request:
        header = request['headers']
        if (src is not None) and (dst is not None):
            server['ip'] = src[0]
            server['srcport'] = src[1]
            if server['srcport'] == dst[1]:
                server['behindnat'] = False
            else:
                server['behindnat'] = True
        if 'user-agent' in header:
            server['name'] = header['user-agent']
            server['uatype'] = 'uac'
        if 'server' in header:
            server['name'] = header['server']
            server['uatype'] = 'uas'
        if 'contact' in header:
            m = re.match('<sip:(.*?)>', header['contact'][0])
            if m:
                server['contactip'] = m.group(1)
        if 'supported' in header:
            server['supported'] = header['supported']
        if 'accept-language' in header:
            server['accept-language'] = header['accept-language']
        if 'allow-events' in header:
            server['allow-events'] = header['allow-events']
        if 'allow' in header:
            server['allow'] = header['allow']
    return server


def fingerPrintPacket(buff, src=None):
    header = parseHeader(buff)
    if header is not None:
        return fingerPrint(header, src)


def getCredentials(buff):
    data = getTag(buff)
    if data is None:
        return
    userpass = data.split(b':')
    if len(userpass) > 0:
        return(userpass)


def getTag(buff):
    tagRE = r'(From|f): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'
    _tmp = re.findall(tagRE, buff)
    if _tmp is not None:
        if len(_tmp) > 0:
            _tmp2 = _tmp[0][1]
            try:
                _tmp2 = a2b_hex(_tmp2.strip())
            except (TypeError, b2aerr):
                return
            if _tmp2.find(b'\x01') > 0:
                try:
                    c, _ = _tmp2.split(b'\x01')
                except ValueError:
                    c = 'svcrash detected'
            else:
                c = _tmp2
            return c


def createTag(data):
    rnd = getrandbits(32)
    return b2a_hex(str(data).encode('utf-8') + b'\x01' + str(rnd).encode('utf-8'))


def getToTag(buff):
    tagRE = r'(To|t): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'
    _tmp = re.findall(tagRE, buff)
    if _tmp is not None:
        if len(_tmp) > 0:
            _tmp2 = _tmp[0][1]
            return _tmp2
    return


def challengeResponse(auth, method, uri):
    from hashlib import md5
    username = auth["username"]
    realm = auth["realm"]
    passwd = auth["password"]
    nonce = auth["nonce"]
    opaque = auth["opaque"]
    algorithm = auth["algorithm"]
    cnonce = ""
    qop = None
    if auth["qop"] != None:
        qop = auth["qop"].split(',')[0]
    result = 'Digest username="%s",realm="%s",nonce="%s",uri="%s"' % (
        username, realm, nonce, uri)
    if algorithm == "md5-sess" or qop == "auth":
        cnonce = uuid.uuid4().hex
        nonceCount = "%08d" % auth["noncecount"]
        result += ',cnonce="%s",nc=%s' % (cnonce, nonceCount)
    if algorithm is None or algorithm == "md5":
        ha1 = md5(('%s:%s:%s' % (username, realm, passwd)).encode('utf-8')).hexdigest()
        result += ',algorithm=MD5'
    elif auth["algorithm"] == "md5-sess":
        ha1 = md5((md5(('%s:%s:%s' % (username, realm, passwd)).encode('utf-8')
                      ).hexdigest() + ":" + nonce + ":" + cnonce).encode('utf-8')).hexdigest()
        result += ',algorithm=MD5-sess'
    else:
        print("Unknown algorithm: %s" % auth["algorithm"])
    if qop is None or qop == "auth":
        ha2 = md5(('%s:%s' % (method, uri)).encode('utf-8')).hexdigest()
        result += ',qop=auth'
    if qop == "auth-int":
        print("auth-int is not supported")
    if qop == "auth":
        res = md5((ha1 + ":" + nonce + ":" + nonceCount + ":" +
                  cnonce + ":" + qop + ":" + ha2).encode('utf-8')).hexdigest()
    else:
        res = md5(('%s:%s:%s' % (ha1, nonce, ha2)).encode('utf-8')).hexdigest()
    result += ',response="%s"' % res
    if opaque is not None and opaque != "":
        result += ',opaque="%s"' % opaque
    return result


def makeRedirect(previousHeaders, rediraddr):
    response = 'SIP/2.0 301 Moved Permanently\r\n'
    superheaders = dict()
    headers = dict()
    superheaders['Via'] = ' '.join(previousHeaders['headers']['via'])
    headers['Contact'] = '<%s>' % (rediraddr)
    headers['To'] = ' '.join(previousHeaders['headers']['to'])
    headers['From'] = ' '.join(previousHeaders['headers']['from'])
    headers['Call-ID'] = ' '.join(previousHeaders['headers']['call-id'])
    headers['CSeq'] = ' '.join(previousHeaders['headers']['cseq'])
    r = response
    for h in superheaders.items():
        r += '%s: %s\r\n' % h
    for h in headers.items():
        r += '%s: %s\r\n' % h
    r += '\r\n'
    return(r)


def makeRequest(method, fromaddr, toaddr, dsthost, port, callid, srchost='', branchunique=None, cseq=1,
    auth=None, localtag=None, compact=False, contact='sip:123@1.1.1.1', accept='application/sdp', contentlength=None,
    localport=5060, extension=None, contenttype=None, body='', useragent='friendly-scanner', requesturi=None):
    """makeRequest builds up a SIP request
    method - OPTIONS / INVITE etc
    toaddr = to address
    dsthost = destination host
    port = destination port
    callid = callerid
    srchost = source host
    """
    if extension is None or method == 'REGISTER':
        uri = 'sip:%s' % dsthost
    else:
        uri = 'sip:%s@%s' % (extension, dsthost)
    if branchunique is None:
        branchunique = '%s' % random.getrandbits(32)
    headers = dict()
    finalheaders = dict()
    superheaders = dict()
    if method == 'ACK':
        localtag = None
    if compact:
        superheaders[
            'v'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost, port, branchunique)
        headers['t'] = toaddr
        headers['f'] = fromaddr
        if localtag is not None:
            headers['f'] += ';tag=%s' % localtag.decode('utf-8', 'ignore')
        headers['i'] = callid
        # if contact is not None:
        headers['m'] = contact
    else:
        superheaders[
            'Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost, localport, branchunique)
        headers['Max-Forwards'] = 70
        headers['To'] = toaddr
        headers['From'] = fromaddr
        headers['User-Agent'] = useragent
        if localtag is not None:
            headers['From'] += ';tag=%s' % localtag.decode('utf-8', 'ignore')
        headers['Call-ID'] = callid
        # if contact is not None:
        headers['Contact'] = contact
    headers['CSeq'] = '%s %s' % (cseq, method)
    headers['Max-Forwards'] = 70
    headers['Accept'] = accept
    if contentlength is None:
        headers['Content-Length'] = len(body)
    else:
        headers['Content-Length'] = contentlength
    if contenttype is None and len(body) > 0:
        contenttype = 'application/sdp'
    if contenttype is not None:
        headers['Content-Type'] = contenttype
    if auth is not None:
        response = challengeResponse(auth, method, uri)
        if auth['proxy']:
            finalheaders['Proxy-Authorization'] = response
        else:
            finalheaders['Authorization'] = response

    r = '%s %s SIP/2.0\r\n' % (method, uri)
    if requesturi is not None:
        r = '%s %s SIP/2.0\r\n' % (method, requesturi)
    for h in superheaders.items():
        r += '%s: %s\r\n' % h
    for h in headers.items():
        r += '%s: %s\r\n' % h
    for h in finalheaders.items():
        r += '%s: %s\r\n' % h
    r += '\r\n'
    r += body
    return(r)


def reportBugToAuthor(trace):
    log = logging.getLogger('reportBugToAuthor')
    data = str()
    data += "Command line parameters:\r\n"
    data += str(sys.argv)
    data += '\r\n'
    data += 'version: %s' % __version__
    data += '\r\n'
    data += 'email: <%s>' % input("Your email address (optional): ")
    data += '\r\n'
    data += 'msg: %s' % input("Extra details (optional): ")
    data += '\r\n'
    data += "python version: \r\n"
    data += "%s\r\n" % sys.version
    data += "osname: %s" % os.name
    data += '\r\n'
    if os.name == 'posix':
        data += "uname: %s" % str(os.uname())
        data += '\r\n'
    data += '\r\n\r\n'
    data += "Trace:\r\n"
    data += str(trace)
    try:
        urlopen('https://comms.enablesecurity.com/hello.php',
                urlencode({'message': data}).encode('utf-8'))
        log.warn('Thanks for the bug report! We will be working on it soon')
    except URLError as err:
        log.error(err)
    log.warn('Make sure you are running the latest version of SIPVicious \
                 by running "git pull" in the current directory')


def scanlist(iprange, portranges, methods):
    for ip in iter(iprange):
        for portrange in portranges:
            for port in portrange:
                for method in methods:
                    yield(ip, port, method)


def scanrandom(ipranges, portranges, methods, resume=None, randomstore='.sipvicious_random'):
    # if the ipranges intersect then we go infinate .. we prevent that
    # example: 127.0.0.1 127.0.0.1/24
    log = logging.getLogger('scanrandom')
    mode = 'n'
    if resume:
        mode = 'c'
    database = dbm.open(os.path.join(
        os.path.expanduser('~'), randomstore), mode)
    dbsyncs = False
    try:
        database.sync()
        dbsyncs = True
    except AttributeError:
        pass
    ipsleft = 0
    for iprange in ipranges:
        if iprange is None:
            continue
        startip, endip = iprange
        ipsleft += endip - startip + 1
        hit = 0
        for iprange2 in ipranges:
            startip2, endip2 = iprange2
            if startip <= startip2:
                if endip2 <= endip:
                    hit += 1
                    if hit > 1:
                        log.error(
                            'Cannot use random scan and try to hit the same ip twice')
                        return
    if resume:
        ipsleft -= len(database)
    log.debug('scanning a total of %s ips' % ipsleft)
    while ipsleft > 0:
        randomchoice = random.choice(ipranges)
        #randomchoice = [0,4294967295L]
        randint = random.randint(*randomchoice)
        ip = numToDottedQuad(randint)
        ipfound = False
        if dbsyncs:
            if ip not in database:
                ipfound = True
        else:
            if ip not in database.keys():
                ipfound = True
        if ipfound:
            database[ip] = ''
            for portrange in portranges:
                for port in portrange:
                    for method in methods:
                        ipsleft -= 1
                        yield(ip, port, method)
        else:
            log.debug('found dup %s' % ip)


def scanfromfile(csv, methods):
    for row in csv:
        (dstip, dstport, _, _, _) = row
        for method in methods:
            yield(dstip, int(dstport), method)


def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L', socket.inet_aton(ip))[0]


def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L', n))


def colonHexToNum(ip):
    "convert ipv6 address to long integer"
    return int(hexlify(socket.inet_pton(socket.AF_INET6, ip)), 16)


def ip4range(*args):
    for arg in args:
        r = getranges(arg)
        if r is None:
            continue
        startip, endip = r
        curip = startip
        while curip <= endip:
            yield(numToDottedQuad(curip))
            curip += 1


def ip6range(*args):
    for arg in args:
        if check_ipv6(arg):
            yield(arg)


def getranges(ipstring):
    from sipvicious import svmap
    log = logging.getLogger('getranges')
    if re.match(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        ipstring
    ):
        naddr1, naddr2 = list(map(dottedQuadToNum, ipstring.split('-')))
    elif re.match(
        r'^(\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)$',
        ipstring
    ):
        naddr1, naddr2 = list(map(dottedQuadToNum, getranges2(ipstring)))
    elif re.match(
        r'^.*?\/\d{,2}$',
        ipstring
    ):
        r = getmaskranges(ipstring)
        if r is None:
            return
        naddr1, naddr2 = r
    else:
        # we attempt to resolve the host
        try:
            naddr1 = dottedQuadToNum(socket.gethostbyname(ipstring))
            naddr2 = naddr1
        except socket.error:
            log.error('Could not resolve %s' % ipstring)
            svmap.__exitcode__ = 30  # network error
            return
        # UnicodeError is raised by the idna library when a malformed IP
        # is passed to socket.gethostbyname(). e.g. gethostbyname('1.1..1')
        except UnicodeError:
            log.error('Malformed target supplied: %s' % ipstring)
            svmap.__exitcode__ = resolveexitcode(10, svmap.__exitcode__)
            return
    return naddr1, naddr2


def getranges2(ipstring):
    _tmp = ipstring.split('.')
    if len(_tmp) != 4:
        raise ValueError("needs to be a Quad dotted ip")
    _tmp2 = list(map(lambda x: x.split('-'), _tmp))
    startip = list()
    endip = list()
    for dot in _tmp2:
        if dot[0] == '*':
            startip.append('0')
            endip.append('255')
        elif len(dot) == 1:
            startip.append(dot[0])
            endip.append(dot[0])
        elif len(dot) == 2:
            startip.append(dot[0])
            endip.append(dot[1])
    naddr1 = '.'.join(startip)
    naddr2 = '.'.join(endip)
    return(naddr1, naddr2)


def getmaskranges(ipstring):
    log = logging.getLogger('getmaskranges')
    addr, mask = ipstring.rsplit('/', 1)
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', addr):
        try:
            log.debug('Could not resolve %s' % addr)
            addr = socket.gethostbyname(addr)
        except socket.error:
            return
    assert(mask.isdigit()), "invalid IP mask (1)"
    naddr = dottedQuadToNum(addr)
    masklen = int(mask)
    assert(0 <= masklen <= 32), "invalid IP mask (2)"
    naddr1 = naddr & (((1 << masklen) - 1) << (32 - masklen))
    naddr2 = naddr1 + (1 << (32 - masklen)) - 1
    return (naddr1, naddr2)


def scanfromdb(db, methods):
    database = dbm.open(db, 'r')
    for k in database.keys():
        for method in methods:
            ip, port = k.split(':')
            port = int(port)
            yield(ip, port, method)


def resumeFromIP(ip, args):
    ipranges = list()
    foundit = False
    rargs = list()
    nip = dottedQuadToNum(ip)
    for arg in args:
        if arg is None:
            continue
        startip, endip = getranges(arg)
        if not foundit:
            if startip <= nip and endip >= nip:
                ipranges.append((nip, endip))
                foundit = True
        else:
            ipranges.append((startip, endip))
    for iprange in ipranges:
        rargs.append('-'.join(map(numToDottedQuad, iprange)))
    return rargs


def resumeFrom(val, rangestr):
    val = int(val)
    ranges = list(map(lambda x: map(int, x.split('-')), rangestr.split(',')))
    foundit = False
    tmp = list()
    for r in ranges:
        start, end = r
        if not foundit:
            if start <= val and end >= val:
                tmp.append((val, end))
                foundit = True
        else:
            tmp.append((start, end))
    return ','.join(map(lambda x: '-'.join(map(str, x)), tmp))


def packetcounter(n):
    i = 0
    while 1:
        if i == n:
            i = 0
            r = True
        else:
            i += 1
            r = False
        yield(r)

sessiontypes = ['svmap', 'svwar', 'svcrack']


def findsession(chosensessiontype=None):
    listresult = dict()
    for sessiontype in sessiontypes:
        if chosensessiontype in [None, sessiontype]:
            p = os.path.join(os.path.expanduser(
                '~'), '.sipvicious', sessiontype)
            if os.path.exists(p):
                listresult[sessiontype] = os.listdir(p)
    return listresult


def listsessions(chosensessiontype=None, count=False):
    listresult = findsession(chosensessiontype)
    for k in listresult.keys():
        print("Type of scan: %s" % k)
        for r in listresult[k]:
            sessionstatus = 'Incomplete'
            sessionpath = os.path.join(
                os.path.expanduser('~'), '.sipvicious', k, r)
            dblen = ''
            if count:
                if k == 'svmap':
                    dbloc = os.path.join(sessionpath, 'resultua')
                elif k == 'svwar':
                    dbloc = os.path.join(sessionpath, 'resultauth')
                elif k == 'svcrack':
                    dbloc = os.path.join(sessionpath, 'resultpasswd')
                if not os.path.exists(dbloc):
                    logging.debug(
                        'The database could not be found: %s' % dbloc)
                else:
                    db = dbm.open(dbloc, 'r')
                    dblen = len(db)
            if os.path.exists(os.path.join(sessionpath, 'closed')):
                sessionstatus = 'Complete'
            print("\t- %s\t\t%s\t\t%s\n" % (r, sessionstatus, dblen))


def deletesessions(chosensession, chosensessiontype):
    log = logging.getLogger('deletesessions')
    sessionpath = list()
    if chosensessiontype is None:
        for sessiontype in sessiontypes:
            p = os.path.join(os.path.expanduser(
                '~'), '.sipvicious', sessiontype, chosensession)
            if os.path.exists(p):
                sessionpath.append(p)
    else:
        p = os.path.join(os.path.expanduser('~'), '.sipvicious',
                         chosensessiontype, chosensession)
        if os.path.exists(p):
            sessionpath.append(p)
    if len(sessionpath) == 0:
        return
    for sp in sessionpath:
        try:
            shutil.rmtree(sp)
            log.info("Session at %s was removed" % sp)
        except OSError:
            log.error("Could not delete %s" % sp)
    return sessionpath


def createReverseLookup(src, dst):
    log = logging.getLogger('createReverseLookup')
    #srcdb = anydbm.open(src,'r')
    #dstdb = anydbm.open(dst,'n')
    srcdb = src
    dstdb = dst
    if len(srcdb) > 100:
        log.warn("Performing dns lookup on %s hosts. To disable reverse ip resolution make use of the -n option" % len(srcdb))
    for k in srcdb.keys():
        tmp = k.split(b':', 1)
        if len(tmp) == 2:
            ajpi, port = tmp
            try:
                tmpk = ':'.join([socket.gethostbyaddr(ajpi.decode())[0], port.decode()])
                logging.debug('Resolved %s to %s' % (k, tmpk))
                dstdb[k] = tmpk
            except socket.error:
                logging.info('Could not resolve %s' % k)
                pass
    # srcdb.close()
    # dstdb.close()
    return dstdb


def getasciitable(labels, db, resdb=None, width=60):
    rows = list()
    for k in db.keys():
        cols = [k.decode(), db[k].decode()]
        if resdb is not None:
            if k in resdb:
                cols.append(resdb[k].decode())
            else:
                cols.append('[not available]')
        rows.append(cols)
    o = to_string(rows, header=labels)
    return o


def outputtoxml(title, labels, db, resdb=None, xsl='resources/sv.xsl'):
    from xml.sax.saxutils import escape
    o = '<?xml version="1.0" ?>\r\n'
    o += '<?xml-stylesheet type="text/xsl" href="%s"?>\r\n' % escape(xsl)
    o += '<root>\r\n'
    o += '<title>%s</title>\r\n' % escape(title)
    o += '<labels>\r\n'
    for label in labels:
        o += '<label><name>%s</name></label>\r\n' % escape(label)
    o += '</labels>\r\n'
    o += '<results>\r\n'
    for k in db.keys():
        o += '<result>\r\n'
        o += '<%s><value>%s</value></%s>\r\n' % (labels[0].replace(
            ' ', '').lower(), k.decode(), escape(labels[0]).replace(' ', '').lower())
        o += '<%s><value>%s</value></%s>\r\n' % (labels[1].replace(
            ' ', '').lower(), escape(db[k].decode()), labels[1].replace(' ', '').lower())
        if resdb is not None:
            if k in resdb:
                o += '<%s><value>%s</value></%s>\r\n' % (labels[2].replace(
                    ' ', '').lower(), escape(resdb[k].decode()), labels[2].replace(' ', '').lower())
            else:
                o += '<%s><value>N/A</value></%s>\r\n' % (labels[2].replace(
                    ' ', '').lower(), labels[2].replace(' ', '').lower())
        o += '</result>\r\n'
    o += '</results>\r\n'
    o += '</root>\r\n'
    return o


def getsessionpath(session, sessiontype):
    log = logging.getLogger('getsessionpath')
    sessiontypes = ['svmap', 'svwar', 'svcrack']
    sessionpath = None
    if sessiontype is None:
        log.debug('sessiontype is not specified')
        for sessiontype in sessiontypes:
            p = os.path.join(os.path.expanduser(
                '~'), '.sipvicious', sessiontype, session)
            log.debug('trying %s' % p)
            if os.path.exists(p):
                log.debug('%s exists')
                log.debug('sessiontype is %s' % sessiontype)
                sessionpath = p
                break
    else:
        p = os.path.join(os.path.expanduser(
            '~'), '.sipvicious', sessiontype, session)
        if os.path.exists(p):
            sessionpath = p
    if sessionpath is None:
        return
    return sessionpath, sessiontype


def dbexists(name):
    if os.path.exists(name):
        return True
    elif os.path.exists(name + '.db'):
        return True
    return False


def outputtopdf(outputfile, title, labels, db, resdb):
    log = logging.getLogger('outputtopdf')
    try:
        from reportlab.platypus import TableStyle, Table, SimpleDocTemplate, Paragraph
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        log.error(
            'Reportlab was not found. To export to pdf you need to have reportlab installed. Check out www.reportlab.org')
        return
    log.debug('ok reportlab library found')
    styles = getSampleStyleSheet()
    rows = list()
    rows.append(labels)
    for k in db.keys():
        cols = [k, db[k]]
        if resdb is not None:
            if k in resdb:
                cols.append(resdb[k])
            else:
                cols.append('N/A')
        rows.append(cols)
    t = Table(rows)
    mytable = TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.black),
                          ('TEXTCOLOR', (0, 0), (-1, 0), colors.white)])
    t.setStyle(mytable)
    doc = SimpleDocTemplate(outputfile)
    elements = []
    style = styles["Heading1"]
    Title = Paragraph(title, style)
    elements.append(Title)
    elements.append(t)
    doc.build(elements)


class anotherxrange(object):
    """A pure-python implementation of xrange.

    Can handle float/long start/stop/step arguments and slice indexing"""

    __slots__ = ['_slice']

    def __init__(self, *args):
        self._slice = slice(*args)
        if self._slice.stop is None:
            # slice(*args) will never put None in stop unless it was
            # given as None explicitly.
            raise TypeError("xrange stop must not be None")

    @property
    def start(self):
        if self._slice.start is not None:
            return self._slice.start
        return 0

    @property
    def stop(self):
        return self._slice.stop

    @property
    def step(self):
        if self._slice.step is not None:
            return self._slice.step
        return 1

    def __hash__(self):
        return hash(self._slice)

    # Commented out this due to being redundant
    #def __cmp__(self, other):
    #    return (cmp(type(self), type(other)) or
    #            cmp(self._slice, other._slice))

    def __repr__(self):
        return '%s(%r, %r, %r)' % (self.__class__.__name__,
                                   self.start, self.stop, self.step)

    def __len__(self):
        return self._len()

    def _len(self):
        return max(0, int((self.stop - self.start) / self.step))

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self._len())
            return range(self._index(start),
                          self._index(stop), step * self.step)
        elif isinstance(index, int):
            if index < 0:
                fixed_index = index + self._len()
            else:
                fixed_index = index

            if not 0 <= fixed_index < self._len():
                raise IndexError("Index %d out of %r" % (index, self))

            return self._index(fixed_index)
        else:
            raise TypeError("xrange indices must be slices or integers")

    def _index(self, i):
        return self.start + self.step * i


def getTargetFromSRV(domainnames, methods):
    log = logging.getLogger('getTargetFromSRV')
    try:
        import dns
        import dns.resolver
    except ImportError:
        log.critical(
            'could not import the DNS library. Get it from http://www.dnspython.org/')
        return
    for domainname in domainnames:
        for proto in ['udp', 'tcp']:
            name = '_sip._' + proto + '.' + domainname + '.'
            try:
                log.debug('trying to resolve SRV for %s' % name)
                ans = dns.resolver.query(name, 'SRV')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as err:
                log.debug('Encountered error: %s' % err.__str__())
                log.info('Could not resolve %s' % name)
                continue
            for a in ans.response.answer:
                log.info('got an answer %s' % a.to_text())
                for _tmp in a:
                    for method in methods:
                        try:
                            hostname = socket.gethostbyname(
                                _tmp.target.to_text())
                        except socket.error:
                            log.warn("%s could not be resolved" %
                                     _tmp.target.to_text())
                            continue
                        log.debug("%s resolved to %s" %
                                  (_tmp.target.to_text(), hostname))
                        yield(hostname, _tmp.port, method)


def getAuthHeader(pkt):
    nonceRE = '\r\n(www-authenticate|proxy-authenticate): (.+?)\r\n'
    _tmp = re.findall(nonceRE, pkt, re.I)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0][1])
    return None



def check_ipv6(n):
    log = logging.getLogger('check_ipv6')
    if '/' in n:
        log.error('CIDR notation not supported for IPv6 addresses.')
        return False
    try:
        socket.inet_pton(socket.AF_INET6, n)
        return True
    except socket.error:
        return False


if __name__ == '__main__':
    print(getranges('1.1.1.1/24'))
    seq = getranges('google.com/24')
    if seq is not None:
        a = ip4range(seq)
        for x in iter(a):
            print(x)
