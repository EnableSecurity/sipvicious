
#!/usr/bin/env python


#   Helper.py keeps the rest of the tools clean - part of SIPVicious tools
#   Copyright (C) 2007-2010  Sandro Gauci <sandro@enablesecurity.com>
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
__version__ = '0.2.4'


import sys
if sys.hexversion < 0x020400f0:
    sys.stderr.write("Please update to python 2.4 or greater to run Sipvicious\r\n")
    sys.exit(1)


import base64,struct,socket,logging

import optparse
def standardoptions(parser):
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False,
                      help="Quiet mode")
    parser.add_option("-p", "--port", dest="port", default="5060",
                  help="Destination port or port ranges of the SIP device - eg -p5060,5061,8000-8100", metavar="PORT")
    parser.add_option("-P", "--localport", dest="localport", default=5060, type="int",
                  help="Source port for our packets", metavar="PORT")
    parser.add_option("-x", "--externalip", dest="externalip",
                  help="IP Address to use as the external ip. Specify this if you have multiple interfaces or if you are behind NAT", metavar="IP")
    parser.add_option("-b", "--bindingip", dest="bindingip", default='0.0.0.0',
                  help="By default we bind to all interfaces. This option overrides that and binds to the specified ip address")
    parser.add_option("-t", "--timeout", dest="selecttime", type="float",
                      default=0.005,
                    help="This option allows you to trottle the speed at which packets are sent. Change this if you're losing packets. For example try 0.5.",
                  metavar="SELECTTIME")        
    parser.add_option("-R", "--reportback", dest="reportBack", default=False, action="store_true",
                  help="Send the author an exception traceback. Currently sends the command line parameters and the traceback",                  
                  )
    return parser

def standardscanneroptions(parser):
    parser.add_option("-s", "--save", dest="save",
                  help="save the session. Has the benefit of allowing you to resume a previous scan and allows you to export scans", metavar="NAME")    
    parser.add_option("--resume", dest="resume",
                  help="resume a previous scan", metavar="NAME")    
    parser.add_option("-c", "--enablecompact", dest="enablecompact", default=False, 
                  help="enable compact mode. Makes packets smaller but possibly less compatible",
                  action="store_true",
                  )
    return parser

def calcloglevel(options):
    logginglevel = 30
    if options.verbose is not None:
        if options.verbose >= 3:
            logginglevel = 10
        else:
            logginglevel = 30-(options.verbose*10)
    if options.quiet:
        logginglevel = 50
    return logginglevel


def bindto(bindingip,startport,s):
    import logging
    log = logging.getLogger('bindto')
    localport = startport
    log.debug("binding to %s:%s" % (bindingip,localport))
    while 1:
        if localport > 65535:
            log.critical("Could not bind to any port")
            return
        try:
            s.bind((bindingip,localport))
            break
        except socket.error:
            log.debug("could not bind to %s" % localport)
            localport += 1            
    if startport != localport:
        log.warn("could not bind to %s:%s - some process might already be listening on this port. Listening on port %s instead" % \
                 (bindingip,startport, localport))
        log.info("Make use of the -P option to specify a port to bind to yourself")
    return localport,s


def getRange(rangestr):
    from helper import anotherxrange as xrange
    _tmp1 = rangestr.split(',')
    numericrange = list()
    for _tmp2 in _tmp1:
        _tmp3 = _tmp2.split('-',1)
        if len(_tmp3) > 1:        
            if not (_tmp3[0].isdigit() or _tmp3[1].isdigit()):
                raise ValueError, "the ranges need to be digits"                
                return            
            startport,endport = map(int,[_tmp3[0],_tmp3[1]])
            endport += 1
            numericrange.append(xrange(startport,endport))
        else:
            if not _tmp3[0].isdigit():
                raise ValueError, "the ranges need to be digits"                
                return
            singleport = int(_tmp3[0])
            numericrange.append(xrange(singleport,singleport+1))
    return numericrange


def numericbrute(rangelist,zeropadding=0,template=None,defaults=False):
    """numericbrute gives a yield generator. accepts either zeropadding or template as optional argument"""
    if defaults:
        for i in xrange(1000,9999,100):
            yield('%04i' % i)
        
        for i in xrange(1001,9999,100):
            yield('%04i' % i)
            
        for i in xrange(0,9):
            for l in xrange(1,8):
                yield(('%s' % i) * l)
        
        for i in xrange(100,999):
            yield('%s' % i)
    
        for i in xrange(10000,99999,100):
            yield('%04i' % i)
        
        for i in xrange(10001,99999,100):
            yield('%04i' % i)
        
        for i in [1234,2345,3456,4567,5678,6789,7890,0123]:
            yield('%s' % i)
    
        for i in [12345,23456,34567,45678,56789,67890,01234]:
            yield('%s' % i)
    

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
    r = dictionaryfile.readline().strip()    
    while r != '':
        yield(r)
        r = dictionaryfile.readline().strip()
    dictionaryfile.close()


class genericbrute:
    pass



def getNonce(pkt):
    import re
    nonceRE='nonce="([:a-zA-Z0-9]+)"'
    _tmp = re.findall(nonceRE,pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def getRealm(pkt):
    import re
    nonceRE='realm="([.:a-zA-Z0-9@]+)"'
    _tmp = re.findall(nonceRE,pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def getCID(pkt):
    import re
    cidRE='Call-ID: ([:a-zA-Z0-9]+)'
    _tmp = re.findall(cidRE,pkt)
    if _tmp is not None:
        if len(_tmp) > 0:
            return(_tmp[0])
    return None

def mysendto(sock,data,dst):
    while data:
        bytes_sent = sock.sendto(data[:8192],dst)
        data = data[bytes_sent:]

def parseSDP(buff):
    r = dict()
    for line in buff.splitlines():
        _tmp = line.split('=',1)
        if len(_tmp) == 2:
            k,v = _tmp
            if not r.has_key(k):
                r[k] = list()
            r[k].append(v)
    return r

def getAudioPort(sdp):
    if sdp.has_key('m'):
        for media in sdp['m']:
            if media.startswith('audio'):
                mediasplit = media.split()
                if len(mediasplit) > 2:
                    port = mediasplit[1]
                    return port

def getAudioIP(sdp):
    if sdp.has_key('c'):
        for connect in sdp['c']:
            if connect.startswith('IN IP4'):
                connectsplit = connect.split()
                if len(connectsplit) > 2:
                    ip = connectsplit[2]
                    return ip

def getSDP(buff):
    sip = parseHeader(buff)
    if sip.has_key('body'):
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

def parseHeader(buff,type='response'):
    import re
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    import logging
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
        body = ''
    headerlines = re.split(HeadersSEP, header)
    
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                sipversion,_code,description = _t
            else:
                log.warn('Could not parse the first header line: %s' % `_t`)
                return r
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            _t = headerlines[0].split(' ',2)
            if len(_t) == 3:
                method,uri,sipversion = _t     
        else:
            log.warn('Could not parse the first header line: %s' % `_t`)
            return r  
        r['headers'] = dict()
        for headerline in headerlines[1:]:
            SEP = ':'
            if SEP in headerline:
                tmpname,tmpval = headerline.split(SEP,1)
                name = tmpname.lower().strip()
                val =  map(lambda x: x.strip(),tmpval.split(','))
            else:
                name,val = headerline.lower(),None
            r['headers'][name] = val
        r['body'] = body
        return r
    


def fingerPrint(request,src=None,dst=None):
    # work needs to be done here
    import re
    server = dict()
    if request.has_key('headers'):
                 header = request['headers']
                 if (src is not None) and (dst is not None):
                      server['ip'] = src[0]
                      server['srcport'] = src[1]
                      if server['srcport'] == dst[1]:
                               server['behindnat'] = False
                      else:
                               server['behindnat'] = True
                 if header.has_key('user-agent'):
                    server['name'] = header['user-agent']
                    server['uatype'] = 'uac' 
                 if header.has_key('server'):
                    server['name'] = header['server']
                    server['uatype'] = 'uas'
                 if header.has_key('contact'):
                    m = re.match('<sip:(.*?)>',header['contact'][0])
                    if m: 
                        server['contactip'] = m.group(1)
                 if header.has_key('supported'):
                    server['supported'] = header['supported']
                 if header.has_key('accept-language'):
                    server['accept-language'] = header['accept-language']
                 if header.has_key('allow-events'):
                    server['allow-events'] = header['allow-events']
                 if header.has_key('allow'):
                    server['allow'] = header['allow']
    return server

def fingerPrintPacket(buff,src=None):
    header = parseHeader(buff)
    if header is not None:
        return fingerPrint(header,src)
    
def getCredentials(buff):
    data = getTag(buff)
    if data is None:
        return    
    userpass = data.split(':')
    if len(userpass) > 0:
        return(userpass)    
    
def getTag(buff):
    import re
    from binascii import a2b_hex
    tagRE='(From|f): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'    
    _tmp = re.findall(tagRE,buff)
    if _tmp is not None:
        if len(_tmp) > 0:
            _tmp2 = _tmp[0][1]
            _tmp2 = a2b_hex(_tmp2)
            if _tmp2.find('\x01') > 0:
                try:
                    c,rand = _tmp2.split('\x01')
                except ValueError:
                    c = 'svcrash detected'
            else:
                c = _tmp2
            return c

def createTag(data):
    from binascii import b2a_hex
    from random import getrandbits
    rnd = getrandbits(32)
    return b2a_hex(str(data)+'\x01'+str(rnd))

def getToTag(buff):
    import re
    tagRE='(To|t): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'    
    _tmp = re.findall(tagRE,buff)
    if _tmp is not None:
        if len(_tmp) > 0:
            _tmp2 = _tmp[0][1]
            return _tmp2
    return

def challengeResponse(username,realm,passwd,method,uri,nonce):
    import md5
    a1 = md5.new('%s:%s:%s' % (username,realm,passwd)).hexdigest()
    a2 = md5.new('%s:%s' % (method,uri)).hexdigest()
    res = md5.new('%s:%s:%s' % (a1,nonce,a2)).hexdigest()
    return res

def makeRedirect(previousHeaders,rediraddr):
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
    for h in superheaders.iteritems():
        r += '%s: %s\r\n' % h
    for h in headers.iteritems():
        r += '%s: %s\r\n' % h
    r += '\r\n'
    return(r)
    

def makeRequest(
                method,fromaddr,toaddr,dsthost,port,callid,srchost='',
                branchunique=None,cseq=1,auth=None,localtag=None,compact=False
                ,contact='sip:123@1.1.1.1',accept='application/sdp',contentlength=None,
                localport=5060,extension=None,contenttype=None,body='',
                useragent='friendly-scanner'):
    """makeRequest builds up a SIP request
    method - OPTIONS / INVITE etc
    toaddr = to address
    dsthost = destination host
    port = destination port
    callid = callerid
    srchost = source host
    """
    import random
    if extension is None:
        uri = 'sip:%s' % dsthost
    else:
        uri = 'sip:%s@%s' % (extension,dsthost)
    if branchunique is None:
        branchunique = '%s' % random.getrandbits(32)
    headers = dict()
    finalheaders = dict()
    superheaders = dict()
    if compact:
        superheaders['v'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost,port,branchunique)        
        headers['t'] = toaddr
        headers['f'] = fromaddr
        if localtag is not None:
            headers['f'] += ';tag=%s' % localtag
        headers['i'] = callid
        #if contact is not None:
        headers['m'] = contact
    else:
        superheaders['Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost,localport,branchunique)
        headers['Max-Forwards'] = 70    
        headers['To'] = toaddr
        headers['From'] = fromaddr
        headers['User-Agent'] = useragent
        if localtag is not None:
            headers['From'] += '; tag=%s' % localtag
        headers['Call-ID'] = callid
        #if contact is not None:
        headers['Contact'] = contact
    headers['CSeq'] = '%s %s' % (cseq,method)
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
        response = challengeResponse(auth['username'],auth['realm'],auth['password'],method,uri,auth['nonce'])        
        if auth['proxy']:
            finalheaders['Proxy-Authorization'] = \
                'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=MD5' % (auth['username'],
                                                                                                        auth['realm'],
                                                                                                        auth['nonce'],
                                                                                                        uri,
                                                                                                        response)
        else:
            finalheaders['Authorization'] = \
                'Digest username="%s",realm="%s",nonce="%s",uri="%s",response="%s",algorithm=MD5' % (auth['username'],
                                                                                                        auth['realm'],
                                                                                                        auth['nonce'],
                                                                                                        uri,
                                                                                                        response)
            
    r = '%s %s SIP/2.0\r\n' % (method,uri)
    for h in superheaders.iteritems():
        r += '%s: %s\r\n' % h
    for h in headers.iteritems():
        r += '%s: %s\r\n' % h
    for h in finalheaders.iteritems():
        r += '%s: %s\r\n' % h
    r += '\r\n'
    r += body
    return(r)




def reportBugToAuthor(trace):
    from urllib2 import urlopen,URLError
    from urllib import urlencode
    import logging
    from sys import argv,version
    import os
    from urllib import quote
    log = logging.getLogger('reportBugToAuthor')
    data = str()
    data += "Command line parameters:\r\n"
    data += str(argv)
    data += '\r\n'
    data += 'version: %s' % __version__
    data += '\r\n'
    data += 'email: <%s>' % raw_input("Your email address (optional): ")
    data += '\r\n'
    data += 'msg: %s' % raw_input("Extra details (optional): ")
    data += '\r\n'
    data += "python version: \r\n"
    data += "%s\r\n" % version
    #data += """2.5 (r25:51918, Sep 19 2006, 08:49:13)
    #data += "[GCC ]"
    #data += "A"*900
    data += "osname: %s" % os.name
    data += '\r\n'
    if os.name == 'posix':
        data += "uname: %s" % str(os.uname())
        data += '\r\n'
    data += '\r\n\r\n'
    data += "Trace:\r\n"
    data += str(trace)
    data = quote(data)
    try:
        urlopen('http://geekbazaar.org/bugreport/r2.php',urlencode({'d':data}))
        log.warn('Thanks for the bug report! I\'ll be working on it soon')
    except URLError,err:
        log.error( err )
    log.warn('Make sure you are running the latest version of SIPVicious (svn version) \
                 by running "svn update" in the current directory')
    

def scanlist(iprange,portranges,methods):
    for ip in iter(iprange):
        for portrange in portranges:
            for port in portrange:
                for method in methods:
                    yield(ip,port,method)


def scanrandom(ipranges,portranges,methods,resume=None,randomstore='.sipvicious_random'):
    # if the ipranges intersect then we go infinate .. we prevent that
    # example: 127.0.0.1 127.0.0.1/24
    import random    
    import anydbm    
    log = logging.getLogger('scanrandom')
    mode = 'n'
    if resume:
        mode = 'c'
    database = anydbm.open(randomstore,mode)
    dbsyncs = False
    try:
        database.sync()
        dbsyncs = True
    except AttributeError:
        pass
    ipsleft = 0
    for iprange in ipranges:
        startip,endip = iprange
        ipsleft += endip - startip + 1
        hit = 0
        for iprange2 in ipranges:
            startip2,endip2 = iprange2
            if startip <= startip2:
                if endip2 <= endip:
                    hit += 1
                    if hit > 1:
                        log.error('Cannot use random scan and try to hit the same ip twice')
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
                        yield(ip,port,method)                    
        else:
            log.debug( 'found dup %s' % ip)


def scanfromfile(csv,methods):
    for row in csv:            
        (dstip,dstport,srcip,srcport,uaname) = row
        for method in methods:
            yield(dstip,int(dstport),method)
            
def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L',n))
      

def ip4range(*args):    
    for arg in args:
        r = getranges(arg)
        if r is None:            
            continue
        startip,endip = r
        curip = startip
        while curip <= endip:        
            yield(numToDottedQuad(curip))
            curip += 1

def getranges(ipstring):
    import re
    log = logging.getLogger('getranges')
    if re.match(
        '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        ipstring
        ):        
        naddr1,naddr2 = map(dottedQuadToNum,ipstring.split('-'))
    elif re.match(
        '^(\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)$',
        ipstring
        ):
        naddr1,naddr2 = map(dottedQuadToNum,getranges2(ipstring))
    elif re.match(
        '^.*?\/\d{,2}$',
        ipstring
        ):
        r = getmaskranges(ipstring)
        if r is None:
            return
        naddr1,naddr2 = r
    else:
        # we attempt to resolve the host
        from socket import gethostbyname
        try:
            naddr1 = dottedQuadToNum(gethostbyname(ipstring))
            naddr2 = naddr1
        except socket.error:
            log.info('Could not resolve %s' % ipstring)
            return
    return((naddr1,naddr2))

def getranges2(ipstring):
    _tmp = ipstring.split('.')
    if len(_tmp) != 4:
        raise ValueError, "needs to be a Quad dotted ip"
    _tmp2 = map(lambda x: x.split('-'),_tmp)
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
    return(naddr1,naddr2)

def getmaskranges(ipstring):
    import re
    log = logging.getLogger('getmaskranges')
    addr,mask = ipstring.rsplit('/',1)    
    if not re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',addr):
        from socket import gethostbyname
        try:
            log.debug('Could not resolve %s' % addr)
            addr = gethostbyname(addr)
        except socket.error:
            return
    
    naddr = dottedQuadToNum(addr)
    masklen = int(mask)
    if not 0 <= masklen <= 32:
        raise ValueError
    naddr1 = naddr & (((1<<masklen)-1)<<(32-masklen))
    naddr2 = naddr1 + (1<<(32-masklen)) - 1
    return (naddr1,naddr2)

def scanfromdb(db,methods):
    import anydbm
    database = anydbm.open(db,'r')
    for k in database.keys():
        for method in methods:
            ip,port = k.split(':')
            port = int(port)
            yield(ip,port,method)
    
    

def resumeFromIP(ip,args):
    ipranges = list()
    foundit = False
    rargs = list()
    nip = dottedQuadToNum(ip)
    for arg in args:
            startip,endip = getranges(arg)
            if not foundit:
                  if startip <= nip and endip >= nip:
                           ipranges.append((nip,endip))
                           foundit = True
            else:
                ipranges.append((startip,endip))
    for iprange in ipranges:
             rargs.append('-'.join(map(numToDottedQuad,iprange)))
    return rargs


def resumeFrom(val,rangestr):
    val = int(val)
    ranges = map(lambda x : map(int,x.split('-')),rangestr.split(','))    
    foundit = False
    tmp = list()
    for r in ranges:        
        start,end = r
        if not foundit:
            if start <= val and end >= val:                
                tmp.append((val,end))
                foundit= True
        else:
            tmp.append((start,end))    
    return ','.join(map(lambda x: '-'.join(map(str,x)),tmp))

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

sessiontypes = ['svmap','svwar','svcrack']
def findsession(chosensessiontype=None):
        import os
        listresult = dict()
        for sessiontype in sessiontypes:
            if chosensessiontype in [None,sessiontype]:
                p = os.path.join('.sipvicious',sessiontype)
                if os.path.exists(p):
                    listresult[sessiontype] = os.listdir(p)
        return listresult
         
def listsessions(chosensessiontype=None,count=False):         
        import os.path,anydbm
        listresult = findsession(chosensessiontype)
        for k in listresult.keys():
                print "Type of scan: %s" % k
                for r in listresult[k]:
                    sessionstatus = 'Incomplete'
                    sessionpath=os.path.join('.sipvicious',k,r)
                    dblen = ''
                    if count:
                        if k == 'svmap':
                                dbloc = os.path.join(sessionpath,'resultua')
                        elif k == 'svwar':
                                dbloc = os.path.join(sessionpath,'resultauth')
                        elif k == 'svcrack':
                                dbloc = os.path.join(sessionpath,'resultpasswd')
                        if not os.path.exists(dbloc):
                                         logging.debug('The database could not be found: %s'%dbloc)
                        else:
                            db = anydbm.open(dbloc,'r')
                            dblen = len(db)
                    if os.path.exists(os.path.join(sessionpath,'closed')):
                                    sessionstatus = 'Complete'
                    print "\t- %s\t\t%s\t\t%s" % (r,sessionstatus,dblen)
                print

def deletesessions(chosensession,chosensessiontype):
        import shutil,os, logging
        log = logging.getLogger('deletesessions')
        sessionpath = list()
        if chosensessiontype is None:
            for sessiontype in sessiontypes:
                p = os.path.join('.sipvicious',sessiontype,chosensession)
                if os.path.exists(p):
                        sessionpath.append(p)
        else:
                p = os.path.join('.sipvicious',chosensessiontype,chosensession)
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

def createReverseLookup(src,dst):
    import anydbm,logging
    log = logging.getLogger('createReverseLookup')
    #srcdb = anydbm.open(src,'r')
    #dstdb = anydbm.open(dst,'n')
    srcdb = src
    dstdb = dst
    if len(srcdb) > 100:
        log.warn("Performing dns lookup on %s hosts. To disable reverse ip resolution make use of the -n option" % len(srcdb))
    for k in srcdb.keys():
        tmp = k.split(':',1)
        if len(tmp) == 2:
                ajpi,port = tmp
                try:
                        tmpk = ':'.join([socket.gethostbyaddr(ajpi)[0],port])
                        logging.debug('Resolved %s to %s' % (k,tmpk))
                        dstdb[k] = tmpk
                except socket.error:
                        logging.info('Could not resolve %s' % k)
                        pass
    #srcdb.close()
    #dstdb.close()
    return dstdb

def getasciitable(labels,db,resdb=None,width=60):
    from pptable import indent,wrap_onspace                        
    rows = list()
    for k in db.keys():
            cols = [k,db[k]]
            if resdb is not None:
                if resdb.has_key(k):
                    cols.append(resdb[k])
                else:
                    cols.append('[not available]')
            rows.append(cols)
    o = indent([labels]+rows,hasHeader=True,
        prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
    return o

def outputtoxml(title,labels,db,resdb=None,xsl='sv.xsl'):
    from xml.sax.saxutils import escape
    o  = '<?xml version="1.0" ?>\r\n'
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
        o += '<%s><value>%s</value></%s>\r\n' % (labels[0].replace(' ','').lower(),k,escape(labels[0]).replace(' ','').lower())
        o += '<%s><value>%s</value></%s>\r\n' % (labels[1].replace(' ','').lower(),escape(db[k]),labels[1].replace(' ','').lower())
        if resdb is not None:
            if resdb.has_key(k):
                o += '<%s><value>%s</value></%s>\r\n' % (labels[2].replace(' ','').lower(),escape(resdb[k]),labels[2].replace(' ','').lower())
            else:
                o += '<%s><value>N/A</value></%s>\r\n' % (labels[2].replace(' ','').lower(),labels[2].replace(' ','').lower())
        o += '</result>\r\n'
    o += '</results>\r\n'
    o += '</root>\r\n'
    return o

def getsessionpath(session,sessiontype):
    import os, logging
    log = logging.getLogger('getsessionpath')
    sessiontypes = ['svmap','svwar','svcrack']
    sessionpath = None
    if sessiontype is None:
            log.debug('sessiontype is not specified')
            for sessiontype in sessiontypes:
                    p = os.path.join('.sipvicious',sessiontype,session)
                    log.debug('trying %s' % p)
                    if os.path.exists(p):
                            log.debug('%s exists')
                            log.debug('sessiontype is %s' % sessiontype)
                            sessionpath = p
                            break
    else:
            p = os.path.join('.sipvicious',sessiontype,session)
            if os.path.exists(p):
                    sessionpath = p
    if sessionpath is None:
        return
    return sessionpath,sessiontype
import os.path
def dbexists(name):
    if os.path.exists(name):
        return True
    elif os.path.exists(name+'.db'):
        return True
    return False

def outputtopdf(outputfile,title,labels,db,resdb):
    import logging
    log = logging.getLogger('outputtopdf')
    try:
            from reportlab.platypus import TableStyle, Table, SimpleDocTemplate, Paragraph
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.pdfgen import canvas
    except ImportError:
            log.error('Reportlab was not found. To export to pdf you need to have reportlab installed. Check out www.reportlab.org')
            return
    log.debug('ok reportlab library found')
    styles = getSampleStyleSheet()
    rows=list()
    rows.append(labels)
    for k in db.keys():
        cols = [k,db[k]]
        if resdb is not None:
            if resdb.has_key(k):
                cols.append(resdb[k])
            else:
                cols.append('N/A')
        rows.append(cols)    
    t=Table(rows)
    mytable = TableStyle([('BACKGROUND',(0,0),(-1,0),colors.black),
                            ('TEXTCOLOR',(0,0),(-1,0),colors.white)])
    t.setStyle(mytable)
    doc = SimpleDocTemplate(outputfile)
    elements = []
    style = styles["Heading1"]
    Title = Paragraph(title,style)
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

    def __cmp__(self, other):
        return (cmp(type(self), type(other)) or
                cmp(self._slice, other._slice))

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
            return xrange(self._index(start),
                          self._index(stop), step*self.step)
        elif isinstance(index, (int, long)):
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


def getTargetFromSRV(domainnames,methods):
    import logging
    import socket
    log = logging.getLogger('getTargetFromSRV')
    try:
        import dns
        import dns.resolver
    except ImportError:
        log.critical('could not import the DNS library. Get it from http://www.dnspython.org/')
        return    
    for domainname in domainnames:
        for proto in ['udp','tcp']:
            name = '_sip._'+proto+'.' + domainname + '.'            
            try:
                log.debug('trying to resolve SRV for %s' % name)
                ans = dns.resolver.query(name,'SRV')
            except (dns.resolver.NXDOMAIN,dns.resolver.NoAnswer), err:
                log.info('Could not resolve %s' % name)
                continue
            for a in ans.response.answer:
                log.info('got an answer %s' % a.to_text())
                for _tmp in a:
                    for method in methods:
                        try:
                            hostname = socket.gethostbyname(_tmp.target.to_text())
                        except socket.error:
                            log.warn("%s could not be resolved" % _tmp.target.to_text())
                            continue
                        log.debug("%s resolved to %s" % (_tmp.target.to_text(),hostname))
                        yield(hostname,_tmp.port,method)


if __name__ == '__main__':
    print getranges('1.1.1.1/24')
    seq = getranges('google.com/24')    
    if seq is not None:
        a = ip4range(seq)
        for x in iter(a):
            print x

