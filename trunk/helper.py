#!/usr/bin/env python

#   Helper.py keeps the rest of the tools clean - part of SIPVicious tools
#   Copyright (C) 2007  Sandro Gauci <sandro@sipvicious.org>
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


__author__ = "Sandro Gauci <sandrogauc@gmail.com>"
__version__ = '0.1'

import base64


def getRange(rangestr):
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
            numericrange.extend(range(startport,endport))
        else:
            if not _tmp3[0].isdigit():
                raise ValueError, "the ranges need to be digits"                
                return
            numericrange.append(int(_tmp3[0]))
    return numericrange

class numericbrute:
    def __init__(self,rangelist,zeropadding=0):
        self.rangelist = rangelist
        self.format = '%%0%su' % zeropadding
    def nextone(self):
        if len(self.rangelist) > 0:
            self.currentpos = self.rangelist.pop(0)
            r = self.format % self.currentpos
        else:
            r = None
        return r

class dictionaryattack:
    def __init__(self,dictionaryfile):
        self.passwordfile = dictionaryfile
        
    def nextone(self):
        r = self.passwordfile.readline().strip()
        if r == '':
            self.passwordfile.close()
            return None
        return r

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

def parseHeader(buff,type='response'):
    SEP = '\r\n\r\n'
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
    headerlines = header.splitlines()
    if len(headerlines) > 1:
        r = dict()
        if type == 'response':
            sipversion,_code,description = headerlines[0].split(' ',2)
            try:
                r['code'] = int(_code)
            except ValueError:
                return r
        elif type == 'request':
            method,uri,sipversion = headerlines[0].split(' ',2)        
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
        return r

def fingerPrint(request,src=None,dst=None):
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
    _tmp1 = getTag(buff)    
    if _tmp1 is not None:
        try:
            _tmp3 = base64.b64decode(_tmp1)
        except TypeError:
            return
        _tmp2 = _tmp3.split(':')
        if len(_tmp2) > 0:
            return(_tmp2)
    return
    
def getTag(buff):
    import re
    tagRE='(From|f): .*?\;\s*tag=([=+/\.:a-zA-Z0-9]+)'    
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
    

def makeRequest(method,fromaddr,toaddr,dsthost,port,callid,srchost='',branchunique=None,cseq=1,auth=None,localtag=None,compact=False,contact=None):
    uri = 'sip:%s' % dsthost    
    headers = dict()
    finalheaders = dict()
    superheaders = dict()
    if compact:
        superheaders['v'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost,port,branchunique)        
        headers['t'] = fromaddr
        headers['f'] = toaddr
        if localtag is not None:
            headers['f'] += ';tag=%s' % localtag
        headers['i'] = callid
        if contact is not None:
            headers['m'] = contact
    else:
        superheaders['Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost,port,branchunique)
        headers['Max-Forwards'] = 70    
        headers['To'] = fromaddr
        headers['From'] = toaddr
        if localtag is not None:
            headers['From'] += '; tag=%s' % localtag
        headers['Call-ID'] = callid
        if contact is not None:
            headers['Contact'] = contact
    headers['CSeq'] = '%s %s' % (cseq,method)
    headers['Max-Forwards'] = 70 
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
    return(r)




def reportBugToAuthor(trace):
    from urllib2 import urlopen,URLError
    from sys import argv
    data = str()
    data += "Command line parameters:\r\n"
    data += str(argv)
    data += '\r\n\r\n'
    data += "Trace:\r\n"
    data += str(trace)
    try:
        urlopen('http://geekbazaar.org/bugreport/r.php',data)
    except URLError,err:
        print err

def scanlist(iprange,portrange,methods):
    for ip in iprange.iteraddresses():
        for port in portrange:
            for method in methods:
                yield(ip,port,method)

def _scanrandom(portrange,methods,resume=False,scanspecialips=False):
    import random
    from iphelper import numToDottedQuad
    import anydbm
    import logging
    log = logging.getLogger('scanrandom')
    mode = 'n'
    if resume:
        mode = 'w'    
    database = anydbm.open('.sipvicious_random',mode)
    
    while 1:
        if not scanspecialips:
            # takes into consideration private and reserved address space
            randomchoice = random.choice([
                [16777216,167772159],
                [184549376,234881023],
                [251658240,2130706431],
                [2147549184L,2851995647L],
                [2852061184L,2886729727L],
                [2886795264L,3221159935L],
                [3221226240L,3227017983L],
                [3227018240L,3232235519L],
                [3232301056L,3323068415L],
                [3323199488L,3758096127L]
                ])
        else:
            randomchoice = [0,4294967295L]
        randint = random.randint(*randomchoice)
        ip = numToDottedQuad(randint)
        if ip not in database:
            database[ip] = ''
            for port in portrange:
                for method in methods:                    
                    yield(ip,port,method)
        else:
            log.debug( 'found dup %s' % ip)

def scanrandom(ipranges,portrange,methods,resume=False,scanspecialips=False):
    import random
    from iphelper import numToDottedQuad,dottedQuadToNum
    import anydbm
    import logging
    log = logging.getLogger('scanrandom')
    mode = 'n'
    if resume:
        mode = 'w'    
    database = anydbm.open('.sipvicious_random',mode)
    ipsleft = 0
    for iprange in ipranges:
        ipsleft += iprange[1] - iprange[0]    
    while ipsleft > 0:
        randomchoice = random.choice(ipranges)
        #randomchoice = [0,4294967295L]
        randint = random.randint(*randomchoice)
        ip = numToDottedQuad(randint)
        if ip not in database:
            database[ip] = ''
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