#!/usr/bin/env python

#   Helper.py keeps the rest of the tools clean - part of SIPVicious tools
#   Copyright (C) 2007  Sandro Gauci <sandrogauc@gmail.com>
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
__version__ = '0.2'

import base64,struct,socket,logging

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
            numericrange.append(xrange(startport,endport))
        else:
            if not _tmp3[0].isdigit():
                raise ValueError, "the ranges need to be digits"                
                return
            singleport = int(_tmp3[0])
            numericrange.append(xrange(singleport,singleport+1))
    return numericrange


def numericbrute(rangelist,zeropedding=0):
    format = '%%0%su' % zeropedding
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

def parseHeader(buff,type='response'):
    SEP = '\r\n\r\n'
    import logging
    log = logging.getLogger('parseHeader')
    if SEP in buff:
        header,body = buff.split(SEP,1)
    else:
        header = buff
    headerlines = header.splitlines()
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
    tagRE='(From|f): .*?\;\s*tag=([=+/\.:a-zA-Z0-9_]+)'    
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
    

def makeRequest(method,fromaddr,toaddr,dsthost,port,callid,srchost='',branchunique=None,cseq=1,auth=None,localtag=None,compact=False,contact=None,accept='application/sdp',contentlength=0,localport=5060):
    uri = 'sip:%s' % dsthost    
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
        if contact is not None:
            headers['m'] = contact
    else:
        superheaders['Via'] = 'SIP/2.0/UDP %s:%s;branch=z9hG4bK-%s;rport' % (srchost,localport,branchunique)
        headers['Max-Forwards'] = 70    
        headers['To'] = toaddr
        headers['From'] = fromaddr
        if localtag is not None:
            headers['From'] += '; tag=%s' % localtag
        headers['Call-ID'] = callid
        if contact is not None:
            headers['Contact'] = contact
    headers['CSeq'] = '%s %s' % (cseq,method)
    headers['Max-Forwards'] = 70
    headers['Accept'] = accept
    headers['Content-Length'] = contentlength
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
    import logging
    from sys import argv
    log = logging.getLogger('reportBugToAuthor')
    data = str()
    data += "Command line parameters:\r\n"
    data += str(argv)
    data += '\r\n'
    data += 'version: %s' % __version__
    data += '\r\n\r\n'
    data += "Trace:\r\n"
    data += str(trace)
    try:
        urlopen('http://geekbazaar.org/bugreport/r.php',data)
    except URLError,err:
        log.error( err )

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
        if ip not in database:
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
	
def listsessions(chosensessiontype=None):	
	listresult = findsession(chosensessiontype)
	for k in listresult.keys():
		print "Type of scan: %s" % k
		for r in listresult[k]:
			print "\t%s" % r
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
			#sessiontype = chosensessiontype
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

    

if __name__ == '__main__':
    print getranges('1.1.1.1/24')
    seq = getranges('google.com/24')    
    if seq is not None:
        a = ip4range(seq)
        for x in iter(a):
            print x

