#!/usr/bin/env python

def getdynamic(buffer):
    """getdynamic parses a string containing a SIP message and returns a
    dictionary object containing dynamic parts of that message"""
    
    # here's a nice list of things that we want to extract
    dynamicheaders = dict()
    dynamicheaders['via'] = dict()
    dynamicheaders['from'] = dict()
    dynamicheaders['to'] = dict()
    dynamicheaders['call-id'] = dict()
    dynamicheaders['contact'] = dict()
    dynamicheaders['warning'] = dict()
    dynamicheaders['content-length'] = dict()
    dynamicheaders['user-agent'] = dict()
    dynamicheaders['warning']['warning'] = '(.*)'    
    dynamicheaders['via']['protocol'] = 'SIP/2.0/(\w+)'
    dynamicheaders['via']['ip'] = 'SIP/2.0/\w+\s*([\w\d\:\.]*)'
    dynamicheaders['via']['received'] = 'received\s*=\s*([^;]*)'
    dynamicheaders['via']['branch'] = 'branch\s*=\s*([^;]*)'
    dynamicheaders['via']['rport'] = 'rport\s*=\s*([^;]*)'
    dynamicheaders['via']['maddr'] = 'maddr\s*=\s*([^;]*)'
    dynamicheaders['via']['ttl'] = 'ttl\s*=\s*([^;]*)'
    dynamicheaders['from']['tag'] = 'tag\s*=\s*([^;]*)'
    dynamicheaders['to']['tag'] = 'tag\s*=\s*([^;]*)'
    dynamicheaders['to']['addr'] = '^\s*(.*?)\;'
    dynamicheaders['from']['addr'] = '^\s*(.*?)=?;'
    dynamicheaders['contact']['addr'] = '(.*)\;*'
    dynamicheaders['call-id']['callid'] = '([\d\w\-\.]+)'
    dynamicheaders['content-length']['length'] = '(.*)'
    dynamicheaders['user-agent']['ua'] = '(.*)'

    
    from helper import parseHeader
    import re
    result = dict()
    ph = parseHeader(buffer)
    if ph.has_key('headers'):
        for dynhead in dynamicheaders.keys():
            if ph['headers'].has_key(dynhead):
                for regexname in dynamicheaders[dynhead].keys():
                    for headerentry in ph['headers'][dynhead]:
                        m = re.search(dynamicheaders[dynhead][regexname],headerentry)
                        if m is not None:
                            if not result.has_key(dynhead):
                                result[dynhead] = dict()
                            result[dynhead][regexname] = m.group(1)                            
    return result

def fpdynamicstoredefault(fpfile="dynamicsign"):
    """ no longer used but kept as an example """
    import cPickle
    try:
        output = open(fpfile,"wb")
    except IOError:
        print "bad"
        return
    dynamicmatch = dict()
    dynamicmatch['to'] = dict()
    dynamicmatch['to']['tag'] = dict()
    dynamicmatch['to']['tag']['brekeke'] = '^\d{13}-\d{7,10}$'
    dynamicmatch['to']['tag']['asterisk'] = '^as[a-f0-9]{8}$'
    dynamicmatch['to']['tag']['3CX PBX'] = '^[a-f0-9]{8}$'
    dynamicmatch['to']['tag']['sjphone'] = '^[a-f0-9]{8,12}$'
    dynamicmatch['to']['tag']['YATE'] = '^\d{9,10}$'
    dynamicmatch['to']['tag']['X-lite'] = dynamicmatch['to']['tag']['3CX PBX']
    dynamicmatch['to']['tag']['wengophone'] = dynamicmatch['to']['tag']['YATE']
    dynamicmatch['to']['tag']['Linksys SPA2102'] = '[a-fA-F0-9]{16}i0'
    cPickle.dump(dynamicmatch,output)
    output.close()

def fpdynamicstore(servername,regex,fpfile="totag"):
    import shelve,os,logging
    log = logging.getLogger('fpdynamicstore')
    if regex is not None:
        try:
            dynamicmatch = shelve.open(fpfile,flag='c')
            dynamicmatch.close()
            return True
        except shelve.error:
            return

def fpdynamic(dyn,fpfile="totag"):
    import shelve
    import logging
    log = logging.getLogger("fpdynamic")
    try:
        dynamicmatch = shelve.open(fpfile,flag='c')
    except shelve.error:
        return    
    import re
    result = list()
    for fpname in dynamicmatch.keys():
        if re.match(dynamicmatch[fpname],dyn):
            result.append(fpname)
    dynamicmatch.close()
    return result
    
def getstatic(buffer,dynamic):
    import logging
    log = logging.getLogger("getstatic")
    sr = list()
    tmpdict = dict()
    for header in dynamic.keys():
        for field in dynamic[header].keys():
            val = dynamic[header][field]
            if not tmpdict.has_key(len(val)):
                tmpdict[len(val)] = list()
            tmpdict[len(val)].append(val)
    sortedlen = tmpdict.keys()
    sortedlen.sort(reverse=True)
    for length in sortedlen:
        for tmp in tmpdict[length]:
            buffer = buffer.replace(tmp,'')
    log.debug("static string: %s" % buffer)
    return buffer

def hashstatic(buffer):
    import sha, re
    totalhashed = sha.new(buffer).hexdigest()
    SEP = '\r\n\r\n'
    HeadersSEP = '\r*\n(?![\t\x20])'
    if SEP in buffer:
        header,body = buffer.split(SEP,1)
    else:
        header = buffer
    headerlines = re.split(HeadersSEP, header)
    hashedheaders = list()
    for headerline in headerlines:
        hashedheader = sha.new(headerline).hexdigest()
        hashedheaders.append(hashedheader)
    orderhash = ''
    return totalhashed,orderhash,hashedheaders

def fpstatic(buffer,fullfn='staticfull',headersfn='staticheaders'):
    totalhashed,orderhashed,hashedheaders = hashstatic(buffer)
    import shelve
    fulldb = shelve.open(fullfn,writeback=True)
    headersdb = shelve.open(headersfn,writeback=True)
    fullguess = None
    if fulldb.has_key(totalhashed):
        fullguess = fulldb[totalhashed]
    headerguess = list()
    for hashedheader in hashedheaders:
        if headersdb.has_key(hashedheader):
            headerguess.extend(headersdb[hashedheader])
    return fullguess,headerguess



def fpstore(servername,fullhash,headerhashes,fullfn='staticfull',headersfn='staticheaders'):
    import shelve
    fulldb = shelve.open(fullfn,writeback=True)
    headersdb = shelve.open(headersfn,writeback=True)
    if fulldb.has_key(fullhash):
        if servername not in fulldb[fullhash]:
            fulldb[fullhash].append(servername)
    else:
        fulldb[fullhash] = [servername]
    for headerhash in headerhashes:
        if headersdb.has_key(headerhash):
            if servername not in headersdb[headerhash]:
                headersdb[headerhash].append(servername)
        else:
            headersdb[headerhash] = [servername]
    fulldb.close()
    headersdb.close()

def _fpcalc(dyn,static):
    results = list()
    if len(dyn) > 0:
        results.extend(dyn*10)
    if static[0] is not None:
        results.extend(static[0]*5)
    results.extend(static[1])    
    uniqueresults = set(results)
    l = 0
    for uniqueresult in uniqueresults:
        totalres = results.count(uniqueresult)
        p = float(totalres) / len(results) * 100
        #print uniqueresult, totalres,"%s%%"%(p)
        if p > l:
            l = p
            s = uniqueresult
        #print results
    return s

def fpcalc(dyn,static):
    results = dict()
    if len(dyn) > 0:
        for d in dyn:
            results[d] = 10
    if static[0] is not None:
        for s in static[0]:            
            if not results.has_key(s):
                results[s] = 0
            results[s] += 5
    if static[1] is not None:
        for s in static[1]:
            if not results.has_key(s):
                results[s] = 0
            results[s] += 1
    return results

def getfingerprints(responses):
    import logging
    from regen import generateregex
    log = logging.getLogger('getfingerprints')
    totags = list()
    statichashes = list()
    for response in responses:
        response = getheader(response)
        dyn = getdynamic(response)
        staticbuff = getstatic(response,dyn)
        _tmp = hashstatic(staticbuff)
        if _tmp not in statichashes:
            statichashes.append(_tmp)
        else:
            log.debug('Already have this static hash')
        if dyn.has_key('to'):
            if dyn['to'].has_key('tag'):
                log.debug("got to tag:%s" % dyn['to']['tag'])
                totags.append(dyn['to']['tag'])
    if len(statichashes) < 1:
        log.warn("no static hash found")
        return
    if len(totags) < 1:
        log.warn("no dynamic tags were found")
        totagregex = None
    else:
        log.debug("Unique to tags: %s" % ','.join(set(totags)))
        totagregex = generateregex(totags)    
    if len(statichashes) > 1:
        log.warn("Static hashes are not so static")
        log.info("static hashes: %s" % statichashes)
    return(totagregex,statichashes)

def getwinners(r):
    l = 0
    res = list()
    for k in r.keys():
        if r[k] > l:
            res = [k]
            l = r[k]
        elif r[k] == l:
            res.append(k)    
    return res

def getheader(buff):
    SEP = "\r\n\r\n"
    splitbuff = buff.split(SEP,2)
    return(splitbuff[0])

def sipfingerprint(response):
    from regen import getbestmatch
    response = getheader(response)
    dyn = getdynamic(response)
    totag=''
    if dyn.has_key('to'):
        if dyn['to'].has_key('tag'):
            totag = dyn['to']['tag']
    staticbuff = getstatic(response,dyn)
    fptotagres = fpdynamic(totag)
    #print fptotagres[
    fpstaticres = fpstatic(staticbuff)
    #print fpstaticres[0]
    #print fpstaticres
    fp = fpcalc(fptotagres,fpstaticres)
    res = getwinners(fp)
    if len(res) > 6:
        bestmatch = getbestmatch(res)
        if len(bestmatch) < 3:
            return
        return [bestmatch]
    return res



if __name__ == "__main__":
    testbuff = ('SIP/2.0 404 Not Found',
                'Via: SIP/2.0/UDP 192.168.1.137:5060;branch=z9hG4bK-X;rport=49938',
                'From: "sipvicious"<sip:100@1.1.1.1>; tag=X'
                'To: "sipvicious"<sip:100@1.1.1.1>;tag=1197140267187-521854730',
                'Call-ID: 1016867877868683084421384',
                'CSeq: 6 OPTIONS',
                'Content-Length: 0')
    buffer = "\r\n".join(testbuff)  + "\r\n"
    print sipfingerprint(buffer)