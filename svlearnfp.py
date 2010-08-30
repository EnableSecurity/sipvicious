#!/usr/bin/env python
# helps create new signatures for the SIP fingerprinting tool


def prompt_yesno(msg,default='y'):
    import sys
    response = "Boo!"
    while response not in ['y','n']:
        sys.stdout.write("%s: " % (msg))
        response = sys.stdin.readline().lower().strip()
        if response == '':
            response = '%s' % default
    if response == 'n':
        r = False
    elif response == 'y':
        r = True
    else:
        raise ValueError
    return r

def collectpackets(dstaddrs,localport,fromaddr,toaddr,bindingip,selecttime=0.005,noisy=False,samples=1000,method='OPTIONS',localip=None):
    import logging, socket, select, random
    from time import sleep
    from sys import stdout
    log = logging.getLogger('collectpackets')
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.settimeout(2)
    bindresult = bindto(bindingip,localport,s)
    if bindresult is None:
        sys.exit(1)
    localport,s = bindresult
    if localip is None:
        log.debug("local ip was not set")
        if bindingip != '0.0.0.0':
            log.debug("but bindingip was set! we'll set it to the binding ip")
            localip = bindingip
        else:
            try:
                log.info("trying to get self ip .. might take a while")
                localip = socket.gethostbyname(socket.gethostname())
                log.info("ok got %s" % localip)
            except socket.error:
                localip = '127.0.0.1'
    else:
        log.debug("external ip was set")
    myaddr = ':'.join((localip,str(localport)))
    externalip = bindingip
    rlist = [s]
    wlist = list()
    xlist = list()
    i = 0
    while samples > i:
        for dstaddr in dstaddrs:
            r, w, e = select.select(
                rlist,
                wlist,
                xlist,
                selecttime
                )
            if r:
                try:
                    buff,srcaddr = s.recvfrom(8192)
                    if not buff.startswith('SIP/2.0 10'):
                        log.debug('got data from %s:%s' % srcaddr)
                        log.debug('data: %s' % `buff`)
                        responses.append(buff)
                    if noisy:
                        stdout.write(".")
                        stdout.flush()
                except socket.error:
                    continue
            else:
                if samples < i:                    
                    break
                i += 1
                branchunique = '%s' % random.getrandbits(32)
                callid = '%s' % random.getrandbits(80)
                localtag = '%s%s' % (''.join(map(lambda x: '%02x' % int(x), \
                                            socket.gethostbyname(dstaddr[0]).split('.'))),'%04x' % dstaddr[1])
                request = makeRequest(
                        method,
                        fromaddr,
                        toaddr,
                        dstaddr[0],
                        dstaddr[1],
                        callid,
                        externalip,
                        branchunique,
                        localtag=localtag,
                        accept='application/sdp',
                        localport=localport,
                        )
                log.debug("sending request: %s" % `request`)
                if noisy:
                    stdout.write("_")
                    stdout.flush()
                s.sendto(request,dstaddr)
            
    try:
        # having the final sip 
        log.debug("Making sure that no packets get lost")
        log.debug("Come to daddy")
        while 1:
            buff,srcaddr = s.recvfrom(8192)
            if not buff.startswith('SIP/2.0 10'):
                log.debug('got data from %s:%s' % srcaddr)
                log.debug('data: %s' % `buff`)
                responses.append(buff)
            if noisy:
                stdout.write(".")
                stdout.flush()
    except socket.error:
        return

if __name__ == '__main__':
    from svfphelper import fpdynamic, fpstatic, getdynamic, getstatic, hashstatic,fpstore, fpdynamicstore
    from svfphelper import getfingerprints, getheader, fpexists, uploadfp
    from optparse import OptionParser
    from svhelper import makeRequest, calcloglevel, fingerPrintPacket, standardoptions, bindto
    from regen import generateregex
    import logging
    import sys,re
    log = logging.getLogger('')
    usage = '%prog [siphost]\r\n'
    usage += 'example: %prog 10.0.0.2\r\n'
    parser = OptionParser(usage)
    parser = standardoptions(parser)
    parser.add_option('--force',dest="force", action="store_true", default=False,
                      help="This tool is not supported anymore and is being rewritten. If you really want to use it you need force ;-)")
    parser.add_option("-S","--samples", dest="samples", type="int", default=222,
                  help="Number of samples to take")
    parser.add_option("--customregex", dest="re", action="store_true", default=False,
                      help="Specify a regular expression and override the automatically generated one. Do not use unless you know what you're doing")
    parser.add_option("--auto", dest="auto", action="store_true", default=False,
                      help="automatically process and save the fingerprint")
    (options, args) = parser.parse_args()
    if not options.force:
        parser.error("This tool is not supported anymore and is being rewritten. If you really want to use it you need force ;-)")
        sys.exit()
    if len(args) < 1:
        parser.error("please specify a sip host")
        sys.exit(2)
    dsthosts = args
    
    servername = None
    logging.basicConfig(level=calcloglevel(options))
    logging.debug('started logging')

    
    dstaddrs = map(lambda x: (x,int(options.port)),dsthosts)
    responses = list()
    method='OPTIONS'
    fromaddr = '"sipvicious"<sip:100@1.1.1.1>'
    toaddr = fromaddr
    try:
        collectpackets(
            dstaddrs,
            options.localport,
            fromaddr,
            toaddr,
            options.bindingip,
            selecttime=options.selecttime,
            method='OPTIONS',
            noisy=True,
            samples=options.samples,
            localip=options.externalip
            )
    except KeyboardInterrupt:
        pass
    print
    if len(responses) < 1:
        logging.warn("no response")
        sys.exit(1)
    totagregex,statichashes = getfingerprints(responses)
    response = 'Boo!'
    fp = fingerPrintPacket(responses[0])
    if fp.has_key('name'):
        defaultua = fp['name'][0]
        defaultuastr = '[%s]' % defaultua
    else:
        defaultua, defaultuastr = '','(could not guess name - please specify)'
    if options.auto:
        # non interactive mode
        servername = defaultua        
    else:
        # interactive friendly mode
        try:
            ok = prompt_yesno("Would you like to define this fingerprint? [Y]","y")
            if not ok:
                sys.exit(1)    
            if options.re:
                regexisbad = True
                while regexisbad:
                    sys.stdout.write("To tag regex [%s]: " % totagregex)
                    newtotagregex = sys.stdin.readline().strip()
                    if len(newtotagregex) > 0:
                        try:
                            re.match(newtotagregex,"teststring")
                            totagregex = newtotagregex                
                            regexisbad = False                            
                        except:
                            sys.stdout.write("Bad regex!\r\n")
                    else:
                        regexisbad = False
            sys.stdout.write("Name of server %s: " % defaultuastr)
            servername = sys.stdin.readline().strip()
            if servername == '':
                servername = defaultua
            if servername == '':
                logging.error("No server name given")
                sys.exit(1)
            logging.debug("servername: %s" % servername)
            logging.debug("to tag regex: %s" % totagregex)
            logging.debug("checking if server name already exists")
            if fpexists(servername):
                sys.stdout.write("WARNING: A fingerprint for this server was already defined\r\n")
                defaultresponse = 'n'                
                question = "Save? [N]"
            else:
                question = "Save? [Y]"
                defaultresponse = 'y'
            ok = prompt_yesno(question,defaultresponse)
            if not ok:
                sys.exit(1)
        except KeyboardInterrupt:
            logging.warn("Caught keyboard interrupt")
            sys.exit(1)
    logging.info("saving as %s with regex %s" % (servername,totagregex))
    for fullhash,orderhash,headerhashes in statichashes:
        logging.debug("Saving fullhash: %s" % fullhash)
        logging.debug("Saving orderhash: %s" % orderhash)
        logging.debug("Saving headerhashes: %s" % headerhashes)
        fpstore(servername,fullhash,headerhashes)
    fpdynamicstore(servername,totagregex)
    if not options.auto:
        ok = prompt_yesno("Send this fingerprint to the author (recommended)? [Y]",'y')
        if not ok:
            logging.debug("That's not so nice")
            sys.exit(1)
        emailaddr = raw_input("Your email address (optional): ")
        if uploadfp(servername,statichashes,totagregex,emailaddr) is not None:
            sys.stdout.write("Thanks!\r\n")
