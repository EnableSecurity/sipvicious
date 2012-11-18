#!/usr/bin/env python
# svmap.py - SIPvicious SIP scanner

__GPL__ = """

   SIPvicious SIP scanner searches for SIP devices on a given network
   Copyright (C) 2012  Sandro Gauci <sandro@enablesecurity.com>

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

from svhelper import __author__, __version__
__prog__ = "svmap"

import socket
import select

import random
from struct import pack,unpack


class DrinkOrSip:
    def __init__(self,scaniter,selecttime=0.005,compact=False, bindingip='0.0.0.0',
                 fromname='sipvicious',fromaddr='sip:100@1.1.1.1', extension=None,
                 sessionpath=None,socktimeout=3,externalip=None,localport=5060,
                 printdebug=False,first=None,fpworks=False):
        import logging,anydbm
        import os.path
        from svhelper import packetcounter
        #from svfphelper import sipfingerprint
        #self.sipfingerprint = sipfingerprint
        self.log = logging.getLogger('DrinkOrSip')
        self.bindingip = bindingip
        self.sessionpath = sessionpath
        self.dbsyncs = False
        if self.sessionpath is not  None:
            self.resultip = anydbm.open(os.path.join(self.sessionpath,'resultip'),'c')
            self.resultua = anydbm.open(os.path.join(self.sessionpath,'resultua'),'c')
            self.resultfp = anydbm.open(os.path.join(self.sessionpath,'resultfp'),'c')
            try:
                self.resultip.sync()
                self.dbsyncs = True
                self.log.info("Db does sync")
            except AttributeError:
                self.log.info("Db does not sync")
                pass
        else:
            self.resultip = dict()
            self.resultua = dict()
            self.resultfp = dict()
        # we do UDP
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        # socket timeout - this is particularly useful when quitting .. to eat
        # up some final packets
        self.sock.settimeout(socktimeout)
        # enable sending to broadcast addresses
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # read handles
        self.rlist = [self.sock]
        # write handles
        self.wlist = list()
        # error handles
        self.xlist = list()
        self.scaniter = scaniter
        self.selecttime = selecttime
        self.localport = localport
        if externalip is None:
            self.log.debug("external ip was not set")
            if (self.bindingip != '0.0.0.0') and (len(self.bindingip) > 0):
                self.log.debug("but bindingip was set! we'll set it to the binding ip")
                self.externalip = self.bindingip
            else:
                try:
                    self.log.info("trying to get self ip .. might take a while")
                    self.externalip = socket.gethostbyname(socket.gethostname())
                except socket.error:
                    self.externalip = '127.0.0.1'
        else:
            self.log.debug("external ip was set")
            self.externalip = externalip
        self.log.debug("External ip: %s:%s" % (self.externalip,localport) )
        self.compact = compact
        self.log.debug("Compact mode: %s" % self.compact)
        self.fromname = fromname        
        self.fromaddr = fromaddr
        self.log.debug("From: %s <%s>" % (self.fromname,self.fromaddr))
        self.nomoretoscan = False
        self.originallocalport = self.localport
        self.nextip = None
        self.extension = extension
        self.fpworks = fpworks
        self.printdebug = printdebug
        self.first = first
        if self.sessionpath is not None:
            self.packetcount = packetcounter(50)
        self.sentpackets = 0
    
    def getResponse(self,buff,srcaddr):
        from svhelper import fingerPrintPacket,getTag
        srcip,srcport = srcaddr
        uaname = 'unknown'
        if buff.startswith('OPTIONS ') \
            or buff.startswith('INVITE ') \
            or buff.startswith('REGISTER '): 
            if self.externalip == srcip:
                self.log.debug("We received our own packet from %s:%s" % srcaddr)
            else: 
                self.log.info("Looks like we received a SIP request from %s:%s"% srcaddr)
                self.log.debug(repr(buff))            
            return
        self.log.debug("running fingerPrintPacket()")
        res = fingerPrintPacket(buff)
        if res is not None:
            if res.has_key('name'):
                uaname = res['name'][0]
            else:
                uaname = 'unknown'
                self.log.debug(`buff`)
            #if self.fpworks:
            #    try:
            #        fp = self.sipfingerprint(buff)
            #    except:
            #        self.log.error("fingerprinting gave errors - will be disabled")
            #        self.fpworks = False
            if not self.fpworks:
                fp = None
            if fp is None:
                if self.fpworks:
                    fpname = 'unknown'
                else:
                    fpname = 'disabled'
            else:
                fpname = ' / '.join(fp)
            self.log.debug('Fingerprint: %s' % fpname)
            self.log.debug("Uaname: %s" % uaname)
            #print buff
            originaldst = getTag(buff)
            try:
                dstip = socket.inet_ntoa(pack('!L',int(originaldst[:8],16)))
                dstport = int(originaldst[8:12],16)
            except (ValueError,TypeError,socket.error):
                self.log.debug("original destination could not be decoded: %s" % (originaldst))
                dstip,dstport = 'unknown','unknown'            
            resultstr = '%s:%s\t->\t%s:%s\t->\t%s\t->\t%s' % (dstip,dstport,srcip,srcport,uaname,fpname)
            self.log.info( resultstr )
            self.resultip['%s:%s' % (srcip,srcport)] = '%s:%s' % (dstip,dstport)
            self.resultua['%s:%s' % (srcip,srcport)] = uaname
            self.resultfp['%s:%s' % (srcip,srcport)] = fpname
            if self.sessionpath is not None and self.dbsyncs:
                    self.resultip.sync()
                    self.resultua.sync()
                    self.resultfp.sync()
        else:
            self.log.info('Packet from %s:%s did not contain a SIP msg'%srcaddr)
            self.log.debug('Packet: %s' % `buff`)
                
    def start(self):
        from svhelper import makeRequest, createTag
        from svhelper import mysendto
        import socket
        # bind to 5060 - the reason is to maximize compatability with
        # devices that disregard the source port and send replies back
        # to port 5060
        self.log.debug("binding to %s:%s" % (self.bindingip,self.localport))
        while 1:
            if self.localport > 65535:
                self.log.critical("Could not bind to any port")
                return
            try:            
                self.sock.bind((self.bindingip,self.localport))
                break
            except socket.error:
                self.log.debug("could not bind to %s" % self.localport)
                self.localport += 1            
        if self.originallocalport != self.localport:
            self.log.warn("could not bind to %s:%s - some process might already be listening on this port. Listening on port %s instead" % (self.bindingip,self.originallocalport, self.localport))
            self.log.info("Make use of the -P option to specify a port to bind to yourself")
        while 1:
            r, w, e = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                self.selecttime
                )
            if r:
                # we got stuff to read off the socket
                try:
                    buff,srcaddr = self.sock.recvfrom(8192)
                    self.log.debug('got data from %s:%s' % srcaddr)
                    self.log.debug('data: %s' % `buff`)
                    if self.printdebug:
                        print srcaddr
                        print buff
                except socket.error:
                    continue
                self.getResponse(buff,srcaddr)
            else:
                # no stuff to read .. its our turn to send back something
                if self.nomoretoscan:                    
                    try:
                        # having the final sip 
                        self.log.debug("Making sure that no packets get lost")
                        self.log.debug("Come to daddy")
                        while 1:
                            buff,srcaddr = self.sock.recvfrom(8192)
                            if self.printdebug:
                                print srcaddr
                                print buff
                            self.getResponse(buff,srcaddr)
                    except socket.error:
                        break
                try:
                    nextscan = self.scaniter.next()
                except StopIteration:
                    self.log.debug('no more hosts to scan')
                    self.nomoretoscan = True
                    continue
                dstip,dstport,method = nextscan
                self.nextip = dstip
                dsthost = (dstip,dstport)
                branchunique = '%s' % random.getrandbits(32)
                
                localtag = createTag('%s%s' % (''.join(map(lambda x: '%02x' % int(x), dsthost[0].split('.'))),'%04x' % dsthost[1]))
                cseq = 1
                fromaddr = '"%s"<%s>' % (self.fromname,self.fromaddr)
                toaddr = fromaddr
                callid = '%s' % random.getrandbits(80)
                contact = None
                if method != 'REGISTER':
                    contact = 'sip:%s@%s:%s' % (self.extension,self.externalip,self.localport)
                data = makeRequest(
                                method,
                                fromaddr,
                                toaddr,
                                dsthost[0],
                                dsthost[1],
                                callid,
                                self.externalip,
                                branchunique,
                                compact=self.compact,
                                localtag=localtag,
                                contact=contact,
                                accept='application/sdp',
                                localport=self.localport,
                                extension=self.extension
                                )
                try:
                    self.log.debug("sending packet to %s:%s" % dsthost)
                    self.log.debug("packet: %s" % `data`)
                    mysendto(self.sock,data,dsthost)
                    self.sentpackets += 1
                    #self.sock.sendto(data,dsthost)    
                    if self.sessionpath is not None:
                        if self.packetcount.next():
                            try:
                                f=open(os.path.join(self.sessionpath,'lastip.pkl'),'w')
                                pickle.dump(self.nextip,f)
                                f.close()
                                self.log.debug('logged last ip %s' % self.nextip)
                            except IOError:
                                self.log.warn('could not log the last ip scanned')
                    if self.first is not None:
                        if self.sentpackets >= self.first:
                            self.log.info('Reached the limit to scan the first %s packets' % self.first)
                            self.nomoretoscan = True
                except socket.error,err:
                    self.log.error( "socket error while sending to %s:%s -> %s" % (dsthost[0],dsthost[1],err))
                    pass

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    import anydbm
    import os
    from svhelper import standardoptions, standardscanneroptions, calcloglevel
    from sys import exit
    import logging
    import pickle
    usage = "usage: %prog [options] host1 host2 hostrange\r\n"
    usage += 'Scans for SIP devices on a given network\r\n\r\n'
    usage += "examples:\r\n\r\n"
    usage += "%prog 10.0.0.1-10.0.0.255 "
    usage += "172.16.131.1 sipvicious.org/22 10.0.1.1/24"
    usage += "1.1.1.1-20 1.1.2-20.* 4.1.*.*\r\n\r\n"
    usage += "%prog -s session1 --randomize 10.0.0.1/8\r\n\r\n"
    usage += "%prog --resume session1 -v\r\n\r\n"
    usage += "%prog -p5060-5062 10.0.0.3-20 -m INVITE\r\n\r\n"
    parser = OptionParser(usage, version="%prog v"+str(__version__)+__GPL__)
    parser = standardoptions(parser)
    parser = standardscanneroptions(parser)
    parser.add_option("--randomscan", dest="randomscan", action="store_true",
                      default=False,
                  help="Scan random IP addresses")
    parser.add_option("-i", "--input", dest="input",
                  help="Scan IPs which were found in a previous scan. Pass the session name as the argument", metavar="scan1")
    parser.add_option("-I", "--inputtext", dest="inputtext",
                  help="Scan IPs from a text file - use the same syntax as command line but with new lines instead of commas. Pass the file name as the argument", metavar="scan1")
    parser.add_option("-m", "--method", dest="method", 
                  help="Specify the request method - by default this is OPTIONS.",
                  default='OPTIONS'
                  )
    parser.add_option("-d", "--debug", dest="printdebug", 
                  help="Print SIP messages received",
                  default=False, action="store_true"
                  )
    parser.add_option("--first", dest="first", 
                  help="Only send the first given number of messages (i.e. usually used to scan only X IPs)",
                  type="long",
                  )
    parser.add_option("-e", "--extension", dest="extension", default='100',
                  help="Specify an extension - by default this is not set")
    parser.add_option("--randomize", dest="randomize", action="store_true",
                      default=False,
                  help="Randomize scanning instead of scanning consecutive ip addresses")
    parser.add_option("--srv", dest="srvscan", action="store_true",
                      default=False,
                  help="Scan the SRV records for SIP on the destination domain name." \
                       "The targets have to be domain names - example.org domain1.com")
    parser.add_option('--fromname',dest="fromname", default="sipvicious",
                      help="specify a name for the from header")
    (options, args) = parser.parse_args()        
    from svhelper import getRange, scanfromfile, scanlist, scanrandom, getranges,\
        ip4range, resumeFromIP, scanfromdb, dbexists, getTargetFromSRV
    exportpath = None
    if options.resume is not None:
        exportpath = os.path.join('.sipvicious',__prog__,options.resume)
        if os.path.exists(os.path.join(exportpath,'closed')):
            logging.error("Cannot resume a session that is complete")
            exit(1)
        if not os.path.exists(exportpath):
            logging.critical('A session with the name %s was not found'% options.resume)
            exit(1)
        optionssrc = os.path.join(exportpath,'options.pkl')
        previousresume = options.resume
        previousverbose = options.verbose
        options,args = pickle.load(open(optionssrc,'r'))        
        options.resume = previousresume
        options.verbose = previousverbose
    elif options.save is not None:
        exportpath = os.path.join('.sipvicious',__prog__,options.save)
    logging.basicConfig(level=calcloglevel(options))
    logging.debug('started logging')
    scanrandomstore = None 
    if options.input is not None:
        db = os.path.join('.sipvicious',__prog__,options.input,'resultua')
        if dbexists(db):
            scaniter = scanfromdb(db,options.method.split(','))
        else:
            logging.error("the session name does not exist. Please use svreport to list existing scans")
            exit(1)
    elif options.randomscan:
        logging.debug('making use of random scan')
        logging.debug('parsing range of ports: %s' % options.port)
        portrange = getRange(options.port)
        internetranges =[[16777216,167772159],
                        [184549376,234881023],
                        [251658240,2130706431],
                        [2147549184L,2851995647L],
                        [2852061184L,2886729727L],
                        [2886795264L,3221159935L],
                        [3221226240L,3227017983L],
                        [3227018240L,3232235519L],
                        [3232301056L,3323068415L],
                        [3323199488L,3758096127L]
                        ]
        scanrandomstore = '.sipviciousrandomtmp'
        resumescan = False 
        if options.save is not None:
            scanrandomstore = os.path.join(exportpath,'random')
            resumescan = True
        scaniter = scanrandom(
                        internetranges,
                        portrange,
                        options.method.split(','),
                        randomstore=scanrandomstore,
                        resume=resumescan
                        )
    elif options.inputtext:
        logging.debug('Using IP addresses from input text file')
        try:
            f = open(options.inputtext,'r')
            args = f.readlines()
            f.close()
        except IOError:
            logging.critical('Could not open %s' % options.inputtext)
            exit(1)
        args = map(lambda x: x.strip(), args)
        args = filter(lambda x: len(x) > 0, args)
        logging.debug('ip addresses %s' % args)
        try:
            iprange = ip4range(*args)
        except ValueError,err:
            logging.error(err)
            exit(1)
        portrange = getRange(options.port)
        if options.randomize:
            scanrandomstore = '.sipviciousrandomtmp'
            resumescan = False
            if options.save is not None:
                scanrandomstore = os.path.join(exportpath,'random')
                resumescan = True
            scaniter = scanrandom(map(getranges,args),portrange,options.method.split(','),randomstore=scanrandomstore,resume=resumescan)
        else:
            scaniter = scanlist(iprange,portrange,options.method.split(','))            
    else:
        if len(args) < 1:
            parser.error('Provide at least one target')
            exit(1)        
        logging.debug('parsing range of ports: %s' % options.port)
        portrange = getRange(options.port)
        if options.randomize:
            scanrandomstore = '.sipviciousrandomtmp'
            resumescan = False
            if options.save is not None:
                scanrandomstore = os.path.join(exportpath,'random')
                resumescan = True
            scaniter = scanrandom(map(getranges,args),portrange,options.method.split(','),randomstore=scanrandomstore,resume=resumescan)
        elif options.srvscan:
            logging.debug("making use of SRV records")
            scaniter = getTargetFromSRV(args,options.method.split(','))
        else:
            if options.resume is not None:
                lastipsrc = os.path.join(exportpath,'lastip.pkl')
                try:
                    f=open(lastipsrc,'r')                    
                    previousip = pickle.load(f)
                    f.close()
                except IOError:
                    logging.critical('Could not read from %s' % lastipsrc)
                    exit(1)
                logging.debug('Previous args: %s' % args)
                args = resumeFromIP(previousip,args)
                logging.debug('New args: %s' % args)
                logging.info('Resuming from %s' % previousip)

            # normal consecutive scan
            try:
                iprange = ip4range(*args)
            except ValueError,err:
                logging.error(err)
                exit(1)
            scaniter = scanlist(iprange,portrange,options.method.split(','))    
    if options.save is not None:
        if options.resume is None:
            exportpath = os.path.join('.sipvicious',__prog__,options.save)
            if os.path.exists(exportpath):
                logging.warn('we found a previous scan with the same name. Please choose a new session name')
                exit(1)
            logging.debug('creating an export location %s' % exportpath)
            try:
                os.makedirs(exportpath,mode=0700)
            except OSError:
                logging.critical('could not create the export location %s' % exportpath)
                exit(1)
            optionsdst = os.path.join(exportpath,'options.pkl')
            logging.debug('saving options to %s' % optionsdst)
            pickle.dump([options,args],open(optionsdst,'w'))
    try:
        options.extension
    except AttributeError:
        options.extension = None
    if options.autogetip:
        tmpsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tmpsocket.connect(("msn.com",80))
        options.externalip=tmpsocket.getsockname()[0]
        tmpsocket.close()
    sipvicious = DrinkOrSip(
                    scaniter,
                    selecttime=options.selecttime,
                    compact=options.enablecompact,
                    localport=options.localport,
                    externalip=options.externalip,
                    bindingip=options.bindingip,
                    sessionpath=exportpath,
                    extension=options.extension,
                    printdebug=options.printdebug,
                    first=options.first,
                    fromname=options.fromname,                    
                    )
    start_time = datetime.now()
    logging.info( "start your engines" )
    try:
        sipvicious.start()
        if exportpath is not None:
            open(os.path.join(exportpath,'closed'),'w').close()
    except KeyboardInterrupt:
        logging.warn( 'caught your control^c - quiting' )
        pass
    except Exception, err:
        import traceback
        from svhelper import reportBugToAuthor 
        if options.reportBack:
            logging.critical( "Got unhandled exception : sending report to author" )
            reportBugToAuthor(traceback.format_exc())
        else:
            logging.critical( "Unhandled exception - please run same command with the -R option to send me an automated report")
            pass
        logging.exception( "Exception" )
    if options.save is not None and sipvicious.nextip is not None and options.randomize is False and options.randomscan is False:
        lastipdst = os.path.join(exportpath,'lastip.pkl')
        logging.debug('saving state to %s' % lastipdst)
        try:
            f = open(lastipdst,'w')
            pickle.dump(sipvicious.nextip,f)
            f.close()
        except OSError:
            logging.warn('Could not save state to %s' % lastipdst)
    elif options.save is None:
        if scanrandomstore is not None: 
        #if options.randomize or options.randomscan:
            try:
                    logging.debug('removing %s' % scanrandomstore)
                    os.unlink(scanrandomstore)
            except OSError:
                    logging.warn('could not remove %s' % scanrandomstore)
                    pass
    # display results
    if not options.quiet:
        lenres = len(sipvicious.resultua)
        if lenres > 0:
            logging.info("we have %s devices" % lenres)
            if (lenres < 400 and options.save is not None) or options.save is None:
                from libs.pptable import indent,wrap_onspace
                width = 60
                labels = ('SIP Device','User Agent','Fingerprint')
                rows = list()
                for k in sipvicious.resultua.keys():
                    rows.append((k,sipvicious.resultua[k],sipvicious.resultfp[k]))
                print indent([labels]+rows,hasHeader=True,
                    prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
            else:
                logging.warn("too many to print - use svreport for this")
        else:
            logging.warn("found nothing")
    end_time = datetime.now()
    total_time = end_time - start_time
    logging.info("Total time: %s" %  total_time)
