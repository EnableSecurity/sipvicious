#!/usr/bin/env python
# svmap.py - SIPvicious scanner

__GPL__ = """

   SIPvicious scanner is a scanner to search for SIP devices
   Copyright (C) 2007  Sandro Gauci <sandrogauc@gmail.com>

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

__author__ = "Sandro Gauci <sandrogauc@gmail.com>"
__version__ = '0.1-svn'

import socket
import select

import random
from struct import pack,unpack


class DrinkOrSip:
    def __init__(self,scaniter,selecttime=0.005,compact=True, bindingip='',
                 fromname='sipvicious',fromaddr='sip:100@1.1.1.1', outputcsv=None,
                 sessionpath=None,socktimeout=3,externalip=None,localport=5060):
        import logging,anydbm
        import os.path
	from helper import packetcounter
        self.log = logging.getLogger('DrinkOrSip')
        self.bindingip = bindingip
	self.sessionpath = sessionpath
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
            self.externalip = socket.gethostbyname(socket.gethostname())
        else:
            self.externalip = externalip
        self.log.debug("External ip: %s:%s" % (self.externalip,localport) )       
        self.compact = compact
        self.log.debug("Compact mode: %s" % self.compact)
        self.fromname = fromname        
        self.fromaddr = fromaddr
        self.log.debug("From: %s <%s>" % (self.fromname,self.fromaddr))
        self.nomoretoscan = False
        self.originallocalport = self.localport
        if outputcsv is not None:
            import csv
            self.outputcsv = csv.writer(open(outputcsv,'wb'))
        else:
            self.outputcsv = None
        self.nextip = None
	if self.sessionpath is not None:
	        self.packetcount = packetcounter(50)
    
    def getResponse(self,buff,srcaddr):
        from helper import fingerPrintPacket,getTag
        srcip,srcport = srcaddr                
        if buff.startswith('OPTIONS ') \
            or buff.startswith('INVITE ') \
            or buff.startswith('REGISTER '): 
            self.log.info("Looks like we received our own packet")
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
            self.log.debug("Uaname: %s" % uaname)
            #print buff
            originaldst = getTag(buff)
            try:
                dstip = socket.inet_ntoa(pack('!L',int(originaldst[:8],16)))
                dstport = int(originaldst[8:12],16)
            except (ValueError,TypeError,socket.error):
                self.log.debug("original destination could not be decoded: %s" % (originaldst))
                dstip,dstport = 'unknown','unknown'            
            resultstr = '%s:%s\t->\t%s:%s\t->\t%s\t' % (dstip,dstport,srcip,srcport,uaname)
            self.log.info( resultstr )
            if self.outputcsv is not None:
                self.outputcsv.writerow((dstip,dstport,srcip,srcport,uaname))
                
    def start(self):
        from helper import makeRequest
        import socket
        # bind to 5060 - the reason is to maximize compatability with
        # devices that disregard the source port and send replies back
        # to port 5060
        if self.bindingip == '':
            bindingip = 'any'
        else:
            bindingip = self.bindingip
        self.log.debug("binding to %s:%s" % (bindingip,self.localport))
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
                
                localtag = '%s%s' % (''.join(map(lambda x: '%02x' % int(x), dsthost[0].split('.'))),'%04x' % dsthost[1])
                cseq = 1
                fromaddr = '"%s"<%s>' % (self.fromname,self.fromaddr)
                toaddr = fromaddr
                callid = '%s' % random.getrandbits(80)
                contact = None
                if method == 'INVITE' or method == 'OPTIONS':
                    contact = 'sip:1000@%s:%s' % (dsthost[0],dsthost[1])
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
                                contact=contact
                                )
                try:
                    self.log.debug("sending packet to %s:%s" % dsthost)
                    self.sock.sendto(data,dsthost)                    
		    if self.sessionpath is not None:
			    if self.packetcount.next():
				try:
					f=open(os.path.join(self.sessionpath,'lastip.txt'),'w')
					f.write(self.nextip)
					f.close()
					self.log.debug('logged last ip %s' % self.nextip)
				except IOError:
					self.log.warn('could not log the last ip scanned')
                except socket.error,err:
                    self.log.error( "socket error while sending to %s:%s -> %s" % (dsthost[0],dsthost[1],err))
                    pass

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    import anydbm
    import os
    from sys import exit
    import logging
    import pickle
    usage = "usage: %prog [options] host1 host2 hostrange\r\n"
    usage += "example: %prog 10.0.0.1-10.0.0.255 "
    usage += "172.16.131.1 sipvicious.org/22 10.0.1.1/24 "
    usage += "1.1.1.1-20 1.1.2-20.* 4.1.*.*"
    parser = OptionParser(usage, version="%prog v"+str(__version__)+__GPL__)
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False,
                      help="Quiet mode")
    parser.add_option("-s", "--save", dest="save",
                  help="save the session. Has the benefit of allowing you to resume a previous scan and allows you to export scans", metavar="NAME")    
    parser.add_option("--resume", dest="resume",
                  help="resume a previous sessname", metavar="NAME")    
    parser.add_option("-o", "--outputcsv", dest="outputcsv",
                  help="Output results to a specified csv file", metavar="output.csv")
    parser.add_option("--randomscan", dest="randomscan", action="store_true",
                      default=False,
                  help="Scan random IP addresses")
    parser.add_option("-i", "--input", dest="inputcsv",
                  help="Input csv based on previous results", metavar="input.csv")
    parser.add_option("-p", "--port", dest="port", default='5060',
                  help="Destination port or port ranges of the SIP device - eg -p5060,5061,8000-8100", metavar="PORT")
    parser.add_option("-P", "--localport", dest="localport", default=5060, type="int",
                  help="Source port for our packets", metavar="PORT")
    parser.add_option("-x", "--externalip", dest="externalip", default='localhost',
                  help="IP Address to use as the external ip. Specify this if you have multiple interfaces or if you are behind NAT", metavar="IP")
    parser.add_option("-b", "--bindingip", dest="bindingip", default='',
                  help="By default we bind to all interfaces. This option overrides that and binds to the specified ip address")
    parser.add_option("-t", "--timeout", dest="selecttime", type="float",
                      default=0.005,
                    help="Timeout for the select() function. Change this if you're losing packets",
                  metavar="SELECTTIME")        
    parser.add_option("-c", "--enablecompact", dest="enablecompact", default=False, 
                  help="enable compact mode. Makes packets smaller but possibly less compatable",
                  action="store_true",
                  )
    parser.add_option("-m", "--method", dest="method", 
                  help="Specify the request method - by default this is OPTIONS.",
                  default='OPTIONS'
                  )
    parser.add_option("-R", "--reportback", dest="reportBack", default=False, action="store_true",
                  help="Send the author an exception traceback. Currently sends the command line parameters and the traceback",                  
                  )
    parser.add_option("--randomize", dest="randomize", action="store_true",
                      default=False,
                  help="Randomize scanning instead of scanning consecutive ip addresses")
    (options, args) = parser.parse_args()        
    from helper import getRange, scanfromfile, scanlist, scanrandom, getranges,ip4range, resumeFromIP
    exportpath = None
    if options.resume is not None:
        exportpath = os.path.join('.sipvicious','svmap',options.resume)
        optionssrc = os.path.join(exportpath,'options.pkl')
	previousresume = options.resume
        options,args = pickle.load(open(optionssrc,'r'))        
	options.resume = previousresume
    logginglevel = 20
    if options.verbose is not None:
        for somecount in xrange(options.verbose):
            if logginglevel > 10:
                logginglevel = logginglevel-10
    if options.quiet:
        logginglevel = 50
    logging.basicConfig(level=logginglevel)
    logging.debug('started logging')

    if options.inputcsv is not None:
        import csv
        reader = csv.reader(open(options.inputcsv,'rb'))
        scaniter = scanfromfile(reader,options.method.split(','))
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
        scaniter = scanrandom(internetranges,portrange,options.method.split(','))
    else:
        if len(args) < 1:
            parser.print_help()
            exit(1)        
        logging.debug('parsing range of ports: %s' % options.port)
        portrange = getRange(options.port)
        if options.randomize:
            scaniter = scanrandom(map(getranges,args),portrange,options.method.split(','))
        else:
            if options.resume is not None:
                lastipsrc = os.path.join(exportpath,'lastip.txt')
                try:
                    f=open(lastipsrc,'r')
                    previousip = f.read()
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
            exportpath = os.path.join('.sipvicious','svmap',options.save)
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
    sipvicious = DrinkOrSip(
                    scaniter,
                    selecttime=options.selecttime,
                    compact=options.enablecompact,
                    localport=options.localport,                    
                    outputcsv=options.outputcsv,
                    externalip=options.externalip,
                    bindingip=options.bindingip,
                    sessionpath=exportpath,
                    )
    start_time = datetime.now()
    logging.info( "start your engines" )
    try:
        sipvicious.start()
    except KeyboardInterrupt:
        logging.warn( 'caught your control^c - quiting' )
        pass
    except Exception, err:
        import traceback
        from helper import reportBugToAuthor 
        if options.reportBack:
            logging.critical( "Got unhandled exception : sending report to author" )
            reportBugToAuthor(traceback.format_exc())
        else:
            logging.critical( "Unhandled exception - please run same command with the -R option to send me an automated report")
            pass
        logging.exception( "Exception" )
    if options.save is not None and sipvicious.nextip is not None:
   	lastipdst = os.path.join(exportpath,'lastip.txt')
   	logging.debug('saving state to %s' % lastipdst)
        try:
            f = open(lastipdst,'w')
            f.write(sipvicious.nextip)
            f.close()
        except OSError:
            logging.warn('Could not save state to %s' % lastipdst)
    end_time = datetime.now()
    total_time = end_time - start_time
    logging.info("Total time: %s" %  total_time)
