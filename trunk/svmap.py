#!/usr/bin/env python
# svmap.py - SIPvicious scanner

__GPL__ = """

   SIPvicious scanner is a scanner to search for SIP devices
   Copyright (C) 2007  Sandro Gauci <sandro@sipvicious.org>

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
__version__ = '0.1'

import socket
import select

import random
from struct import pack,unpack
reportBack = False

class DrinkOrSip:
    def __init__(self,scaniter,selecttime=0.005,compact=True,
                 fromname='sipvicious',fromaddr='sip:100@1.1.1.1', outputcsv=None,
                 socktimeout=3,localhost='localhost',localport=5060):
        import logging
        #logging.basicConfig(level=logging.DEBUG)
        self.log = logging.getLogger('DrinkOrSip')
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
        self.localhost = localhost
        self.log.debug("Local: %s:%s" % (self.localhost,localport) )       
        self.compact = compact
        self.log.debug("Compact mode: %s" % self.compact)
        self.fromname = fromname        
        self.fromaddr = fromaddr
        self.log.debug("From: %s <%s>" % (self.fromname,self.fromaddr))
        # bind to 5060 - the reason is to maximize compatability with
        # devices that disregard the source port and send replies back
        # to port 5060
        self.log.debug("Binding just about now")
        self.sock.bind(('',localport))
        self.nomoretoscan = False
        if outputcsv is not None:
            import csv
            self.outputcsv = csv.writer(open(outputcsv,'wb'))
        else:
            self.outputcsv = None
        
    
    def getResponse(self,buff,srcaddr):
        from helper import fingerPrintPacket,getTag
        srcip,srcport = srcaddr                
        if buff.startswith('OPTIONS ') \
            or buff.startswith('INVITE ') \
            or buff.startswith('REGISTER ') :
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
            self.log.debug("Uaname: %s" % uaname)
            #print buff
            originaldst = getTag(buff)
            dstip = socket.inet_ntoa(pack('!L',int(originaldst[:8],16)))
            dstport = int(originaldst[8:12],16)
            print '%s:%s\t->\t%s:%s\t->\t%s' % (dstip,dstport,srcip,srcport,uaname)
            if self.outputcsv is not None:
                self.outputcsv.writerow((dstip,dstport,srcip,srcport,uaname))
                
    def start(self):
        from helper import makeRequest
        import socket        
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
                except socket.error:
                    continue
                self.getResponse(buff,srcaddr)
            else:
                # no stuff to read .. its our turn to send back something
                if self.nomoretoscan:
                    # no more hosts to scan
                    try:
                        # having the final sip 
                        # print "ok scan complete .. making sure that no packets get lost"
                        while 1:
                            buff,srcaddr = self.sock.recvfrom(8192)
                            self.getResponse(buff,srcaddr)
                    except socket.error:
                        break
                try:
                    nextscan = self.scaniter.next()
                except StopIteration:
                    self.nomoretoscan = True
                    continue
                dstip,dstport,method = nextscan
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
                                self.localhost,
                                branchunique,
                                compact=self.compact,
                                localtag=localtag,
                                contact=contact
                                )
                try:
                    self.log.debug("sending packet to %s:%s" % dsthost)
                    self.sock.sendto(data,dsthost)                    
                except socket.error,err:
                    print "socket error while sending to %s:%s -> %s" % (dsthost[0],dsthost[1],err)

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    from sys import exit
    usage = "usage: %prog [options] host1 host2 hostrange\r\n"
    usage += "example: %prog -l '10.0.0.1<->10.0.0.255' "
    usage += "172.16.131.1 sipvicious.org/22 10.0.1.1/24"

    parser = OptionParser(version="%prog v"+str(__version__)+__GPL__)
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option("-o", "--output", dest="outputcsv",
                  help="Output results to a specified csv file", metavar="output.csv")    
    parser.add_option("-i", "--input", dest="inputcsv",
                  help="Input csv based on previous results", metavar="input.csv")
    parser.add_option("-p", "--port", dest="port", default='5060',
                  help="Destination port or port ranges of the SIP device - eg -p5060,5061,8000-8100", metavar="PORT")
    parser.add_option("-P", "--localport", dest="localport", default=5060, type="int",
                  help="Source port for our packets", metavar="PORT")
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
    (options, args) = parser.parse_args()
    from ip4range import IP4Range
    from helper import getRange, scanfromfile, scanlist
    logginglevel = 40
    if options.verbose is not None:
        for somecount in xrange(options.verbose):
            if logginglevel > 10:
                logginglevel = logginglevel-10
    import logging
    logging.basicConfig(level=logginglevel)
    
    hosts = list()
    if options.inputcsv is None:
        if len(args) < 1:
            parser.print_help()
            exit(1)    
        try:
            iprange = IP4Range(*args)
        except ValueError,err:
            print err
            exit(1)        
        portrange = getRange(options.port)
        scaniter = scanlist(iprange,portrange,[options.method])
    else:
        import csv
        reader = csv.reader(open(options.inputcsv,'rb'))
        scaniter = scanfromfile(reader,[options.method])
    sipvicious = DrinkOrSip(
                    scaniter,                    
                    selecttime=options.selecttime,
                    compact=options.enablecompact,
                    localport=options.localport,                    
                    outputcsv=options.outputcsv,                    
                    )
    
    start_time = datetime.now()
    print "start your engines"
    try:
        sipvicious.start()
    except KeyboardInterrupt:
        print 'caught your control^c - quiting'
#    except Exception, err:
#        if reportBack:
#            import traceback
#            from helper import reportBugToAuthor
#            print "Got unhandled exception : sending report to author"
#            reportBugToAuthor(traceback.format_exc())
#        else:
#            print "Unhandled exception - please enable the 'report bug to author option'"
#            print err 
    end_time = datetime.now()
    total_time = end_time - start_time
    print "Total time:", total_time
