#!/usr/bin/env python
# svwar.py - SIPvicious extension line scanner

__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
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

reportBack = True

class TakeASip:    
    def __init__(self,host='localhost',localport=5060,port=5060,method='REGISTER',guessmode=1,guessargs=None,selecttime=0.005,compact=False):
        from helper import dictionaryattack, numericbrute
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.settimeout(10)
        self.sock.bind(('',localport))
        self.rlist = [self.sock]
        self.wlist = list()
        self.xlist = list()
        self.challenges = list()
        self.localhost = 'localhost'
        self.realm = None
        self.dsthost,self.dstport = host,port
        if guessmode == 1:
            self.usernamegen = numericbrute(*guessargs)
        elif guessmode == 2:
            self.usernamegen = dictionaryattack(guessargs)
        self.selecttime = selecttime
        self.compact=compact
        self.nomore=False
        self.BADUSER=None
        self.method = method.upper()

    PROXYAUTHREQ = 'SIP/2.0 407 '
    AUTHREQ = 'SIP/2.0 401 '
    OKEY = 'SIP/2.0 200 '
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
        
    def createRequest(self,m,username,remotehost,auth=None,cid=None):
        from helper import makeRequest

        if cid is None:
            cid='%s' % str(random.getrandbits(32))
        branchunique = '%s' % random.getrandbits(32)
        cseq = 1
        localtag=username
        contact = None
        if m == 'INVITE' or m == 'OPTIONS':
            contact = 'sip:%s@%s' % (username,self.dsthost)
        register = makeRequest(
                                    m,
                                    '"%s"<sip:%s@%s>' % (username,username,self.dsthost),
                                    '"%s"<sip:%s@%s>' % (username,username,self.dsthost),
                                    self.dsthost,
                                    self.dstport,
                                    cid,
                                    self.localhost,
                                    branchunique,
                                    cseq,
                                    auth,
                                    localtag,
                                    self.compact
                                  )
        return register

    def getResponse(self):
        from helper import getNonce,getCredentials,getRealm,getCID,getTag
        # we got stuff to read off the socket                
        buff,srcaddr = self.sock.recvfrom(8192)
        extension = getTag(buff)        
        if extension is None:
            self.nomore = True
            return
        try:
            firstline = buff.splitlines()[0]
        except (ValueError,IndexError,AttributeError):
            print "could not get the 1st line"
            return
        #print firstline
        #print self.BADUSER        
        if firstline != self.BADUSER:
            if buff.startswith(self.PROXYAUTHREQ) or buff.startswith(self.INVALIDPASS) or buff.startswith(self.AUTHREQ):
                if self.realm is None:
                    self.realm = getRealm(buff)
                print "extension '%s' exists - requires authentication" % extension
            elif buff.startswith(self.TRYING):
                pass
            elif buff.startswith(self.RINGING):
                pass
            elif buff.startswith(self.OKEY):            
                print "extension '%s' exists - authentication not required" % extension
            else:
                print "extension '%s' probably exists but the response is weird" % extension
                print firstline
        elif buff.startswith(self.NOTFOUND):
            pass
            #print "User '%s' not found" % extension
        elif buff.startswith(self.TRYING):
            pass
        elif buff.startswith(self.RINGING):
            pass
        elif buff.startswith(self.OKEY):
            pass
        elif buff.startswith(self.NOTALLOWED):
            print "method not allowed"
            self.nomore = True
            return
        else:
            print "We got this unknown thing:"
            print buff
            self.nomore = True

        
    
    def start(self):        
        import socket
        # perform a test 1st .. we want to see if we get a 404
        # some other error for unknown users
        nextuser = random.getrandbits(32)
        data = self.createRequest(self.method,nextuser,self.dsthost)
        try:
            self.sock.sendto(data,(self.dsthost,self.dstport))
        except socket.error,err:
            print "socket error: %s" % err
            return
        try:
            _tmp = True
            while _tmp:
                buff,srcaddr = self.sock.recvfrom(8192)
                if not buff.startswith(self.TRYING) \
                    and not buff.startswith(self.RINGING) \
                    and not buff.startswith(self.UNAVAILABLE):
                    _tmp=False
            self.BADUSER = buff.splitlines()[0]            
        except socket.timeout:
            if _tmp is True:
                print "got a response but did not manage to grab an appropiate header"
            else:
                print "no server response"
            return
        except (AttributeError,ValueError,IndexError):
            print "bad response .. bailing out"
            return
        while 1:
            if self.nomore:                
                return
            r, w, e = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                self.selecttime
                )
            if r:
                # we got stuff to read off the socket
                self.getResponse()
            else:
                # no stuff to read .. its our turn to send back something
                nextuser = self.usernamegen.nextone()
                if nextuser is None:
                    self.nomore = True
                    continue
                data = self.createRequest(self.method,nextuser,self.dsthost)                
                try:
                    self.sock.sendto(data,(self.dsthost,self.dstport))
                except socket.error,err:
                    print "socket error: %s" % err
                    break

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    parser = OptionParser(version="%prog v"+str(__version__)+__GPL__)
    parser.add_option("-p", "--port", dest="port", default=5060, type="int",
                  help="destination port of the SIP UA", metavar="PORT")
    parser.add_option("-t", "--timeout", dest="selecttime", type="float",
                      default=0.005,
                  help="timeout for the select() function. Change this if you're losing packets",
                  metavar="SELECTTIME")        
    parser.add_option("-d", "--dictionary", dest="dictionary", type="string",
                  help="specify a dictionary file with possible extension names",
                  metavar="DICTIONARY")        
    parser.add_option("-m", "--method", dest="method", type="string",
                  help="specify a request method. The default is REGISTER. Other possible methods are OPTIONS and INVITE",
                  default="REGISTER",
                  metavar="OPTIONS")        
    parser.add_option("-e", "--extensions", dest="range", default='100-999',
                  help="specify an extension or extension range\r\nexample: -e 100-999,1000-1500,9999",
                  metavar="RANGE")
    parser.add_option("-z", "--zeropadding", dest="zeropadding", type="int",
                  help="""the number of zeros used to padd the username.
                  the options "-e 1-9999 -z 4" would give 0001 0002 0003 ... 9999""",
                  default=0,
                  metavar="PADDING")
    parser.add_option("-c", "--enablecompact", dest="enablecompact", default=False, 
                  help="enable compact mode. Makes packets smaller but possibly less compatable",
                  action="store_true",
                  )
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("provide one hostname")
    else:
        host=args[0]
    if options.dictionary is not None:
        guessmode=2
        try:
            dictionary = open(options.dictionary,'r')
        except IOError:
            print "could not open %s" % options.dictionary
        guessargs = dictionary
    else:
        from helper import getRange
        guessmode = 1
        extensionstotry = getRange(options.range)        
        guessargs = (extensionstotry,options.zeropadding)    
    sipvicious = TakeASip(
                    host,
                    port=options.port,
                    selecttime=options.selecttime,
                    method=options.method,
                    compact=options.enablecompact,
                    guessmode=guessmode,
                    guessargs=guessargs
                    )
    start_time = datetime.now()
    print "scan started at %s" % str(start_time)
    try:        
        sipvicious.start()
    except KeyboardInterrupt:
        print 'caught your control^c - quiting'
    except:
        if reportBack:
            import traceback
            from helper import reportBugToAuthor
            print "Got unhandled exception : sending report to author"
            reportBugToAuthor(traceback.format_exc())
        else:
            print "Unhandled exception - please enable the 'report bug to author option'"
    end_time = datetime.now()
    total_time = end_time - start_time
    print "Total time:", total_time
