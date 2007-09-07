#!/usr/bin/env python
# svwar.py - SIPvicious extension line scanner

__GPL__ = """

   Sipvicious extension line scanner scans SIP PaBXs for valid extension lines
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
import logging



class TakeASip:    
    def __init__(self,host='localhost',bindingip='',localport=5060,port=5060,method='REGISTER',guessmode=1,guessargs=None,selecttime=0.005,compact=False,socktimeout=3):
        from helper import dictionaryattack, numericbrute
        import logging
        self.log = logging.getLogger('TakeASip')        
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.settimeout(socktimeout)
        self.bindingip = bindingip
        self.localport = localport
        self.originallocalport = localport
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
            self.log.error("could not get the 1st line")
            return
        if firstline != self.BADUSER:
            if buff.startswith(self.PROXYAUTHREQ) or buff.startswith(self.INVALIDPASS) or buff.startswith(self.AUTHREQ):
                if self.realm is None:
                    self.realm = getRealm(buff)
                self.log.info("extension '%s' exists - requires authentication" % extension)
            elif buff.startswith(self.TRYING):
                pass
            elif buff.startswith(self.RINGING):
                pass
            elif buff.startswith(self.OKEY):            
                self.log.info("extension '%s' exists - authentication not required" % extension)
            else:
                self.log.warn("extension '%s' probably exists but the response is weird" % extension)
                self.log.debug("response: %s" % firstline)
        elif buff.startswith(self.NOTFOUND):            
            self.log.debug("User '%s' not found" % extension)
        elif buff.startswith(self.TRYING):
            pass
        elif buff.startswith(self.RINGING):
            pass
        elif buff.startswith(self.OKEY):
            pass
        elif buff.startswith(self.NOTALLOWED):
            self.log.warn("method not allowed")
            self.nomore = True
            return
        else:
            self.log.warn("We got this unknown thing:")
            self.log.error("Response: %s" % `buff`)
            self.nomore = True

        
    
    def start(self):        
        import socket
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

        # perform a test 1st .. we want to see if we get a 404
        # some other error for unknown users
        nextuser = random.getrandbits(32)
        data = self.createRequest(self.method,nextuser,self.dsthost)
        try:
            self.sock.sendto(data,(self.dsthost,self.dstport))
        except socket.error,err:
            self.log.error("socket error: %s" % err)
            return
        # first we identify the assumed reply for an unknown extension 
        gotbadresponse=False
        try:
            while 1:
                buff,srcaddr = self.sock.recvfrom(8192)
                if buff.startswith(self.TRYING) \
                    or buff.startswith(self.RINGING) \
                    or buff.startswith(self.UNAVAILABLE):
                    gotbadresponse=True
                else:
                    self.BADUSER = buff.splitlines()[0]
                    gotbadresponse=False
                    break
        except socket.timeout:
            if gotbadresponse:
                self.log.error("The response we got was not good: %s" % `buff`)
            else:
                self.log.error("No server response - are you sure that this PBX is listening? run svmap against it to find out")
            return
        except (AttributeError,ValueError,IndexError):
            self.log.error("bad response .. bailing out")            
            return
        # let the fun commence
        while 1:
            if self.nomore:
                while 1:
                    try:
                        self.getResponse()
                    except socket.timeout:                        
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
                try:
                    nextuser = self.usernamegen.next()
                except StopIteration:
                    self.nomore = True
                    continue
                data = self.createRequest(self.method,nextuser,self.dsthost)                
                try:
                    self.sock.sendto(data,(self.dsthost,self.dstport))
                except socket.error,err:
                    self.error("socket error: %s" % err)
                    break

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    import logging, sys
    logging.basicConfig(level=logging.DEBUG)
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
    parser.add_option("-R", "--reportback", dest="reportBack", default=False, action="store_true",
                  help="Send the author an exception traceback. Currently sends the command line parameters and the traceback",                  
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
            logging.error( "could not open %s" % options.dictionary )
            sys.exit(1)
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
    logging.info("scan started at %s" % str(start_time))
    try:        
        sipvicious.start()
    except KeyboardInterrupt:
        logging.warn('caught your control^c - quiting')
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
    end_time = datetime.now()
    total_time = end_time - start_time
    logging.info("Total time:", total_time)
