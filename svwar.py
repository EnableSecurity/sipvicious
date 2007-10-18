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
__version__ = '0.2-svn'
__prog__ = 'svwar'

import socket
import select
import random
import logging



class TakeASip:
    def __init__(self,host='localhost',bindingip='',localport=5060,port=5060,
                 method='REGISTER',guessmode=1,guessargs=None,selecttime=0.005,
                 sessionpath=None,compact=False,socktimeout=3,initialcheck=True):
        from helper import dictionaryattack, numericbrute, packetcounter
        import logging
        self.log = logging.getLogger('TakeASip')
        self.sessionpath = sessionpath
        self.dbsyncs = False
        if self.sessionpath is not  None:
            self.resultauth = anydbm.open(os.path.join(self.sessionpath,'resultauth'),'c')
            try:
                self.resultauth.sync()
                self.dbsyncs = True
                self.log.info("Db does sync")
            except AttributeError:
                self.log.info("Db does not sync")
                pass
        else:
            self.resultauth = dict()
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
        self.guessmode = guessmode
        self.guessargs = guessargs
        if guessmode == 1:
            self.usernamegen = numericbrute(*guessargs)
        elif guessmode == 2:
            self.usernamegen = dictionaryattack(guessargs)
        self.selecttime = selecttime
        self.compact=compact
        self.nomore=False
        self.BADUSER=None
        self.method = method.upper()
        if self.sessionpath is not None:
            self.packetcount = packetcounter(50)
        self.initialcheck = initialcheck

    PROXYAUTHREQ = 'SIP/2.0 407 '
    AUTHREQ = 'SIP/2.0 401 '
    OKEY = 'SIP/2.0 200 '
    NOTFOUND = 'SIP/2.0 404 '
    INVALIDPASS = 'SIP/2.0 403 '
    TRYING = 'SIP/2.0 100 '
    RINGING = 'SIP/2.0 180 '
    NOTALLOWED = 'SIP/2.0 405 '
    UNAVAILABLE = 'SIP/2.0 480 '
    DECLINED = 'SIP/2.0 603 '

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
                                self.compact,
                                localport=self.localport
                              )
        return register

    def getResponse(self):
        from helper import getNonce,getCredentials,getRealm,getCID,getTag
        # we got stuff to read off the socket
        from socket import error as socketerror
        try:
            buff,srcaddr = self.sock.recvfrom(8192)
        except socketerror,err:
            self.log.error("socket error: %s" % err)
            return
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
            if buff.startswith(self.PROXYAUTHREQ) \
            or buff.startswith(self.INVALIDPASS) \
            or buff.startswith(self.AUTHREQ):
                if self.realm is None:
                    self.realm = getRealm(buff)
                self.log.info("extension '%s' exists - requires authentication" % extension)
                self.resultauth[extension] = 'reqauth'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()
            elif buff.startswith(self.TRYING):
                pass
            elif buff.startswith(self.RINGING):
                pass
            elif buff.startswith(self.OKEY):            
                self.log.info("extension '%s' exists - authentication not required" % extension)
                self.resultauth[extension] = 'noauth'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()
            else:
                self.log.warn("extension '%s' probably exists but the response is unexpected" % extension)
                self.log.debug("response: %s" % firstline)
                self.resultauth[extension] = 'weird'
                if self.sessionpath is not None and self.dbsyncs:
                    self.resultauth.sync()
        elif buff.startswith(self.NOTFOUND):            
            self.log.debug("User '%s' not found" % extension)
        elif buff.startswith(self.TRYING):
            pass
        elif buff.startswith(self.RINGING):
            pass
        elif buff.startswith(self.OKEY):
            pass
        elif buff.startswith(self.DECLINED):
            pass
        elif buff.startswith(self.NOTALLOWED):
            self.log.warn("method not allowed")
            self.nomore = True
            return
        else:
            self.log.warn("We got an unknown response")
            self.log.error("Response: %s" % `buff`)
            self.log.debug("1st line: %s" % `firstline`)
            self.log.debug("Bad user: %s" % `self.BADUSER`)
            self.nomore = True

        
    
    def start(self):        
        import socket, pickle
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
        self.nextuser = random.getrandbits(32)
        data = self.createRequest(self.method,self.nextuser,self.dsthost)
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
                elif (buff.startswith(self.PROXYAUTHREQ) \
                    or buff.startswith(self.INVALIDPASS) \
                    or buff.startswith(self.AUTHREQ)) \
                    and self.initialcheck:
                    self.log.error("SIP server replied with an authentication request for an unknown extension. Set --force to force a scan.")
                    return
                else:
                    self.BADUSER = buff.splitlines()[0]
                    self.log.debug("Bad user = %s" % self.BADUSER)
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
        except socket.error,err:
            self.log.error("socket error: %s" % err)
            return
        if self.BADUSER.startswith(self.AUTHREQ):
            self.log.warn("Bad user = %s - svwar will probably not work!" % self.AUTHREQ)
        # let the fun commence
        self.log.info('Ok SIP device found')
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
                    self.nextuser = self.usernamegen.next()
                except StopIteration:
                    self.nomore = True
                    continue
                data = self.createRequest(self.method,self.nextuser,self.dsthost)                
                try:
                    self.sock.sendto(data,(self.dsthost,self.dstport))
                    if self.sessionpath is not None:
                        if self.packetcount.next():
                            try:
                                if self.guessmode == 1:
                                    pickle.dump(self.nextuser,open(os.path.join(exportpath,'lastextension.pkl'),'w'))
                                    self.log.debug('logged last extension %s' % self.nextuser)
                                elif self.guessmode == 2:
                                    pickle.dump(self.guessargs.tell(),open(os.path.join(exportpath,'lastextension.pkl'),'w'))
                                    self.log.debug('logged last position %s' % self.guessargs.tell())
                            except IOError:
                                    self.log.warn('could not log the last extension scanned')
                except socket.error,err:
                    self.log.error("socket error: %s" % err)
                    break

if __name__ == '__main__':
    from optparse import OptionParser
    from datetime import datetime
    import anydbm
    from helper import resumeFrom
    import os
    from sys import exit
    import logging
    import pickle
    #logging.basicConfig(level=logging.DEBUG)
    usage = "usage: %prog [options] target\r\n"
    usage += "examples:\r\n"
    usage += "%prog -e100-999 10.0.0.1\r\n"
    usage += "%prog -d dictionary.txt 10.0.0.2\r\n"
    parser = OptionParser(usage,version="%prog v"+str(__version__)+__GPL__)
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False,
                      help="Quiet mode")
    parser.add_option("-s", "--save", dest="save",
                  help="save the session. Has the benefit of allowing you to resume a previous scan and allows you to export scans", metavar="NAME")    
    parser.add_option("--resume", dest="resume",
                  help="resume a previous scan", metavar="NAME")    
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
    parser.add_option('--force', dest="force", action="store_true",
                      default=False,
                      help="Force scan, ignoring initial sanity checks.")
    (options, args) = parser.parse_args()
    exportpath = None
    logginglevel = 30
    if options.verbose is not None:
        if options.verbose >= 3:
            logginglevel = 10
        else:
            logginglevel = 30-(options.verbose*10)
    if options.quiet:
        logginglevel = 50
    logging.basicConfig(level=logginglevel)
    logging.debug('started logging')
    if options.force:
        initialcheck = False
    else:
        initialcheck = True
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
            exit(1)
        if options.resume is not None:
            lastextensionsrc = os.path.join(exportpath,'lastextension.pkl')
            previousposition = pickle.load(open(lastextensionsrc,'r'))
            dictionary.seek(previousposition)
        guessargs = dictionary
    else:
        from helper import getRange 
        guessmode = 1
        if options.resume is not None:
            lastextensionsrc = os.path.join(exportpath,'lastextension.pkl')
            try:
                previousextension = pickle.load(open(lastextensionsrc,'r'))
            except IOError:
                logging.critical('Could not read from %s' % lastipsrc)
                exit(1)
            logging.debug('Previous range: %s' % options.range)
            options.range = resumeFrom(previousextension,options.range)
            logging.debug('New range: %s' % options.range)
            logging.info('Resuming from %s' % previousextension)
        extensionstotry = getRange(options.range)
        guessargs = (extensionstotry,options.zeropadding)
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
    sipvicious = TakeASip(
                    host,
                    port=options.port,
                    selecttime=options.selecttime,
                    method=options.method,
                    compact=options.enablecompact,
                    guessmode=guessmode,
                    guessargs=guessargs,
                    sessionpath=exportpath,
                    initialcheck=initialcheck
                    )
    start_time = datetime.now()
    #logging.info("scan started at %s" % str(start_time))
    logging.info( "start your engines" )
    try:
        sipvicious.start()
        open(os.path.join(exportpath,'closed'),'w').close()
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
    if options.save is not None and sipvicious.nextuser is not None:
        lastextensiondst = os.path.join(exportpath,'lastextension.pkl')
        logging.debug('saving state to %s' % lastextensiondst)
        try:
            if guessmode == 1:
                pickle.dump(sipvicious.nextuser,open(os.path.join(exportpath,'lastextension.pkl'),'w'))
                logging.debug('logged last extension %s' % sipvicious.nextuser)
            elif guessmode == 2:
                pickle.dump(sipvicious.guessargs.tell(),open(os.path.join(exportpath,'lastextension.pkl'),'w'))
                logging.debug('logged last position %s' % sipvicious.guessargs.tell())            
        except IOError:
            logging.warn('could not log the last extension scanned')
    # display results
    if not options.quiet:
        lenres = len(sipvicious.resultauth)
        if lenres > 0:
            logging.info("we have %s devices" % lenres)
            if (lenres < 400 and options.save is not None) or options.save is None:
                from pptable import indent,wrap_onspace
                width = 60
                labels = ('Extension','Authentication')
                rows = list()
                for k in sipvicious.resultauth.keys():
                    rows.append((k,sipvicious.resultauth[k]))
                print indent([labels]+rows,hasHeader=True,
                    prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
            else:
                logging.warn("too many to print - use svreport for this")
        else:
            logging.warn("found nothing")
    end_time = datetime.now()
    total_time = end_time - start_time
    logging.info("Total time: %s" % total_time)
