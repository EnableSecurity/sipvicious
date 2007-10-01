#!/usr/bin/env python
# SIPVicious report engine
__GPL__ = """

   SIPVicious report engine manages sessions from previous scans with SIPVicious
   tools and allows you to export these scans.
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
__version__= '0.1-svn'
__prog__   = 'svreport'

import anydbm
from xml.dom.minidom import Document
from optparse import OptionParser
from sys import exit
import os
import logging
import socket

if __name__ == "__main__":
	commandsusage = """Supported commands:
		- list:\tlists all scans
		- export:\texports the given scan to a given format
		- delete:\tdeletes the scan
"""
        commandsusage += "example:\r\n"
        commandsusage += "      %s.py list\r\n" % __prog__
        commandsusage += "      %s.py export -f pdf -o scan1.pdf -s scan1\r\n" % __prog__
        commandsusage += "      %s.py delete -s scan1\r\n" % __prog__
        usage = "%prog [command] [options]\r\n\r\n"
        usage += commandsusage
	parser = OptionParser(usage=usage)
        parser.add_option('-v', '--verbose', dest="verbose", action="count",
                          help="Increase verbosity")
        parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                          default=False,
                          help="Quiet mode")
	parser.add_option("-t", "--type", dest="sessiontype",
			help="Type of session. This is usually either svmap, svwar or svcrack. If not set I will try to find the best match")
	parser.add_option("-s", "--session", dest="session",
			help="Name of the session")
	parser.add_option("-f", "--format", dest="format",
			help="Format type. Can be stdout, pdf, xml, csv or txt")
	parser.add_option("-o", "--output", dest="outputfile",
			help="Output filename")
	parser.add_option("-n", dest="resolve", default=True,
                          action="store_false", help="Do not resolve the ip address")
	(options,args) = parser.parse_args()
	if len(args) < 1:
		parser.error("Please specify a command.\r\n")
		exit(1)
	command = args[0]
	from helper import listsessions,deletesessions,createReverseLookup
        from helper import getsessionpath,getasciitable,outputtoxml,outputtopdf
        logginglevel = 30
        if options.verbose is not None:
            if options.verbose >= 3:
                    logginglevel = 10
            else:
                    logginglevel = 30-(options.verbose*10)
        if options.quiet:
            logginglevel = 50
        validcommands = ['list','export','delete']
        if command not in validcommands:
                parser.error('%s is not a supported command' % command)
                exit(1)
        logging.basicConfig(level=logginglevel)
        sessiontypes = ['svmap','svwar','svcrack']
        logging.debug('started logging')        
	if command == 'list':
		listsessions(options.sessiontype)
	if command == 'delete':
		if options.session is None:
			parser.error("Please specify a valid session.")
			exit(1)
		sessionpath = deletesessions(options.session,options.sessiontype)
		if sessionpath is None:
			parser.error('Session could not be found. Make sure it exists by making use of %s.py list' % __prog__)
			exit(1)
	elif command == 'export':
		from datetime import datetime
		start_time = datetime.now()
		if options.session is None:
			parser.error("Please specify a valid session")
			exit(1)
		if options.outputfile is None and options.format not in [None,'stdout']:
			parser.error("Please specify an output file")
			exit(1)
                tmp = getsessionpath(options.session,options.sessiontype)                
		if tmp is None:
			parser.error('Session could not be found. Make sure it exists by making use of %s list' % __prog__)
			exit(1)
                sessionpath,sessiontype = tmp
                resolve = False
                resdb = None
                if sessiontype == 'svmap':
                        dbloc = os.path.join(sessionpath,'resultua.db')
                        labels = ['Host','User Agent']
                elif sessiontype == 'svwar':
                        dbloc = os.path.join(sessionpath,'resultauth.db')
                        labels = ['Extension','Authentication']
                elif sessiontype == 'svcrack':
                        dbloc = os.path.join(sessionpath,'resultpasswd.db')
                        labels = ['Extension','Password']
                if not os.path.exists(dbloc):
                        logging.error('The database could not be found: %s'%dbloc)
                        exit(1)
                db = anydbm.open(dbloc,'r')

                if options.resolve and sessiontype == 'svmap':
                        resolve = True
                        labels.append('Resolved')                                
                        resdbloc = os.path.join(sessionpath,'resolved.db')
                        if not os.path.exists(resdbloc):
                                logging.info('Performing DNS reverse lookup')
                                resdb = anydbm.open(resdbloc,'c')
                                createReverseLookup(db,resdb)
                        else:
                                logging.info('Not Performing DNS lookup')
                                resdb = anydbm.open(resdbloc,'r')

                if options.outputfile is not None:
			if options.outputfile.find('.') < 0:
				if options.format is None:
					options.format = 'txt'
				options.outputfile += '.%s' % options.format

                if options.format in [None,'stdout','txt']:
                        o = getasciitable(labels,db,resdb)
                        if options.outputfile is None:
                                print o
                        else:
                                open(options.outputfile,'w').write(o)
                elif options.format == 'xml':
                        from xml.dom.minidom import Document
                        doc = Document()
                        node = doc.createElement(sessiontype)                        
                        o = outputtoxml('%s report' % sessiontype,labels,db,resdb)
                        open(options.outputfile,'w').write(o)
                elif options.format == 'pdf':
                        outputtopdf(options.outputfile,'%s report' % sessiontype,labels,db,resdb)
                elif options.format == 'csv':
                        import csv
                        writer = csv.writer(open(options.outputfile,"w"))
                        for k in db.keys():
                                row = [k,db[k]]
                                if resdb is not None:
                                        if resdb.has_key(k):
                                                row.append(resdb[k])
                                        else:
                                                row.append('N/A')
                                writer.writerow(row)
		logging.info( "That took %s" % (datetime.now() - start_time))
