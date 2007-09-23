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


if __name__ == "__main__":
	usage = """%prog [command] [options]
	Command can be:
		- list:\tlists all scans
		- export:\texports the given scan to a given format
		- delete:\t deletes the scan
	"""
	parser = OptionParser(usage=usage)
	parser.add_option("-t", "--type", dest="sessiontype",
			help="Type of session. This is usually either svmap, svwar or svcrack. If not set I will try to find the best match")
	parser.add_option("-s", "--session", dest="session",
			help="Name of the session")
	parser.add_option("-f", "--format", dest="format",
			help="Format type. Can be stdout, pdf, xml, csv or txt")
	parser.add_option("-o", "--output", dest="outputfile",
			help="Output filename")
	(options,args) = parser.parse_args()
	if len(args) < 1:
		parser.error("please specify a command. Current commands are list, export and delete")
		exit(1)
	command = args[0]
	from helper import listsessions,deletesessions
	if command == 'list':
		listsessions(options.sessiontype)
	if command == 'delete':
		if options.session is None:
			parser.error("please specify a saved session")
			exit(1)
		sessionpath = deletesessions(options.session,options.sessiontype)
		if sessionpath is None:
			parser.error('Session could not be found. Make sure it exists by making use of %s.py list' % __prog__)
			exit(1)
	elif command == 'export':
		from datetime import datetime
		start_time = datetime.now()
		if options.session is None:
			parser.error("please specify a saved session")
			exit(1)
		if options.outputfile is None and options.format not in [None,'stdout']:
			parser.error("please specify a file to output")
			exit(1)
		sessionpath = None
		if options.sessiontype is None:
			for sessiontype in sessiontypes:
				p = os.path.join('.sipvicious',sessiontype,options.session)
				if os.path.exists(p):
					sessionpath = p
					break
		else:
			p = os.path.join('.sipvicious',options.sessiontype,options.session)
			if os.path.exists(p):
				sessionpath = p
				sessiontype = options.sessiontype
		if sessionpath is None:
			parser.error('Session could not be found. Make sure it exists by making use of %prog list')
			exit(1)
		resultua = anydbm.open(os.path.join(sessionpath,'resultua.db'),'r')
		if options.outputfile is not None:
			if options.outputfile.find('.') < 0:
				if options.format is None:
					options.format = 'txt'
				options.outputfile += '.%s' % options.format
		if sessiontype == 'svmap':
			if options.format in [None,'stdout','txt']:
				from pptable import indent,wrap_onspace
				width = 60
				labels = ('SIP Device','User Agent')
				rows = list()
				for k in resultua.keys():
				    rows.append((k,resultua[k]))
				o = indent([labels]+rows,hasHeader=True,
				    prefix='| ', postfix=' |',wrapfunc=lambda x: wrap_onspace(x,width))
				if options.outputfile is None:
					print o
				else:
					open(options.outputfile,'w').write(o)
			elif options.format == 'xml':
				from xml.dom.minidom import Document
				doc = Document()
				node = doc.createElement('svmap')
				for k in resultua.keys():
					elem = doc.createElement('entry')	
					elem.setAttribute('ip',k)
					elem.setAttribute('useragent',resultua[k])
					node.appendChild(elem)
				doc.appendChild(node)
				open(options.outputfile,'w').write(doc.toprettyxml())
			elif options.format == 'pdf':
				try:
					from reportlab.platypus import *
				except ImportError:
					parser.error('reportlab was not found. To export to pdf you need to have reportlab installed. Check out www.reportlab.org')
					exit(1)
				rows=list()
				for k in resultua.keys():
					rows.append((k,resultua[k]))
				t=Table(rows)
				doc = SimpleDocTemplate(options.outputfile)
				elements = []
				elements.append(t)
				doc.build(elements)
			elif options.format == 'csv':
				import csv
				writer = csv.writer(open(options.outputfile,"w"))
				for k in resultua.keys():
					writer.writerow((k,resultua[k]))
	
		print "That took %s" % (datetime.now() - start_time)
	
