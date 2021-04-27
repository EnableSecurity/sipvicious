# SIPVicious report engine
__GPL__ = """

   SIPVicious report engine manages sessions from previous scans with SIPVicious
   tools and allows you to export these scans.
   Copyright (C) 2007-2021 Sandro Gauci <sandrogauc@gmail.com>

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

import re
import dbm
import csv
import logging
import os
from optparse import OptionParser
from sys import exit
from datetime import datetime
from operator import itemgetter
from sipvicious.libs.svhelper import (
    __version__, calcloglevel, listsessions, deletesessions, getsessionpath,
    dbexists, createReverseLookup, getasciitable, outputtoxml, outputtopdf
)

__prog__ = 'svreport'

def main():
    commandsusage = """Supported commands:
    - list:\tlists all scans
    - export:\texports the given scan to a given formats
    - delete:\tdeletes the scan
    - stats:\tprint out some statistics of interest
    - search:\tsearch for a specific string in the user agent (svmap)\r\n
"""
    commandsusage += "examples:\r\n"
    commandsusage += "      %s.py list\r\n" % __prog__
    commandsusage += "      %s.py export -f pdf -o scan1.pdf -s scan1\r\n" % __prog__
    commandsusage += "      %s.py delete -s scan1\r\n" % __prog__
    usage = "%prog [command] [options]\r\n\r\n"
    usage += commandsusage
    parser = OptionParser(usage=usage, version="%prog v" + str(__version__) + __GPL__)
    parser.add_option('-v', '--verbose', dest="verbose", action="count",
                      help="Increase verbosity")
    parser.add_option('-q', '--quiet', dest="quiet", action="store_true",
                      default=False, help="Quiet mode")
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
    parser.add_option("-c", "--count", dest="count", default=False,
                      action="store_true", help="Used togather with 'list' command to count the number of entries")
    options, args = parser.parse_args()
    if len(args) < 1:
        parser.error("Please specify a command.\r\n")
        exit(1)
    command = args[0]
    validcommands = ['list', 'export', 'delete', 'stats', 'search']
    if command not in validcommands:
        parser.error('%s is not a supported command' % command)
        exit(1)
    logging.basicConfig(level=calcloglevel(options))
    sessiontypes = ['svmap', 'svwar', 'svcrack']
    if options.sessiontype not in sessiontypes:
        parser.error("Invalid session type. Please specify a valid session type.")
        exit(1)
    logging.debug('started logging')
    if command == 'list':
        listsessions(options.sessiontype, count=options.count)
    if command == 'delete':
        if options.session is None:
            parser.error("Please specify a valid session.")
            exit(1)
        sessionpath = deletesessions(options.session, options.sessiontype)
        if sessionpath is None:
            parser.error(
                'Session could not be found. Make sure it exists by making use of %s.py list' % __prog__)
            exit(1)
    elif command == 'export':
        start_time = datetime.now()
        if options.session is None:
            parser.error("Please specify a valid session")
            exit(1)
        if options.outputfile is None and options.format not in [None, 'stdout']:
            parser.error("Please specify an output file")
            exit(1)
        tmp = getsessionpath(options.session, options.sessiontype)
        if tmp is None:
            parser.error(
                'Session could not be found. Make sure it exists by making use of %s list' % __prog__)
            exit(1)
        sessionpath, sessiontype = tmp
        resdb = None
        if sessiontype == 'svmap':
            dbloc = os.path.join(sessionpath, 'resultua')
            labels = ['Host', 'User Agent']
        elif sessiontype == 'svwar':
            dbloc = os.path.join(sessionpath, 'resultauth')
            labels = ['Extension', 'Authentication']
        elif sessiontype == 'svcrack':
            dbloc = os.path.join(sessionpath, 'resultpasswd')
            labels = ['Extension', 'Password']
        if not dbexists(dbloc):
            logging.error('The database could not be found: %s' % dbloc)
            exit(1)

        db = dbm.open(dbloc, 'r')

        if options.resolve and sessiontype == 'svmap':
            labels.append('Resolved')
            resdbloc = os.path.join(sessionpath, 'resolved')
            if not dbexists(resdbloc):
                logging.info('Performing DNS reverse lookup')
                resdb = dbm.open(resdbloc, 'c')
                createReverseLookup(db, resdb)
            else:
                logging.info('Not Performing DNS lookup')
                resdb = dbm.open(resdbloc, 'r')

        if options.outputfile is not None:
            if options.outputfile.find('.') < 0:
                if options.format is None:
                    options.format = 'txt'
                options.outputfile += '.%s' % options.format
        if options.format in [None, 'stdout', 'txt']:
            o = getasciitable(labels, db, resdb)
            if options.outputfile is None:
                print(o)
            else:
                open(options.outputfile, 'w').write(o)
        elif options.format == 'xml':
            o = outputtoxml('%s report' % sessiontype, labels, db, resdb)
            open(options.outputfile, 'w').write(o)
        elif options.format == 'pdf':
            outputtopdf(options.outputfile, '%s report' %
                        sessiontype, labels, db, resdb)
        elif options.format == 'csv':
            writer = csv.writer(open(options.outputfile, "w"))
            for k in db.keys():
                row = [k.decode(), db[k].decode()]
                if resdb is not None:
                    if k in resdb:
                        row.append(resdb[k].decode())
                    else:
                        row.append('N/A')
                writer.writerow(row)
        logging.info("That took %s" % (datetime.now() - start_time))

    elif command == 'stats':
        if options.session is None:
            parser.error("Please specify a valid session")
            exit(1)
        if options.outputfile is None and options.format not in [None, 'stdout']:
            parser.error("Please specify an output file")
            exit(1)
        tmp = getsessionpath(options.session, options.sessiontype)
        if tmp is None:
            parser.error(
                'Session could not be found. Make sure it exists by making use of %s list' % __prog__)
            exit(1)
        sessionpath, sessiontype = tmp
        if sessiontype != 'svmap':
            parser.error('Only takes svmap sessions for now')
            exit(1)
        dbloc = os.path.join(sessionpath, 'resultua')
        if not dbexists(dbloc):
            logging.error('The database could not be found: %s' % dbloc)
            exit(1)
        db = dbm.open(dbloc, 'r')
        useragents = dict()
        useragentconames = dict()
        for k in db.keys():
            v = db[k]
            if v not in useragents:
                useragents[v] = 0
            useragents[v] += 1
            useragentconame = re.split(b'[ /]', v)[0]
            if useragentconame not in useragentconames:
                useragentconames[useragentconame] = 0
            useragentconames[useragentconame] += 1

        _useragents = sorted(iter(useragents.items()),
                             key=itemgetter(1), reverse=True)
        suseragents = list(map(lambda x: '\t- %s (%s)' % (x[0].decode(), x[1]), _useragents))
        _useragentsnames = sorted(
            iter(useragentconames.items()), key=itemgetter(1), reverse=True)
        suseragentsnames = list(map(lambda x: '\t- %s (%s)' %
                               (x[0].decode(), x[1]), _useragentsnames))
        print("Total number of SIP devices found: %s" % len(list(db.keys())))
        print("Total number of useragents: %s\r\n" % len(suseragents))
        print("Total number of useragent names: %s\r\n" % len(suseragentsnames))
        print("Most popular top 30 useragents:\r\n")
        print('\r\n'.join(suseragents[:30]), '\r\n\r\n')
        print("Most unpopular top 30 useragents:\r\n\t")
        print('\r\n'.join(suseragents[-30:]), "\r\n\r\n")
        print("Most popular top 30 useragent names:\r\n")
        print('\r\n'.join(suseragentsnames[:30]), '\r\n\r\n')
        print("Most unpopular top 30 useragent names:\r\n\t")
        print('\r\n'.join(suseragentsnames[-30:]), '\r\n\r\n')

    elif command == 'search':
        if options.session is None:
            parser.error("Please specify a valid session")
            exit(1)
        if len(args) < 2:
            parser.error('You need to specify a search string')
        searchstring = args[1]
        tmp = getsessionpath(options.session, options.sessiontype)
        if tmp is None:
            parser.error(
                'Session could not be found. Make sure it exists by making use of %s list' % __prog__)
            exit(1)
        sessionpath, sessiontype = tmp
        if sessiontype != 'svmap':
            parser.error('Only takes svmap sessions for now')
            exit(1)
        dbloc = os.path.join(sessionpath, 'resultua')
        if not dbexists(dbloc):
            logging.error('The database could not be found: %s' % dbloc)
            exit(1)
        db = dbm.open(dbloc, 'r')
        useragents = dict()
        useragentconames = dict()
        labels = ['Host', 'User Agent']
        for k in db.keys():
            v = db[k].decode()
            if searchstring.lower() in v.lower():
                print(k.decode() + '\t' + v)

if __name__ == "__main__":
    main()
