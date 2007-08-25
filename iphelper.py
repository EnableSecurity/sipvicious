#!/usr/bin/env python

import socket, struct

def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('!L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
    "convert long int to dotted quad string"
    return socket.inet_ntoa(struct.pack('!L',n))
      
def makeMask(n):
    "return a mask of n bits as a long integer"
    return (1L<<n)-1

def ipToNetAndHost(ip, maskbits):
    "returns tuple (network, host) dotted-quad addresses given IP and mask size"
    # (by Greg Jorgensen)
    n = dottedQuadToNum(ip)
    m = makeMask(maskbits)
    host = n & m
    net = n - host
    return numToDottedQuad(net), numToDottedQuad(host)

class iprange:
    def __init__(self,startip,endip):
        self.curpos = dottedQuadToNum(startip)
        self.endpos = dottedQuadToNum(endip)
        
    def getnext(self):
        r = self.curpos
        if self.endpos < self.curpos:
            return
        self.curpos += 1
        return r
    def getnextip(self):
        nextone = self.getnext()
        if nextone is not None:
            return numToDottedQuad(nextone)

def getranges(ipstring):
    import re
    if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',ipstring):
        return(ipstring.split('-'))
    elif re.match('^(\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)\.(\*|\d{1,3}(-\d{1,3})*)$',ipstring):
        return getranges2(ipstring)
    else:
        # handle CIDR + hostnames here
        pass
    

def getranges2(ipstring):
    _tmp = ipstring.split('.')
    if len(_tmp) != 4:
        raise ValueError, "needs to be a Quad dotted ip"
    _tmp2 = map(lambda x: x.split('-'),_tmp)
    startip = list()
    endip = list()
    for dot in _tmp2:
        if dot[0] == '*':
            startip.append('0')
            endip.append('255')
        elif len(dot) == 1:
            startip.append(dot[0])
            endip.append(dot[0])
        elif len(dot) == 2:
            startip.append(dot[0])
            endip.append(dot[1])
    return('.'.join(startip),'.'.join(endip))

if __name__ == '__main__':
    print getranges('1.1.1.11-22')
    a = iprange(*getranges('127.0.0.*'))
    while 1:
        x = a.getnextip()
        if x is None:
            break
        print x
