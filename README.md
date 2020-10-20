# Welcome to SIPVicious OSS security tools

The SIPVicious OSS toolset consists of the following tools:

- svmap
- svwar
- svcrack
- svreport
- svcrash

![SIPVicious mascot](https://blog.sipvicious.com/images/sipvicious.png)

## The tools

### svmap

	this is a sip scanner. When launched against
	ranges of ip address space, it will identify any SIP servers 
	which it finds on the way. Also has the option to scan hosts 
	on ranges of ports.

	Usage: <https://github.com/EnableSecurity/sipvicious/wiki/SVMap-Usage>

### svwar

	identifies working extension lines on a PBX. A working 
	extension is one that can be registered. 
	Also tells you if the extension line requires authentication or not. 

	Usage: <https://github.com/EnableSecurity/sipvicious/wiki/SVWar-Usage>

### svcrack
	
	a password cracker making use of digest authentication. 
	It is able to crack passwords on both registrar servers and proxy 
	servers. Current cracking modes are either numeric ranges or
	words from dictionary files.

	Usage: <https://github.com/EnableSecurity/sipvicious/wiki/SVCrack-Usage>

### svreport

	able to manage sessions created by the rest of the tools
	and export to pdf, xml, csv and plain text.

	Usage: <https://github.com/EnableSecurity/sipvicious/wiki/SVReport-Usage>

### svcrash
	
	responds to svwar and svcrack SIP messages with a message that
	causes old versions to crash. 

	Usage: <https://github.com/EnableSecurity/sipvicious/wiki/SVCrash-FAQ>

For usage help make use of `-h` or `--help` switch. 

For getting started:

- [Getting started on the Wiki](https://github.com/enablesecurity/sipvicious/wiki/Getting-Started)
- Communication Breakdown blog: [Attacking a real VoIP System with SIPVicious OSS](https://www.rtcsec.com/2020/06/02-attacking-voip-system-with-sipvicious/).

## Installation

Please refer to the [installation documentation](https://github.com/EnableSecurity/sipvicious/wiki/Basics#installation).

## A note to vendors and service providers

If you are looking for a professional grade toolset to test your RTC systems, please consider [SIPVicious PRO](https://www.sipvicious.pro) which is available as a closed beta version.

## Further information

Check out the [wiki](https://github.com/enablesecurity/sipvicious/wiki) for documentation.

