<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- =========================================================================
            sv.xsl stylesheet version 0.1
            last change: Mon Nov 19 13:08:55 GMT 2012			
            Sandro Gauci, http://enablesecurity.com
==============================================================================
    Copyright (c) 2012 Sandro Gauci
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. The name of the author may not be used to endorse or promote products
       derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
========================================================================== -->
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="root">
  <html>
  <body>
    <h2>
        <xsl:value-of select="title"/>
    </h2>
    <table bgcolor="#000000">
    <tr bgcolor="#000000">
    <xsl:for-each select="labels/label">
        <th align="left">
            <font color="#ffffff"> <xsl:value-of select="name"/></font>
        </th>
    </xsl:for-each>
    </tr>
    <xsl:for-each select="results/result"> 
    <tr bgcolor="#ffffff">
        <xsl:for-each select="*"> 
            <td><xsl:value-of select="value"/></td>
        </xsl:for-each>
    </tr>
    </xsl:for-each>
    </table>
  </body>
  </html>
</xsl:template>

</xsl:stylesheet>