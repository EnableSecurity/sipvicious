<?xml version="1.0" encoding="ISO-8859-1"?>

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