<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="root">
  <html>
  <body>
    <h2>
        <xsl:value-of select="title"/>
    </h2>
    <table border="0">
    <tr bgcolor="#000">
    <xsl:for-each select="labels/label">
        <th align="left">
            <font color="#fff"> <xsl:value-of select="name"/></font>
        </th>
    </xsl:for-each>
    </tr>
    <xsl:for-each select="results/result"> 
    <tr>
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