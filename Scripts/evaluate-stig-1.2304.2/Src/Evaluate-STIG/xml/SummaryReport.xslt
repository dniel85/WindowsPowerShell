<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
     <xsl:template match="/">
          <html>
               <head>
                    <style type="text/css">
                         .styled-table {
                              border-collapse: collapse;
                              margin: 25px 0;
                              font-size: 0.9em;
                              font-family: sans-serif;
                              min-width: 400px;
                              box-shadow: 0 0 20px rgba(0, 0, 0, 0.15);
                              width: 100%
                         }
                         .styled-table thead tr {
                              background-color: #2E86C1;
                              color: #ffffff;
                              text-align: left;
                         }
                         .styled-table th,
                         .styled-table td {
                              text-align: center;
                              padding: 12px 15px;
                         }
                         .styled-table tbody tr:last-of-type {
                              border-bottom: 2px solid #3498DB;
                         }
                         .styled-table tbody tr.active-row {
                              font-weight: bold;
                              color: #3498DB;
                         }
                         .hidden {
                              visibility: hidden;
                         }
                         .button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #AED6F1;
                              background-color: #AED6F1;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 250px;
                              height: 20px;
                              margin: 5px;
                         }
                         .stig_button {
                              color: #494949 !important;
                              text-align: center;
                              text-transform: uppercase;
                              text-decoration: none;
                              backgrond: #f6b93b;
                              background-color: #f6b93b;
                              padding: 20px;
                              border: 4px solid #494949 !important;
                              display: inline-block;
                              transition: all 0.4s ease 0s;
                              width: 450px;
                              height: 10px;
                         }
                         .button:hover{
                              color: #ffffff !important;
                              background: #f6b93b;
                              border-color: #f6b93b !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         .stig_button:hover{
                              color: #ffffff !important;
                              background: #AED6F1;
                              border-color: #AED6F1 !important;
                              transition: all 0.4s ease 0s;
                              cursor: pointer;
                         }
                         #topbtn{
                              position: fixed;
                              bottom: 20px;
                              right: 30px;
                              z-index: 99;
                              font-size: 18px;
                              border: none;
                              outline: none;
                              background-color: red;
                              color: white;
                              cursor: pointer;
                              padding: 15px;
                              border-radius: 4px;
                         }
                         #topbtn:hover{
                              background-color: #555;
                         }
                         caption{
                              text-align: center;
                              margin-bottom 5px;
                              font-size: 200%;
                              padding: 5px;
                              letter-space: 10px;
                              font-weight: bold;
                         }
                         .grid-container {
                              display: inline-grid;
                              grid-template-columns: auto auto auto;
                              padding: 10px;
                         }
                         .grid-item {
                              padding: 20px;
                              text-align: center;
                         }
                         .green {
                              background-color: #A9DFBF;
                         }
                         .red {
                              background-color: #E6B0AA;
                         }
                         .orange {
                              background-color: #FAD7A0;
                         }
                         .darkorange {
                              background-color: #EDBB99;
                         }
                         .gray {
                              background-color: #CCD1D1;
                         }
                         .white {
                              background-color: #FDFEFE;
                         }
                    </style>
                    <script>
                         var topbutton = document.getElementById("topbtn");

                         function topFunction() {
                              document.body.scrollTop = 0;
                              document.documentElement.scrollTop = 0;
                         }

                         function change(table_value) {
                              var x = document.getElementById(table_value);
                              var rows = document.getElementById(table_value).getElementsByTagName("tbody");

                              if (x.style.display === "none") {
                                   x.style.display = "table";
                              } else {
                                   x.style.display = "none";
                              }

                              for (var i = 0; i &lt; rows.length; i++){
                                   row = rows[i].getElementsByTagName("td");

                                   switch (row[1].innerHTML){
                                        case "NotAFinding":
                                             rows[i].className = "green";
                                             break;
                                        case "Not_Applicable":
                                             rows[i].className = "gray";
                                             break;
                                        default:
                                             rows[i].className = "white";
                                   }
                                   if (row[1].innerHTML === "Open"){
                                        switch (row[0].innerHTML){
                                             case "CAT I":
                                                  rows[i].className = "red";
                                                  break;
                                             case "CAT II":
                                                  rows[i].className = "orange";
                                                  break;
                                             case "CAT III":
                                                  rows[i].className = "darkorange";
                                                  break;
                                        }
                                   }
                              }
                         }
                    </script>
               </head>
               <body>
                    <h1 align="center">Evaluate-STIG Summary Report</h1>
                    <h4 align="center">Click the Hostname button for Computer and STIG Info</h4>
                    <button onclick="topFunction()" id="topbtn" title="Go to Top">Top</button>
               </body>
          </html>
          <xsl:variable name="Summaries" select="Summaries/Summary" />
          <xsl:variable name="SummaryCount" select="count($Summaries)" />
          <xsl:for-each select="Summaries/Summary">
               <xsl:variable name="ComputerName" select="Computer/Name" />
               <xsl:choose>
                    <xsl:when test="$SummaryCount > 1">
                         <div class="grid-container">
                              <div class="grid-item"><div class="button_cont" align="center"><a class="button" id="button" onclick="change('{$ComputerName}')" title="Show/Hide {$ComputerName} information"><xsl:value-of select="Computer/Name" /></a></div></div>
                         </div>
                    </xsl:when>
                    <xsl:otherwise>
                         <div class="button_cont" align="center"><a class="button" id="button" onclick="change('{$ComputerName}')" title="Show/Hide {$ComputerName} information"><xsl:value-of select="Computer/Name" /></a></div>
                    </xsl:otherwise>
               </xsl:choose>
                    <table id="{$ComputerName}" class="styled-table" style="display:none">
                         <td><h2 align="center"><xsl:value-of select="Computer/Name" /></h2>
                         <h3 align="center">Scan Date: <xsl:value-of select="Computer/ScanDate" /></h3>
                         <h3 align="center">Evaluate-STIG Version: <xsl:value-of select="Computer/EvalSTIGVer" /></h3>
                         <h3 align="center">Scan Type: <xsl:value-of select="Computer/ScanType" /></h3>
                         <xsl:if test = "Computer/Marking">
                              <h3 align="center">Marking: <xsl:value-of select="Computer/Marking" /></h3>
                         </xsl:if>
                         <h3 align="center">Scanned User Profile: <xsl:value-of select="Computer/ScannedUserProfile" /></h3>
                         <div class="button_cont" align="center"><a class="button" id="button" onclick="change('{$ComputerName}_computer_table')" title="Show/Hide Computer information">Computer Information</a><a class="button" id="button" onclick="change('{$ComputerName}_stig_table')" title="Show/Hide STIG information">STIG Information</a></div>
                         <table id="{$ComputerName}_computer_table" class="styled-table">
                              <caption>Computer Information</caption>
                              <td><table class="styled-table">
                                   <thead><tr>
                                        <th>Manufacturer</th>
                                        <th>Model</th>
                                        <th>SerialNumber</th>
                                        <th>BIOSVersion</th>
                                        <th>OSName</th>
                                        <th>OSVersion</th>
                                        <th>CPUArchitecture</th>
                                   </tr></thead>
                                   <tbody><tr>
                                        <td><xsl:value-of select="Computer/Manufacturer" /></td>
                                        <td><xsl:value-of select="Computer/Model" /></td>
                                        <td><xsl:value-of select="Computer/SerialNumber" /></td>
                                        <td><xsl:value-of select="Computer/BIOSVersion" /></td>
                                        <td><xsl:value-of select="Computer/OSName" /></td>
                                        <td><xsl:value-of select="Computer/OSVersion" /></td>
                                        <td><xsl:value-of select="Computer/CPUArchitecture" /></td>
                                   </tr></tbody>
                              </table>
                              <table class="styled-table">
                                   <thead><tr>
                                        <th>InterfaceIndex</th>
                                        <th>Caption</th>
                                        <th>MACAddress</th>
                                        <th>IPv4Addresses</th>
                                        <th>IPv6Addresses</th>
                                   </tr></thead>
                                   <xsl:for-each select="Computer/NetworkAdapters/Adapter">
                                        <tbody><tr>
                                             <td><xsl:value-of select="@InterfaceIndex" /></td>
                                             <td><xsl:value-of select="Caption" /></td>
                                             <td><xsl:value-of select="MACAddress" /></td>
                                             <td><xsl:value-of select="IPv4Addresses" /></td>
                                             <td><xsl:value-of select="IPv6Addresses" /></td>
                                        </tr></tbody>
                                   </xsl:for-each>
                              </table>
                              <table class="styled-table">
                                   <thead><tr>
                                        <th>Index</th>
                                        <th>DeviceID</th>
                                        <th>Size</th>
                                        <th>Caption</th>
                                        <th>Serialnumber</th>
                                        <th>MediaType</th>
                                        <th>InterfaceType</th>
                                   </tr></thead>
                                   <xsl:for-each select="Computer/DiskDrives/Disk">
                                        <tbody><tr>
                                             <td><xsl:value-of select="@Index" /></td>
                                             <td><xsl:value-of select="DeviceID" /></td>
                                             <td><xsl:value-of select="Size" /></td>
                                             <td><xsl:value-of select="Caption" /></td>
                                             <td><xsl:value-of select="SerialNumber" /></td>
                                             <td><xsl:value-of select="MediaType" /></td>
                                             <td><xsl:value-of select="InterfaceType" /></td>
                                        </tr></tbody>
                                   </xsl:for-each>
                              </table></td>
                         </table>
                         <table id="{$ComputerName}_stig_table" class="styled-table">
                              <caption>STIG Information</caption>
                              <thead><tr>
                                   <th>STIG Name</th>
                                   <th>CKL FileName</th>
                                   <th>CKL Scan Date</th>
                                   <th>Open</th>
                                   <th>Not A Finding</th>
                                   <th>Not Applicable</th>
                                   <th>Not Reviewed</th>
                                   <th title="(Not A Finding + Not Applicable)/Total Findings">CKL Score</th>
                                   <th>Change from Previous</th>
                              </tr></thead>
                              <xsl:for-each select="Checklists/Checklist">
                              <xsl:variable name="CKLFile" select="@CklFile" />
                                   <tbody><tr>
                                        <td><div class="button_cont" align="left"><a class="stig_button" id="button" onclick="change('{$CKLFile}')" title="Show/Hide {STIG}"><xsl:value-of select="STIG" /></a></div></td>
                                        <td><xsl:value-of select="@CklFile" /></td>
                                        <td><xsl:value-of select="@Date" /></td>
                                        <td><xsl:value-of select="CAT_I/@Open + CAT_II/@Open + CAT_III/@Open" /></td>
                                        <td><xsl:value-of select="CAT_I/@NotAFinding + CAT_II/@NotAFinding + CAT_III/@NotAFinding" /></td>
                                        <td><xsl:value-of select="CAT_I/@Not_Applicable + CAT_II/@Not_Applicable + CAT_III/@Not_Applicable" /></td>
                                        <td><xsl:value-of select="CAT_I/@NotReviewed + CAT_II/@NotReviewed + CAT_III/@NotReviewed" /></td>
                                        <td><xsl:value-of select="format-number(CurrentScore/@Score, '0%')" /></td>
                                        <xsl:variable name="Delta" select="PreviousScore/@Delta" />
                                        <xsl:choose>
                                             <xsl:when test="$Delta &lt; 0">
                                                  <td class="red"><xsl:value-of select="format-number($Delta, '0%')" /></td>
                                             </xsl:when>
                                             <xsl:otherwise>
                                                  <td class="green">+<xsl:value-of select="format-number($Delta, '0%')" /></td>
                                             </xsl:otherwise>
                                        </xsl:choose>
                                   </tr></tbody>
                                   <td colspan="8"><table id="{$CKLFile}" class="styled-table" style="display:none">
                                        <thead><tr>
                                             <th>Severity</th>
                                             <th>Status</th>
                                             <th>Vuln ID</th>
                                             <th>Rule Title</th>
                                        </tr></thead>
                                        <xsl:for-each select="CAT_I/Vuln">
                                             <tbody><tr>
                                                  <td>CAT I</td>
                                                  <td><xsl:value-of select="@Status" /></td>
                                                  <td><xsl:value-of select="@ID" /></td>
                                                  <td><xsl:value-of select="@RuleTitle" /></td>
                                             </tr></tbody>
                                        </xsl:for-each>
                                        <xsl:for-each select="CAT_II/Vuln">
                                             <tbody><tr>
                                                  <td>CAT II</td>
                                                  <td><xsl:value-of select="@Status" /></td>
                                                  <td><xsl:value-of select="@ID" /></td>
                                                  <td><xsl:value-of select="@RuleTitle" /></td>
                                             </tr></tbody>
                                        </xsl:for-each>
                                        <xsl:for-each select="CAT_III/Vuln">
                                             <tbody><tr>
                                                  <td>CAT III</td>
                                                  <td><xsl:value-of select="@Status" /></td>
                                                  <td><xsl:value-of select="@ID" /></td>
                                                  <td><xsl:value-of select="@RuleTitle" /></td>
                                             </tr></tbody>
                                        </xsl:for-each>
                                   </table></td>
                              </xsl:for-each>
                         </table>
                    </td></table>
          </xsl:for-each>
     </xsl:template>
</xsl:stylesheet>