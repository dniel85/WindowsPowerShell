Powershell module must be saved in your local powershell modules directory with this structure ---->  c:\users\"yourusername"\documents\windowspowershell\modules\Scan-SSNPII\Scan-SSNPII.psm1

run import-module Scan-SSNPII.psm1


   Perform a scan of Microsoft word files containg SSN PII
   PS C:\> Scan-SSNPII -uncPath <string> 

   Perform a can of Microsoft word files containing SSN PII and output results to CSV
   PS C:\> Scan-SSNPII -uncPath <string> -ExportResultsToCSV

pii_script.ini file is used to update regex queries for strings associated with the pii data search. It's recomended you only add to this file and not delete any regex queries. 