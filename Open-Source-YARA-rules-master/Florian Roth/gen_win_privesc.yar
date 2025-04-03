/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-06-02
    Identifier: Win Privilege Escalation
*/

/* Rule Set ----------------------------------------------------------------- */

rule Win_PrivEsc_gp3finder_v4_0 {
    meta:
        id = "noB3che4qQiz1z3i5jjcO"
        fingerprint = "v1_sha256_7d5618315ae5293ce1aea18d255d08bb007f39a466021fb636605684433da158"
        version = "1.0"
        score = 80
        date = "2016-06-02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
        category = "INFO"
        reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
        hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"

    strings:
        $x1 = "Check for and attempt to decrypt passwords on share" ascii
        $x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
        $x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( all of them )
}

rule Win_PrivEsc_folderperm {
    meta:
        id = "7IPkEpmP4coC5oMKqkAgAZ"
        fingerprint = "v1_sha256_899fda75e4c6d9f588767e5170dbd30241a492ba89f7cc1b0ad4adb2fcd173cb"
        version = "1.0"
        score = 80
        date = "2016-06-02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
        category = "INFO"
        reference = "http://www.greyhathacker.net/?p=738"
        hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"

    strings:
        $x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
        $x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
        $x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii
    condition:
        1 of them
}

rule Win_PrivEsc_ADACLScan4_3 {
    meta:
        id = "6cZvOCc6zPkoWFFGfbqasU"
        fingerprint = "v1_sha256_ca657e5c4172d240f46a890fc112ee89d5bdf9e35e7d412332ee11bdaf166215"
        version = "1.0"
        score = 60
        date = "2016-06-02"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
        category = "INFO"
        reference = "https://adaclscan.codeplex.com/"
        hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"

    strings:
        $s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
        $s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
        $s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii
    condition:
        all of them
}
