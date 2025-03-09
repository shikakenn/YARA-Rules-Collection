/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-08-31
    Identifier: RWMC Powershell Credential Dumper
*/

rule Reveal_MemoryCredentials {
    meta:
        id = "5i71y9rIwIToqFPtWVM44m"
        fingerprint = "v1_sha256_d740462aacd3b30d0258d018344642683fefd43ef033dd7f5bdde2bdddce4115"
        version = "1.0"
        date = "2015-08-31"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule - file Reveal-MemoryCredentials.ps1"
        category = "INFO"
        reference = "https://github.com/giMini/RWMC/"
        hash = "893c26818c424d0ff549c1fbfa11429f36eecd16ee69330c442c59a82ce6adea"

    strings:
        $s1 = "$dumpAProcessPath = \"C:\\Windows\\temp\\msdsc.exe\"" fullword ascii
        $s2 = "$user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}" fullword ascii
        $s3 = "Copy-Item -Path \"\\\\$computername\\\\c$\\windows\\temp\\lsass.dmp\" -Destination \"$logDirectoryPath\"" fullword ascii
        $s4 = "if($backupOperatorsFlag -eq \"true\") {$loginPlainText = $loginPlainText + \" = Backup Operators\"}            " fullword ascii
    condition:
        filesize < 200KB and 1 of them
}

rule MiniDumpTest_msdsc {
    meta:
        id = "4gmS1JrjCQKFdJESalXpzl"
        fingerprint = "v1_sha256_ae8a28df245a8f7a2d62639789c31556b012322fcac09784595fd6f95d6bf195"
        version = "1.0"
        date = "2015-08-31"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule - file msdsc.exe"
        category = "INFO"
        reference = "https://github.com/giMini/RWMC/"
        hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"

    strings:
        $s1 = "MiniDumpTest1.exe" fullword wide
        $s2 = "MiniDumpWithTokenInformation" fullword ascii
        $s3 = "MiniDumpTest1" fullword wide
        $s6 = "Microsoft 2008" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

