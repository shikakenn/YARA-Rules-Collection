/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-05-21
    Identifier: Kerberoast
*/

rule GetUserSPNs_VBS {
    meta:
        id = "6SSseJfMdzavbIvBmf6jcX"
        fingerprint = "v1_sha256_ece81cd717fed6ca1f9053384911fd59462b6f3b01210ceeb037ba3da2f7a318"
        version = "1.0"
        date = "2016-05-21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule - file GetUserSPNs.vbs"
        category = "INFO"
        reference = "https://github.com/skelsec/PyKerberoast"
        hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"

    strings:
        $s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
        $s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
        $s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii
    condition:
        2 of them
}

rule GetUserSPNs_PS1 {
    meta:
        id = "6ESHIedTfrR0zT2PtxZAhG"
        fingerprint = "v1_sha256_204b009677a02bf8725f928c2bfff321b4543a883760e312a0c92f187684c8e9"
        version = "1.0"
        date = "2016-05-21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule - file GetUserSPNs.ps1"
        category = "INFO"
        reference = "https://github.com/skelsec/PyKerberoast"
        hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"

    strings:
        $s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
        $s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
        $s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
        $s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii
    condition:
        2 of them
}

rule kerberoast_PY {
    meta:
        id = "2gnwxPFGRxt0YylUjRH0Lc"
        fingerprint = "v1_sha256_3b285cc55733bd4c499ffb4821a92675806bf66faf3b3565ffb6de867bed538d"
        version = "1.0"
        date = "2016-05-21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Auto-generated rule - file kerberoast.py"
        category = "INFO"
        reference = "https://github.com/skelsec/PyKerberoast"
        hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"

    strings:
        $s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
        $s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
        $s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
    condition:
        2 of them
}
