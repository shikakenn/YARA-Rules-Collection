rule IndiaCharlie_One
{
    meta:
        id = "1A04y8txdvpjdLL3q1lL61"
        fingerprint = "v1_sha256_2eea708e2a313bb074ee0247e4248a2059a539b2af98298a45b572a26a116553"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $ = "WMPNetworkSvcUpdate"
        $ = "backSched.dll"
        $ = "\\mspaint.exe"
        $aesKey = "X,LLIe{))%%l2i<[AM|aq!Ql/lPlw]d7@C-#j.<c|#*}Kx4_H(q^F-F^p/[t#%HT"
    condition:
        2 of them or $aesKey
}

rule IndiaCharlie_Two
{
    meta:
        id = "7KKrzc9w5VpFKDMiEJxM7L"
        fingerprint = "v1_sha256_82b23ef8e6ab67747342dd735260d84e098154780e50778085c75f08d7ddfaf0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        $s1 = "%s is an essential element in Windows System configuration and management. %s"
        $s2 = "%SYSTEMROOT%\\system32\\svchost.exe -k "
        $s3 = "%s\\system32\\%s"
        $s4 = "\\mspaint.exe"
        $s5 = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
        $aesKey = "}[eLkQAeEae0t@h18g!)3x-RvE%+^`n.6^()?+00ME6a&F7vcV}`@.dj]&u$o*vX"

    condition:
        3 of ($s*) or $aesKey
}
