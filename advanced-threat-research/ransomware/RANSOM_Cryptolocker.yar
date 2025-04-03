rule CryptoLocker_set1
{

    meta:
        id = "5bZtfOboFIXEwPAzODhuRn"
        fingerprint = "v1_sha256_5be8d077537a59d860a972392be186d2697e55778f750d03b0fd3b0a73f714d9"
        version = "1.0"
        date = "2014-04-13"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
        description = "Detection of Cryptolocker Samples"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        rule_version = "v1"
        malware_family = "Ransom:W32/Cryptolocker"
        actor_group = "Unknown"

    strings:

        $string0 = "static"
        $string1 = " kscdS"
        $string2 = "Romantic"
        $string3 = "CompanyName" wide
        $string4 = "ProductVersion" wide
        $string5 = "9%9R9f9q9"
        $string6 = "IDR_VERSION1" wide
        $string7 = "  </trustInfo>"
        $string8 = "LookFor" wide
        $string9 = ":n;t;y;"
        $string10 = "        <requestedExecutionLevel level"
        $string11 = "VS_VERSION_INFO" wide
        $string12 = "2.0.1.0" wide
        $string13 = "<assembly xmlns"
        $string14 = "  <trustInfo xmlns"
        $string15 = "srtWd@@"
        $string16 = "515]5z5"
        $string17 = "C:\\lZbvnoVe.exe" wide

    condition:

        12 of ($string*)
}

rule CryptoLocker_rule2
{

    meta:
        id = "5FY9JTZovLpMrh6TZLvsBL"
        fingerprint = "v1_sha256_e8e03516cc0b669000c8d6b443be7a5f7a8b904abba98fd3c7d4f038de6741ab"
        version = "1.0"
        date = "2014-04-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
        description = "Detection of CryptoLocker Variants"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        rule_version = "v1"
        malware_family = "Ransom:W32/Cryptolocker"
        actor_group = "Unknown"

    strings:

        $string0 = "2.0.1.7" wide
        $string1 = "    <security>"
        $string2 = "Romantic"
        $string3 = "ProductVersion" wide
        $string4 = "9%9R9f9q9"
        $string5 = "IDR_VERSION1" wide
        $string6 = "button"
        $string7 = "    </security>"
        $string8 = "VFileInfo" wide
        $string9 = "LookFor" wide
        $string10 = "      </requestedPrivileges>"
        $string11 = " uiAccess"
        $string12 = "  <trustInfo xmlns"
        $string13 = "last.inf"
        $string14 = " manifestVersion"
        $string15 = "FFFF04E3" wide
        $string16 = "3,31363H3P3m3u3z3"

    condition:

        12 of ($string*)
}


