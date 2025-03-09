rule Malware_Cridex_Generic {
    meta:
        id = "3uv431tYrGMyckCzdEO0v"
        fingerprint = "v1_sha256_943271d834a8a234404ad52669ef3082810bbcea01acf9b5763208dd9fe62748"
        version = "1.0"
        date = "2014-01-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "F. Roth"
        description = "Rule matching Cridex-C Malware distributed in a German Campaign, January 2014 (Vodafone, Telekom, Volksbank bills)"
        category = "INFO"
        reference = "https://www.virustotal.com/en/file/519120e4ff6524353247dbac3f66e6ddad711d384e317923a5bb66c16601743e/analysis/"
        hash = "86d3e008b8f5983c374a4859739f7de4"

strings:
        $c1 = "NEWDEV.dll" fullword
        $b2a = "COMUID.dll" fullword
        $b2b = "INSENG.dll" fullword
condition:
        $c1 and 1 of ($b*)
}
