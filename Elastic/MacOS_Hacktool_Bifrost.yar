rule MacOS_Hacktool_Bifrost_39bcbdf8 {
    meta:
        id = "21j3cVZm0sJnLlYJ7ZV0rs"
        fingerprint = "v1_sha256_a2ff4f1aca51e80f2b277e9171e99a80a75177d1d17d487de2eb8872832cb0d5"
        version = "1.0"
        date = "2021-10-12"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Hacktool.Bifrost"
        reference_sample = "e2b64df0add316240b010db7d34d83fc9ac7001233259193e5a72b6e04aece46"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $s1 = "[dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]" fullword
        $s2 = "[-] Error in parseKirbi: %s"
        $s3 = "[-] Error in parseTGSREP: %s"
        $s4 = "genPasswordHashPassword:Length:Enc:Username:Domain:Pretty:"
        $s5 = "storeLKDCConfDataFriendlyName:Hostname:Password:CCacheName:"
        $s6 = "bifrostconsole-"
        $s7 = "-kerberoast"
        $s8 = "asklkdcdomain"
        $s9 = "askhash"
    condition:
        3 of them
}

