rule MacOS_Backdoor_Useragent_1a02fc3a {
    meta:
        id = "65aozxVFIaNNpKnprgjIU"
        fingerprint = "v1_sha256_90debdfc24ef100952302808a2e418bca2a46be3e505add9a0ccf4c49aff5102"
        version = "1.0"
        date = "2021-11-11"
        modified = "2022-07-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Backdoor.Useragent"
        reference_sample = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $s1 = "/Library/LaunchAgents/com.UserAgent.va.plist"
        $s2 = "this is not root"
        $s3 = "rm -Rf "
        $s4 = "/start.sh"
        $s5 = ".killchecker_"
    condition:
        4 of them
}

