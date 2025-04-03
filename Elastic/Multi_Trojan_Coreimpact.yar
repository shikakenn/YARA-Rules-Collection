rule Multi_Trojan_Coreimpact_37703dc3 {
    meta:
        id = "4EeWsMqE12PBy6LH3KaxIS"
        fingerprint = "v1_sha256_0695f22d6eb8c1b335c43213087539db419562bebd6f5b948cbb168c454bd37c"
        version = "1.0"
        date = "2022-08-10"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Trojan.Coreimpact"
        reference_sample = "2d954908da9f63cd3942c0df2e8bb5fe861ac5a336ddef2bd0a977cebe030ad7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $str1 = "Uh, oh, exit() failed" fullword
        $str2 = "agent_recv" fullword
        $str3 = "needroot" fullword
        $str4 = "time is running backwards, corrected" fullword
        $str5 = "junk pointer, too low to make sense" fullword
    condition:
        3 of them
}

