rule Linux_Hacktool_Lightning_d9a9173a {
    meta:
        id = "559hHcGGdlB4j0h0zSF5RU"
        fingerprint = "v1_sha256_93961d9771aa4e828e15923064a848291c7814ad4e15e30cd252fc41523d789e"
        version = "1.0"
        date = "2022-11-08"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        threat_name = "Linux.Hacktool.Lightning"
        reference_sample = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "cat /sys/class/net/%s/address" ascii fullword
        $a2 = "{\"ComputerName\":\"%s\",\"Guid\":\"%s\",\"RequestName\":\"%s\",\"Licence\":\"%s\"}" ascii fullword
        $a3 = "sleep 60 && ./%s &" ascii fullword
        $a4 = "Lightning.Core" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_e87c9d50 {
    meta:
        id = "yi453oEJBjikAHT2QyEUw"
        fingerprint = "v1_sha256_455ecf97e7becaf9c40843f8a3f60ec233d35e0061c6994f168428a8835c1b20"
        version = "1.0"
        date = "2022-11-08"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        threat_name = "Linux.Hacktool.Lightning"
        reference_sample = "fd285c2fb4d42dde23590118dba016bf5b846625da3abdbe48773530a07bcd1e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "Execute %s Faild." ascii fullword
        $a2 = "Lightning.Downloader" ascii fullword
        $a3 = "Execute %s Success." ascii fullword
        $a4 = "[-] Socks5 are Running!" ascii fullword
        $a5 = "[-] Get FileInfo(%s) Faild!" ascii fullword
    condition:
        all of them
}

rule Linux_Hacktool_Lightning_3bcac358 {
    meta:
        id = "1U9NyzY64NSyc7V7sSkO6l"
        fingerprint = "v1_sha256_f260372b9f2ea32f93ff7a30dc8239766e713a1e177a483444b14538741c24af"
        version = "1.0"
        date = "2022-11-08"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
        threat_name = "Linux.Hacktool.Lightning"
        reference_sample = "ad16989a3ebf0b416681f8db31af098e02eabd25452f8d781383547ead395237"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "[+] %s:%s %d,ntop:%s,strport:%s" ascii fullword
        $a2 = "%s: reading file \"%s\"" ascii fullword
        $a3 = "%s: kill(%d): %s" ascii fullword
        $a4 = "%s exec \"%s\": %s" ascii fullword
    condition:
        all of them
}

