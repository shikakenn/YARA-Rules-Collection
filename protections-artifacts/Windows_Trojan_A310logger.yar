rule Windows_Trojan_A310logger_520cd7ec {
    meta:
        id = "tUVPndXw8OTJTx0LWsvaw"
        fingerprint = "v1_sha256_6095ce913e3fb1cfc2f1b091598fc06b2dfec30c2353be7df08dcbb1a06b07c3"
        version = "1.0"
        date = "2022-01-11"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.A310logger"
        reference_sample = "60fb9597e5843c72d761525f73ca728409579d81901860981ebd84f7d153cfa3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/dumps9taw" ascii fullword
        $a2 = "/logstatus" ascii fullword
        $a3 = "/checkprotection" ascii fullword
        $a4 = "[CLIPBOARD]<<" wide fullword
        $a5 = "&chat_id=" wide fullword
    condition:
        all of them
}

