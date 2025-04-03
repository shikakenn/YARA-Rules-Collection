rule Linux_Trojan_Xpmmap_7dcc3534 {
    meta:
        id = "7BIzsQWxUXsfw4rtu5FMbb"
        fingerprint = "v1_sha256_f88cc0f02797651e8cdf8e25b67a92f7825ec616b79df21daae798b613baf334"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Xpmmap"
        reference_sample = "765546a981921187a4a2bed9904fbc2ccb2a5876e0d45c72e79f04a517c1bda3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 89 45 F8 48 83 7D F8 FF 75 14 BF 10 0C 40 00 }
    condition:
        all of them
}

