rule Windows_Trojan_ShadowPad_be71209d {
    meta:
        id = "6iCGc7sWRojPthqLO2OHXp"
        fingerprint = "v1_sha256_24e035bbcd5d44877e6e582a995d0035ad26c53e832c34b0c8a3836cb1a11637"
        version = "1.0"
        date = "2023-01-31"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Target ShadowPad loader"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        threat_name = "Windows.Trojan.ShadowPad"
        reference_sample = "452b08d6d2aa673fb6ccc4af6cebdcb12b5df8722f4d70d1c3491479e7b39c05"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "{%8.8x-%4.4x-%4.4x-%8.8x%8.8x}"
    condition:
        all of them
}

rule Windows_Trojan_ShadowPad_0d899241 {
    meta:
        id = "3avQRj6efVekodWLr00l1w"
        fingerprint = "v1_sha256_57385e149c6419aed2dcd3ecbbe26d8598918395a6480dd5cdb799ce7328901a"
        version = "1.0"
        date = "2023-01-31"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Target ShadowPad payload"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/update-to-the-REF2924-intrusion-set-and-related-campaigns"
        threat_name = "Windows.Trojan.ShadowPad"
        reference_sample = "cb3a425565b854f7b892e6ebfb3734c92418c83cd590fc1ee9506bcf4d8e02ea"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "hH#whH#w" fullword
        $a2 = "Yuv~YuvsYuvhYuv]YuvRYuvGYuv1:tv<Yuvb#tv1Yuv-8tv&Yuv" fullword
        $a3 = "pH#wpH#w" fullword
        $a4 = "HH#wHH#wA" fullword
        $a5 = "xH#wxH#w:$" fullword
        $re1 = /(HTTPS|TCP|UDP):\/\/[^:]+:443/
    condition:
        4 of them
}

