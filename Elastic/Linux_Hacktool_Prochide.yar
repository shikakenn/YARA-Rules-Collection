rule Linux_Hacktool_Prochide_7333221a {
    meta:
        id = "155R36kdEQjshTzOV1h76n"
        fingerprint = "v1_sha256_413f19744240eae0a87d56da1e524e2afa0fe0ec385bd9369218713b13a93495"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Hacktool.Prochide"
        reference_sample = "fad956a6a38abac8a8a0f14cc50f473ec6fc1c9fd204e235b89523183931090b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF FF 83 BD 9C FC FF FF FF 75 14 BF 7F 22 40 00 }
    condition:
        all of them
}

