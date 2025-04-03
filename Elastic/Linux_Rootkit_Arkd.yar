rule Linux_Rootkit_Arkd_bbd56917 {
    meta:
        id = "2uCNM8XRXO79B1Z0PrDrEs"
        fingerprint = "v1_sha256_5e1ce9c37d92222e21b43f9e5f3275a70c6e8eb541c3762f9382c5d5c72fb50d"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Arkd"
        reference_sample = "e0765f0e90839b551778214c2f9ae567dd44838516a3df2c73396a488227a600"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 7D 0B B8 FF FF FF FF EB 11 8D 74 26 00 39 C1 7F 04 31 C0 EB 05 B8 01 00 }
    condition:
        all of them
}

