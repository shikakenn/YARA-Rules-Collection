rule Linux_Ransomware_Erebus_ead4f55b {
    meta:
        id = "21EVQKwXQxuh4SSnZctQeY"
        fingerprint = "v1_sha256_82e81577372298623ee3ed3583bb18b2c0cfff30abbacf2909e7efca35c83bd7"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Erebus"
        reference_sample = "6558330f07a7c90c40006346ed09e859b588d031193f8a9679fe11a85c8ccb37"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "important files have been encrypted"
        $a2 = "max_size_mb"
        $a3 = "EREBUS IS BEST."
    condition:
        2 of them
}

