rule MacOS_Cryptominer_Xmrig_241780a1 {
    meta:
        id = "4CL5EuQ8nFhSU6bFxGLIy4"
        fingerprint = "v1_sha256_9e091f6881a96abdc6592db385eb9026806befdda6bda4489470b4e16e1d4d87"
        version = "1.0"
        date = "2021-09-30"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Cryptominer.Xmrig"
        reference_sample = "2e94fa6ac4045292bf04070a372a03df804fa96c3b0cb4ac637eeeb67531a32f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a1 = "mining.set_target" ascii fullword
        $a2 = "XMRIG_HOSTNAME" ascii fullword
        $a3 = "Usage: xmrig [OPTIONS]" ascii fullword
        $a4 = "XMRIG_VERSION" ascii fullword
    condition:
        all of them
}

