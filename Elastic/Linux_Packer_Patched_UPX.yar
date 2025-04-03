rule Linux_Packer_Patched_UPX_62e11c64 {
    meta:
        id = "5iiB2WeGEuH5HVoHwVxcjl"
        fingerprint = "v1_sha256_cb576fdd59c255234a96397460b81cbb2deeb38befaed101749b7bb515624028"
        version = "1.0"
        date = "2021-06-08"
        modified = "2021-07-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://cujo.com/upx-anti-unpacking-techniques-in-iot-malware/"
        threat_name = "Linux.Packer.Patched_UPX"
        reference_sample = "02f81a1e1edcb9032a1d7256a002b11e1e864b2e9989f5d24ea1c9b507895669"
        severity = 60
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 55 50 58 21 [4] 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        all of them and $a in (0 .. 255)
}

