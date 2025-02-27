rule Windows_VulnDriver_EneIo_6e01882f {
    meta:
        id = "1c4P5TqJUm1HIQJlJzqUmp"
        fingerprint = "v1_sha256_144ac5375cb637b6301a2275f2412fbd0d0c5fb23105c7cce5aa7912cf68fa2c"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.EneIo"
        reference_sample = "175eed7a4c6de9c3156c7ae16ae85c554959ec350f1c8aaa6dfe8c7e99de3347"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\Release\\EneIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

