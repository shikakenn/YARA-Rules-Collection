rule Windows_Trojan_ProtectS_9f6eaa90 {
    meta:
        id = "70Jhgk1iEuDE0TJtHG2EYr"
        fingerprint = "v1_sha256_ddc8c97598b2d961dc51bdf2c7ab96abcec63824acd39b767bc175371844c1e5"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.ProtectS"
        reference_sample = "c0330e072b7003f55a3153ac3e0859369b9c3e22779b113284e95ce1e2ce2099"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\ProtectS.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

