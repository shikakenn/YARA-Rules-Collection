rule Windows_Trojan_CaesarKbd_32bb198b {
    meta:
        id = "1Vwz89cPwt9fRQzDf2RauW"
        fingerprint = "v1_sha256_f708706524515f98ebf612ac98318ee7172347096251d9ccd723f439070521de"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-06-09"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CaesarKbd"
        reference_sample = "d4335f4189240a3bcafa05fab01f0707cc8e3dd7a2998af734c24916d9e37ca8"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "CaesarKbd_IOCtrl"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

