rule Windows_Trojan_PrivateLoader_96ac2734 {
    meta:
        id = "EexUNPf8pU5jPXaySwoHH"
        fingerprint = "v1_sha256_9f96f1c54853866e124d0996504e6efd3d154111390617999cc10520d7f68fe6"
        version = "1.0"
        date = "2023-01-03"
        modified = "2023-02-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PrivateLoader"
        reference_sample = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $xor_decrypt = { 0F 28 85 ?? ?? FF FF 66 0F EF ?? ?? FE FF FF 0F 29 85 ?? ?? FF FF 0F 28 85 ?? ?? FF FF }
        $str0 = "https://ipinfo.io/" wide
        $str1 = "Content-Type: application/x-www-form-urlencoded" wide
        $str2 = "https://db-ip.com/" wide
    condition:
        all of ($str*) and #xor_decrypt > 3
}

