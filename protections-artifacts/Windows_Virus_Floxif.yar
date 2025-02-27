rule Windows_Virus_Floxif_493d1897 {
    meta:
        id = "7WvXza5wdgxMajzYfhlOGN"
        fingerprint = "v1_sha256_d3f516966bd4423c49771251075a1ea2f725aec91615f7f44dd098da2a4f3574"
        version = "1.0"
        date = "2023-09-26"
        modified = "2023-11-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Virus.Floxif"
        reference_sample = "e628b7973ee25fdfd8f849fdf5923c6fba48141de802b0b4ce3e9ad2e40fe470"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 8B 54 24 04 80 7A 03 01 75 04 8D 42 04 C3 8D 42 04 53 8B C8 8A 5A 02 84 DB 74 02 30 19 8A 19 }
    condition:
        all of them
}

