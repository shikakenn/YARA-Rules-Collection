rule Windows_Packer_ScrubCrypt_6a75a4bb {
    meta:
        id = "3pWBEQgO4N9iIlvrDswYUo"
        fingerprint = "v1_sha256_edcaa6f1cc85ef084ae5bf2524f39869a90b008dce85e72bca4835565f067ca7"
        version = "1.0"
        date = "2023-04-18"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Packer.ScrubCrypt"
        reference_sample = "05c1eea2ff8c31aa5baf1dfd8015988f7e737753275ed1c8c29013a3a7414b50"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 43 68 65 63 6B 52 65 6D 6F 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6E 74 00 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6E 74 }
        $b = { 53 63 72 75 62 43 72 79 70 74 00 53 74 61 72 74 }
    condition:
        all of them
}

