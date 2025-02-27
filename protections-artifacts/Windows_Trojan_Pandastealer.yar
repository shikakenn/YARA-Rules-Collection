rule Windows_Trojan_Pandastealer_8b333e76 {
    meta:
        id = "3Rc0pIxBwav9F6VgiPI6R2"
        fingerprint = "v1_sha256_5878799338fc18bac0f946faeadd59c921dee32c9391fc12d22c72c0cd6733a8"
        version = "1.0"
        date = "2021-09-02"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Pandastealer"
        reference_sample = "ec346bd56be375b695b4bc76720959fa07d1357ffc3783eb61de9b8d91b3d935"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "] - [user: " ascii fullword
        $a2 = "[-] data unpacked failed" ascii fullword
        $a3 = "[+] data unpacked" ascii fullword
        $a4 = "\\history\\" ascii fullword
        $a5 = "PlayerName" ascii fullword
    condition:
        all of them
}

