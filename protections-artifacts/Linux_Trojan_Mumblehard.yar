rule Linux_Trojan_Mumblehard_523450aa {
    meta:
        id = "Aeq08j4hAlvXJOD7I4Op1"
        fingerprint = "v1_sha256_60b4cc388975ce030e03c5c3a48adcfeec25299105206909163f20100fbf45d8"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mumblehard"
        reference_sample = "a637ea8f070e1edf2c9c81450e83934c177696171b24b4dff32dfb23cefa56d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 09 75 05 89 03 89 53 04 B8 02 00 00 00 50 80 F9 09 75 0B CD 80 }
    condition:
        all of them
}

