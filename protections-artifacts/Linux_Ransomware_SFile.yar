rule Linux_Ransomware_SFile_9e347b52 {
    meta:
        id = "5ay0mtZqySfDDJ0oSqpG3Y"
        fingerprint = "v1_sha256_394571fd5746132d15da97428c3afc149435d91d5432eadf1c838d4a6433c7c1"
        version = "1.0"
        date = "2023-07-29"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.SFile"
        reference_sample = "49473adedc4ee9b1252f120ad8a69e165dc62eabfa794370408ae055ec65db9d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 49 74 27 73 20 6A 75 73 74 20 61 20 62 75 73 69 6E 65 73 73 2E }
        $a2 = { 41 6C 6C 20 64 61 74 61 20 69 73 20 70 72 6F 70 65 72 6C 79 20 70 72 6F 74 65 63 74 65 64 20 61 67 61 69 6E 73 74 20 75 6E 61 75 74 68 6F 72 69 7A 65 64 20 61 63 63 65 73 73 20 62 79 20 73 74 65 61 64 79 20 65 6E 63 72 79 70 74 69 6F 6E 20 74 65 63 68 6E 6F 6C 6F 67 79 2E }
    condition:
        all of them
}

