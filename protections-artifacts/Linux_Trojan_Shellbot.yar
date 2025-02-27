rule Linux_Trojan_Shellbot_65aa6568 {
    meta:
        id = "65vTeOO9xtKJKsNxaeR6jD"
        fingerprint = "v1_sha256_46558801151ddc2f25bf46a278719f027acca2a18d2a9fcb275f4d787fbb1f0b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Shellbot"
        reference_sample = "457d1f4e1db41a9bdbfad78a6815f42e45da16ad0252673b9a2b5dcefc02c47b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 00 73 74 72 63 6D 70 00 70 61 6D 5F 70 72 6F 6D 70 74 00 }
    condition:
        all of them
}

