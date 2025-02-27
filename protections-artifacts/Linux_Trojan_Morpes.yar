rule Linux_Trojan_Morpes_d2ae1edf {
    meta:
        id = "4ITKOCRBpvIoGHi56xoJea"
        fingerprint = "v1_sha256_27eb8b4d0f91477c2ac26a5e25bfc52903faf5501300ec40773d3fc6797c3218"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Morpes"
        reference_sample = "14c4c297388afe4be47be091146aea6c6230880e9ea43759ef29fc1471c4b86b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 64 B0 05 00 00 B0 05 00 00 B0 05 00 00 3C 00 00 00 3C 00 00 00 }
    condition:
        all of them
}

