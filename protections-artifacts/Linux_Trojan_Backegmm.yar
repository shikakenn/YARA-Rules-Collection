rule Linux_Trojan_Backegmm_b59712e6 {
    meta:
        id = "1wpZUekDkzXqp6qDObSrQk"
        fingerprint = "v1_sha256_a2e6016bfd8475880c28c89b5f5beeef1335de9529d44bbe7c5aaa352aab9a29"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Backegmm"
        reference_sample = "d6c8e15cb65102b442b7ee42186c58fa69cd0cb68f4fd47eb5ad23763371e0be"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 69 73 74 65 6E 00 66 6F 72 6B 00 73 70 72 69 6E 74 66 00 68 }
    condition:
        all of them
}

