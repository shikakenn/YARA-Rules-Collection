rule Linux_Trojan_Subsevux_e9e80c1e {
    meta:
        id = "1lrbvvh70hSSLp7aGmLsi1"
        fingerprint = "v1_sha256_8bc38f26da5a3350cbae3e93b890220bb461ff77e83993a842f68db8f757e435"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Subsevux"
        reference_sample = "a4ccd399ea99d4e31fbf2bbf8017c5368d29e630dc2985e90f07c10c980fa084"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 C0 89 45 F4 83 7D F4 00 79 1C 83 EC 0C 68 }
    condition:
        all of them
}

