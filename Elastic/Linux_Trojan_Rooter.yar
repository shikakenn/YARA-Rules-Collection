rule Linux_Trojan_Rooter_c8d08d3a {
    meta:
        id = "4VXkuDom0EBr1yuWSBZ0j0"
        fingerprint = "v1_sha256_c91f3112cc61acec08ab3cd59bab2ae833ba0d8ac565ffb26a46982f38af0e71"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Rooter"
        reference_sample = "f55e3aa4d875d8322cdd7caa17aa56e620473fe73c9b5ae0e18da5fbc602a6ba"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D8 DC 04 08 BB 44 C3 04 08 CD 80 C7 05 48 FB 04 }
    condition:
        all of them
}

