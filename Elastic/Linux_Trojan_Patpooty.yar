rule Linux_Trojan_Patpooty_e2e0dff1 {
    meta:
        id = "1HyCsxseovIAICwCGiJ23o"
        fingerprint = "v1_sha256_ec7d12296383ca0ed20e3221fb96b9dbdaf6cc7f07f5c8383e43489a9fd6fcfe"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "d38b9e76cbc863f69b29fc47262ceafd26ac476b0ae6283d3fa50985f93bedf3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F0 8B 45 E4 8B 34 88 8D 7E 01 FC 31 C0 83 C9 FF F2 AE F7 D1 83 }
    condition:
        all of them
}

rule Linux_Trojan_Patpooty_f90c7e43 {
    meta:
        id = "4RsY169wVNH6EQ53cpa0u3"
        fingerprint = "v1_sha256_2d995722b06ce51a5378e395896764421f84afcf6b13855a87ed43d9b9e38982"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Patpooty"
        reference_sample = "79475a66be8741d9884bc60f593c81a44bdb212592cd1a7b6130166a724cb3d3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { C2 48 39 C2 75 F1 C7 43 58 01 00 00 00 C7 43 54 01 00 00 00 C7 43 50 01 00 }
    condition:
        all of them
}

