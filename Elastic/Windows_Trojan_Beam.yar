rule Windows_Trojan_Beam_e41b243a {
    meta:
        id = "1hniLpi8ZDif550C1SUErh"
        fingerprint = "v1_sha256_295837743ecfa51e1713d19cba24ff8885c8716201caac058ae8b2bc9e008e6c"
        version = "1.0"
        date = "2021-12-07"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Beam"
        reference_sample = "233a1f1dcbb679d31dab7744358b434cccabfc752baf53ba991388ced098f7c8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 69 70 22 3A 22 28 5B 30 2D 39 2E 5D 2B 29 }
        $a2 = { 63 6F 75 6E 74 72 79 5F 63 6F 64 65 22 3A 22 28 5C 77 2A 29 }
        $a3 = { 20 2F 66 20 26 20 65 72 61 73 65 20 }
        $a4 = "\\BeamWinHTTP2\\Release\\BeamWinHTTP.pdb"
    condition:
        all of them
}

rule Windows_Trojan_Beam_5a951d13 {
    meta:
        id = "6OCyoDxUHDbuQLjbyqoCRo"
        fingerprint = "v1_sha256_3419b649717b69f07334bd966f438dd0b77f03572fe14f4b88ce95a2a86cae07"
        version = "1.0"
        date = "2021-12-07"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Beam"
        reference_sample = "233a1f1dcbb679d31dab7744358b434cccabfc752baf53ba991388ced098f7c8"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 24 40 8B CE 2B C8 3B CA 0F 42 D1 83 FF 10 8D 4C 24 18 0F 43 CB }
    condition:
        all of them
}

