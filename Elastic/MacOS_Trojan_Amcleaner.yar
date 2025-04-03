rule MacOS_Trojan_Amcleaner_445bb666 {
    meta:
        id = "2qv2ED7kmS5iCaQVZZ4HWL"
        fingerprint = "v1_sha256_664829ff761186ec8f3055531b5490b7516756b0aa9d0183d4c17240a5ca44c4"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 10 A0 5B 15 57 A8 8B 17 02 F9 A8 9B E8 D5 8C 96 A7 48 42 91 E5 EC 3D C8 AC 52 }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_a91d3907 {
    meta:
        id = "5XhRWKhL5nU3bChCSnp2FR"
        fingerprint = "v1_sha256_e61ceea117acf444a6b137b93d7c335c6eb8a7e13a567177ec4ea44bf64fd5c6"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }
    condition:
        all of them
}

rule MacOS_Trojan_Amcleaner_8ce3fea8 {
    meta:
        id = "74VJyRzAx2yEsvNtimg7Cl"
        fingerprint = "v1_sha256_08c4b5b4afefbf1ee207525f9b28bc7eed7b55cb07f8576fddfa0bbe95002769"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Amcleaner"
        reference_sample = "c85bf71310882bc0c0cf9b74c9931fd19edad97600bc86ca51cf94ed85a78052"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 54 40 22 4E 53 54 61 62 6C 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6B 54 70 51 }
    condition:
        all of them
}

