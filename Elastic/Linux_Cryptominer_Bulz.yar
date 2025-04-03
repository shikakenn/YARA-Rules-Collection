rule Linux_Cryptominer_Bulz_2aa8fbb5 {
    meta:
        id = "Xo8g2Z3tlsWJVfC3svhyv"
        fingerprint = "v1_sha256_21d8bec73476783e01d2a51a99233f186d7c72b49c9292c42e19e1aa6397d415"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FE D7 C5 D9 72 F2 09 C5 E9 72 D2 17 C5 E9 EF D4 C5 E9 EF D6 C5 C1 }
    condition:
        all of them
}

rule Linux_Cryptominer_Bulz_0998f811 {
    meta:
        id = "3Sdv2xpsovVwxR5HV8wRNJ"
        fingerprint = "v1_sha256_178f6c42582dd99cc5418388d020d4d76f2a9204297a673359fe0a300121c35b"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Bulz"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 79 70 E4 39 C5 F9 70 C9 4E C5 91 72 F0 12 C5 F9 72 D0 0E C5 91 }
    condition:
        all of them
}

