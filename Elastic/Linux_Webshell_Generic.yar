rule Linux_Webshell_Generic_e80ff633 {
    meta:
        id = "2EVvGx45J92n66YJhF1Q54"
        fingerprint = "v1_sha256_d345e6ce3e51ed55064aafb1709e9bee7ef2ce87ec80165ac1b58eebd83cefee"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Webshell.Generic"
        reference_sample = "7640ba6f2417931ef901044152d5bfe1b266219d13b5983d92ddbdf644de5818"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 24 A8 00 00 00 89 1C 24 83 3C 24 00 74 23 83 04 24 24 8D B4 24 AC 00 }
    condition:
        all of them
}

rule Linux_Webshell_Generic_41a5fa40 {
    meta:
        id = "6klBbB0VgMctqKeP0kqSrx"
        fingerprint = "v1_sha256_574148bc58626aac00add1989c65ad56315c7e2a8d27c7b96be404d831a7a576"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "18ac7fbc3d8d3bb8581139a20a7fee8ea5b7fcfea4a9373e3d22c71bae3c9de0"
        threat_name = "Linux.Webshell.Generic"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 5A 46 55 6C 73 6E 55 6B 56 52 56 55 56 54 56 46 39 56 55 6B 6B }
    condition:
        all of them
}

