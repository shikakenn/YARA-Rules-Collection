rule Linux_Trojan_Sambashell_f423755d {
    meta:
        id = "4GqYaHX9Ti0k0tZT0Qti8S"
        fingerprint = "v1_sha256_b93c671fae87cd635679142d248cb2b754389ba3b416f3370ea331640eb906ab"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sambashell"
        reference_sample = "bd8a3728a59afbf433799578ef597b9a7211c8d62e87a25209398814851a77ea"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 01 00 00 00 FC 0E 00 00 FC 1E 00 00 FC 1E 00 00 74 28 00 00 }
    condition:
        all of them
}

