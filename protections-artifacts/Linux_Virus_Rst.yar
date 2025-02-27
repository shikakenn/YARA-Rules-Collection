rule Linux_Virus_Rst_1214e2ae {
    meta:
        id = "2ILNWhFLhJmUOMDxERrEoa"
        fingerprint = "v1_sha256_82de4a97f414d591daba2d5d49b941ec4c51d6a6af36f97f062eaac5c74ebe30"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Virus.Rst"
        reference_sample = "b0e4f44d2456960bb6b20cb468c4ca1390338b83774b7af783c3d03e49eebe44"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 00 00 53 89 F3 CD 80 5B 58 5F 5E 5A 59 5B C3 }
    condition:
        all of them
}

