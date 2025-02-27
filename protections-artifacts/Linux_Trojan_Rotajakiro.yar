rule Linux_Trojan_Rotajakiro_fb24f399 {
    meta:
        id = "7LA0es0AsOlOP2Bygecy8S"
        fingerprint = "v1_sha256_be33fdda50ef0ea1a0cf45835cc2b7a805cecb3fff371ed6d93e01c2d477d867"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "023a7f9ed082d9dd7be6eba5942bfa77f8e618c2d15a8bc384d85223c5b91a0c"
        threat_name = "Linux.Trojan.Rotajakiro"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 41 56 41 55 41 54 49 89 FD 55 53 48 63 DE 48 83 EC 08 0F B6 17 80 }
    condition:
        all of them
}

