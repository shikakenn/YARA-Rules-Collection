rule Linux_Trojan_Lala_51deb1f9 {
    meta:
        id = "3AkGOFAOCljgD20WyWZU91"
        fingerprint = "v1_sha256_73a7ec230be9aabcc301095c9c075f839852155419bdd8d5542287f34699ab33"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Lala"
        reference_sample = "f3af65d3307fbdc2e8ce6e1358d1413ebff5eeb5dbedc051394377a4dabffa82"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { D9 7C F3 89 D8 83 7D FC 00 7D 02 F7 D8 8B 55 08 }
    condition:
        all of them
}

