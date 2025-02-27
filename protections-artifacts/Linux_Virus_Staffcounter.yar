rule Linux_Virus_Staffcounter_d2d608a8 {
    meta:
        id = "zDRu46GJjjmVAfhpObBYg"
        fingerprint = "v1_sha256_e30f1312eb1cbbc4faba3f67527a4e0e955b5684a1ba58cdd82a7a0f1ce3d2b9"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "06e562b54b7ee2ffee229c2410c9e2c42090e77f6211ce4b9fa26459ff310315"
        threat_name = "Linux.Virus.Staffcounter"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 22 00 20 4C 69 6E 75 78 22 20 3C 00 54 6F 3A 20 22 00 20 }
    condition:
        all of them
}

