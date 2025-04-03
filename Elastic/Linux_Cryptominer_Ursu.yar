rule Linux_Cryptominer_Ursu_3c05f8ab {
    meta:
        id = "6Hd4sN4F2uurBRKbrplqtD"
        fingerprint = "v1_sha256_8261e4ee40131cd7df61914cd7bdf154e8a2b5fa3abd9d301436f9371253f510"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Ursu"
        reference_sample = "d72361010184f5a48386860918052dbb8726d40e860ea0287994936702577956"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 64 55 4C 2C 20 0A 09 30 78 33 30 32 38 36 30 37 38 32 38 37 38 }
    condition:
        all of them
}

