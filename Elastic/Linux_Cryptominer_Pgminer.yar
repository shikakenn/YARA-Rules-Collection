rule Linux_Cryptominer_Pgminer_ccf88a37 {
    meta:
        id = "3nKCXUUq5boAHDX1APc5fB"
        fingerprint = "v1_sha256_77833cdb319bc8e22db2503478677d5992774105f659fe7520177a691c83aa91"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Pgminer"
        reference_sample = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { F6 41 83 C5 02 48 8B 5D 00 8A 0B 80 F9 2F 76 7E 41 83 FF 0A B8 0A 00 }
    condition:
        all of them
}

rule Linux_Cryptominer_Pgminer_5fb2efd5 {
    meta:
        id = "zZNTB5WUQpmGgyZCKiBsN"
        fingerprint = "v1_sha256_4c247f40c9781332f04f82a244f6e8e22c9c744963f736937eddecf769b40a54"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Pgminer"
        reference_sample = "6d296648fdbc693e604f6375eaf7e28b87a73b8405dc8cd3147663b5e8b96ff0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 00 16 00 00 00 0E 00 00 00 18 03 00 7F EB 28 33 C5 56 5D F2 50 67 C5 6F }
    condition:
        all of them
}

