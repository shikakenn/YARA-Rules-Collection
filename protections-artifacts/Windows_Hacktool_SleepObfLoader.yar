rule Windows_Hacktool_SleepObfLoader_460a1a75 {
    meta:
        id = "1NgitLuLqzAGObsZ621Qlt"
        fingerprint = "v1_sha256_c0bc1b7ef71c1a91fc487f904315c6f187530ab39825f90f55ac36625d5b93cf"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        threat_name = "Windows.Hacktool.SleepObfLoader"
        reference_sample = "84b3bc58ec04ab272544d31f5e573c0dd7812b56df4fa445194e7466f280e16d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { BA 01 00 00 00 41 B8 20 01 00 00 8B 48 3C 8B 4C 01 28 48 03 C8 48 89 0D ?? ?? ?? ?? FF ?? ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? B9 01 00 00 00 }
        $b = { 8A 50 20 83 60 24 F0 80 E2 F8 48 8B ?? ?? ?? 4C 8B ?? ?? ?? 48 89 08 48 8B ?? ?? ?? 48 89 48 08 }
        $c = { 8B 46 FB 41 89 40 18 0F B7 46 FF 66 41 89 40 1C 8A 46 01 41 88 40 1E }
    condition:
        all of them
}

