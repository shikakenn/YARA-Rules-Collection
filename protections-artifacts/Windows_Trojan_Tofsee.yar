rule Windows_Trojan_Tofsee_26124fe4 {
    meta:
        id = "1GHUG6BOSCOgeGhIzRbqOV"
        fingerprint = "v1_sha256_e765953dec7c7b2a1fbebf92c2fff46453c8258722ad5ca92ba4c7526a8b0c66"
        version = "1.0"
        date = "2022-03-31"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Tofsee"
        reference_sample = "e658fe6d3bd685f41eb0527432099ee01075bfdb523ef5aa3e5ebd42221c8494"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 55 8B EC 8B 45 ?? 57 8B 7D ?? B1 01 85 FF 74 ?? 56 8B 75 ?? 2B F0 8A 14 06 32 55 ?? 88 10 8A D1 02 55 ?? F6 D9 00 55 ?? 40 4F 75 ?? 5E 8B 45 ?? 5F 5D C3 }
        $b = { 8B 44 24 ?? 53 8A 18 84 DB 74 ?? 8B D0 2B 54 24 ?? 8B 4C 24 ?? 84 DB 74 ?? 8A 19 84 DB 74 ?? 38 1C 0A 75 ?? 41 80 3C 0A 00 75 ?? 80 39 00 74 ?? 40 8A 18 42 84 DB 75 ?? 33 C0 5B C3 }
    condition:
        any of them
}

