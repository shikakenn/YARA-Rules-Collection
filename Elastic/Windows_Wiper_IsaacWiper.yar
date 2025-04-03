rule Windows_Wiper_IsaacWiper_239cd2dc {
    meta:
        id = "1V43JjieIWuFpqC88mYOtB"
        fingerprint = "v1_sha256_102ffe215b1e1c39e1225cb39dfeb10a20a08c5b10f836490fc1501c6eb9e930"
        version = "1.0"
        date = "2022-03-04"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Wiper.IsaacWiper"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "C:\\ProgramData\\log.txt" wide fullword
        $a2 = "system physical drive -- FAILED" wide fullword
        $a3 = "-- system logical drive: " wide fullword
        $a4 = "start erasing system logical drive " wide fullword
        $a5 = "-- logical drive: " wide fullword
        $a6 = "-- start erasing logical drive " wide fullword
    condition:
        5 of them
}

