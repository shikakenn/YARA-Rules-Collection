rule Windows_Hacktool_CheatEngine_fedac96d {
    meta:
        id = "7MF8kduJe2ziaGiFDZ4YFz"
        fingerprint = "v1_sha256_426b6d388f86dd935d8165af0fb7c8491c987542755ec4c7c53a35a9003f8680"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: Cheat Engine"
        category = "INFO"
        threat_name = "Windows.Hacktool.CheatEngine"
        reference_sample = "b20b339a7b61dc7dbc9a36c45492ba9654a8b8a7c8cbc202ed1dfed427cfd799"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 61 74 20 45 6E 67 69 6E 65 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

