rule Windows_Ransomware_Maui_266dea64 {
    meta:
        id = "25U5hXVFCYbClgdC3r5T0f"
        fingerprint = "v1_sha256_2094920615b6297adb222003d25a8d0934a89f24869e7e70644a4956021c7afc"
        version = "1.0"
        date = "2022-07-08"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Maui"
        reference_sample = "5b7ecf7e9d0715f1122baf4ce745c5fcd769dee48150616753fec4d6da16e99e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Please append it by <Godhead> using -maui option." wide fullword
        $a2 = "Please overwrite it by <Godhead> using -maui option." wide fullword
        $a3 = "maui.log" wide fullword
        $a4 = "maui.key" wide fullword
        $a5 = "maui.evd" wide fullword
        $a6 = "Encrypt[%s]: %s" wide fullword
        $a7 = "PROCESS_GOINGON[%d%% / %d%%]: %s" wide fullword
        $a8 = "PROCESS_REPLACECONFIRM: %s" wide fullword
        $seq_encrypt_priv_key = { 55 8B 6C 24 ?? 57 8B F9 85 DB 74 ?? 85 FF 74 ?? 85 ED 74 ?? 56 8D 87 ?? ?? ?? ?? 50 6A ?? E8 ?? ?? ?? ?? 8B 4D ?? 8B 51 ?? 6A ?? 52 8B F0 56 53 57 E8 ?? ?? ?? ?? 8B F8 83 C4 ?? 85 FF 7F ?? E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 ?? 5E 5F 83 C8 ?? 5D C3 }
        $seq_get_private_key = { 57 8B F8 85 FF 75 ?? 5F C3 56 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 80 7F ?? ?? 8B F0 74 ?? 8B 07 50 56 E8 ?? ?? ?? ?? EB ?? 8B 0F 51 56 E8 ?? ?? ?? ?? 83 C4 ?? 85 F6 75 ?? 5E 33 C0 5F C3 }
        $seq_get_pub_key = { B9 F4 FF FF FF 2B 4C 24 ?? 6A 02 51 53 E8 ?? ?? ?? ?? 8B 54 24 ?? 8B 07 53 6A ?? 52 50 E8 ?? ?? ?? ?? 53 E8 ?? ?? ?? ?? 32 DB 8B C7 E8 ?? ?? ?? ?? 89 46 28 8B 0F 51 E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 83 C4 ?? 5F 8B C6 5E 5B 33 CC E8 ?? ?? ?? ?? 81 C4 ?? ?? ?? ?? C3 }
    condition:
        5 of ($a*) or 2 of ($seq*)
}

