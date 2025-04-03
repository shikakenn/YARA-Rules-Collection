rule Multi_Ransomware_BlackCat_aaf312c3 {
    meta:
        id = "Yq1qBKRWfyFRFOoOmsl7u"
        fingerprint = "v1_sha256_0771ab5a795af164a568bda036cccf08afeb33458f2cd5a7240349fca9b60ead"
        version = "1.0"
        date = "2022-02-02"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $chacha20_enc = { EF D9 F3 0F 7F 14 3B F3 0F 7F 5C 3B 10 83 C7 20 39 F8 75 D0 8B }
        $crc32_imp = { F3 0F 6F 02 66 0F 6F D1 66 0F 3A 44 CD 11 83 C0 F0 83 C2 10 66 0F 3A 44 D4 00 83 F8 0F 66 0F EF C8 66 0F EF CA }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_00e525d7 {
    meta:
        id = "4VOvdA9WcDIxbwSIvstuxU"
        fingerprint = "v1_sha256_e44625d0fa8308b9d4d63a9e6920b4da4a2ce124437f122b2c8fe5cf0ab85a6b"
        version = "1.0"
        date = "2022-02-02"
        modified = "2022-08-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "ata\",\"boot\",\"config.msi\",\"google\",\"perflogs\",\"appdata\",\"windows.old\"],\"exclude_file_names\":[\"desktop.ini\",\"aut"
        $a2 = "locker::core::windows::processvssadmin.exe delete shadows /all /quietshadow_copy::remove_all=" ascii fullword
        $a3 = "\\\\.\\pipe\\__rust_anonymous_pipe1__." ascii fullword
        $a4 = "--bypass-p-p--bypass-path-path --no-prop-servers \\\\" ascii fullword
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_c4b043e6 {
    meta:
        id = "79tCGnngPTqd9C9gANKRuS"
        fingerprint = "v1_sha256_1262ca76581920f08a6482ead68023fdfff08a9ddd19e00230054e3167dc184c"
        version = "1.0"
        date = "2022-09-12"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_70171625 {
    meta:
        id = "1M5fnDYw6zWXBeVZVm7VkA"
        fingerprint = "v1_sha256_fd07acd7c8627754f000c44827848bf65bcaa96f2dfb46e41542f3c9b40eee78"
        version = "1.0"
        date = "2023-01-05"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $str0 = "}RECOVER-${EXTENSION}-FILES.txt"
        $str1 = "?access-key=${ACCESS_KEY}"
        $str2 = "${NOTE_FILE_NAME}"
        $str3 = "enable_network_discovery"
        $str4 = "enable_set_wallpaper"
        $str5 = "enable_esxi_vm_kill"
        $str6 = "strict_include_paths"
        $str7 = "exclude_file_path_wildcard"
        $str8 = "${ACCESS_KEY}${EXTENSION}"
    condition:
        all of them
}

rule Multi_Ransomware_BlackCat_e066d802 {
    meta:
        id = "1FYQGdZiM6A1bvtTQg1QpP"
        fingerprint = "v1_sha256_00fbb8013faf26c35b6cd8a72ebc246444c37c5ec7a0df2295830e96c01c8720"
        version = "1.0"
        date = "2023-07-27"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "00360830bf5886288f23784b8df82804bf6f22258e410740db481df8a7701525"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "esxcli vm process kill --type=force --world-id=Killing"
        $a2 = "vim-cmd vmsvc/snapshot.removeall $i"
        $a3 = "File already has encrypted extension"
    condition:
        2 of them
}

rule Multi_Ransomware_BlackCat_0ffb0a37 {
    meta:
        id = "YDYptbopj4oSm7Pi8tcFK"
        fingerprint = "v1_sha256_4f28281e4b23868c63438d4800b9e5978426e7c98b6142ef8082cfd251cafe57"
        version = "1.0"
        date = "2023-07-29"
        modified = "2024-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "57136b118a0d6d3c71e522ea53e3305dae58b51f06c29cd01c0c28fa0fa34287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = { C8 C8 00 00 00 89 20 00 00 45 01 00 00 32 22 08 0A 20 64 85 }
        $a2 = { 67 69 74 68 75 62 2E 63 6F 6D 2D 31 65 63 63 36 32 39 39 64 62 39 65 63 38 32 33 2F 73 69 6D 70 6C 65 6C 6F 67 2D }
    condition:
        all of them
}

