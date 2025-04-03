rule Multi_Ransomware_RansomHub_4a8a07cd {
    meta:
        id = "7ZtPxwtSUCmzULgxWZOc2b"
        fingerprint = "v1_sha256_8e2d062e890cf66418c18ce8988c0ac4744c9f00fdc296e8dd91df39ec240abe"
        version = "1.0"
        date = "2024-09-05"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Ransomware.RansomHub"
        reference_sample = "bfbbba7d18be1aa2e85390fa69a761302756ee9348b7343af6f42f3b5d0a939c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "white_files" ascii fullword
        $a2 = "note_file_name" ascii fullword
        $a3 = "note_short_text" ascii fullword
        $a4 = "set_wallpaper" ascii fullword
        $a5 = "local_disks" ascii fullword
        $a6 = "running_one" ascii fullword
        $a7 = "net_spread" ascii fullword
        $a8 = "kill_processes" ascii fullword
    condition:
        5 of them
}

