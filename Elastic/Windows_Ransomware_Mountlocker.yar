rule Windows_Ransomware_Mountlocker_126a76e2 {
    meta:
        id = "2wBxkus2ey3Xxwkdpyg0e4"
        fingerprint = "v1_sha256_5a5e157a245a75033abbe6bc7aa66fe6af6d91dc30abe1fdadce85f8f3905b1e"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Mountlocker"
        reference_sample = "4a5ac3c6f8383cc33c795804ba5f7f5553c029bbb4a6d28f1e4d8fb5107902c1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[SKIP] locker.dir.check > black_list name=%s" wide fullword
        $a2 = "[OK] locker.dir.check > name=%s" wide fullword
        $a3 = "[ERROR] locker.worm > execute pcname=%s" wide fullword
        $a4 = "[INFO] locker.work.enum.net_drive > enum finish name=%s" wide fullword
        $a5 = "[WARN] locker.work.enum.server_shares > logon on server error=%u pcname=%s" wide fullword
    condition:
        any of them
}

