rule Windows_Hacktool_SharpGPOAbuse_14ea480e {
    meta:
        id = "62eUQKXg6QkY3aIAfMbTx6"
        fingerprint = "v1_sha256_efc1259f4ed05c8f41df75c056d36fd5a808a92b5c88cfb0522caedea39476b4"
        version = "1.0"
        date = "2024-03-25"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpGPOAbuse"
        reference_sample = "d13f87b9eaf09ef95778b2f1469aa34d03186d127c8f73c73299957d386c78d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $name = "SharpGPOAbuse" wide fullword
        $s1 = "AddUserTask" wide fullword
        $s2 = "AddComputerTask" wide fullword
        $s3 = "AddComputerScript" wide fullword
        $s4 = "AddUserScript" wide fullword
        $s5 = "GPOName" wide fullword
        $s6 = "ScheduledTasks" wide fullword
        $s7 = "NewImmediateTask" wide fullword
    condition:
        ($name and 1 of ($s*)) or all of ($s*)
}

