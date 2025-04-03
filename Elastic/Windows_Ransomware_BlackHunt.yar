rule Windows_Ransomware_BlackHunt_7b46cb9c {
    meta:
        id = "6oLudNpPlpDpyUZfjVClWm"
        fingerprint = "v1_sha256_97bb8436574fd814d8278e5a7043e011d0e4f9a7dd9df5e67605f28ac1af1e74"
        version = "1.0"
        date = "2024-03-12"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.BlackHunt"
        reference_sample = "6c4e968c9b53906ba0e86a41eccdabe2b736238cb126852023e15850e956293d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "#BlackHunt_ReadMe.txt" wide fullword
        $a2 = "#BlackHunt_Private.key" wide fullword
        $a3 = "#BlackHunt_ID.txt" wide fullword
        $a4 = "BLACK_HUNT_MUTEX" ascii fullword
        $a5 = "BlackKeys" ascii fullword
        $a6 = "ENCRYPTED VOLUME : %dGB" ascii fullword
        $a7 = "RUNNING TIME : %02dm:%02ds" ascii fullword
    condition:
        4 of them
}

