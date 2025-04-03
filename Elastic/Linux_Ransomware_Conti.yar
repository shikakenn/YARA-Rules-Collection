rule Linux_Ransomware_Conti_53a640f4 {
    meta:
        id = "4XFdw3TqOshaTmJRWW22P6"
        fingerprint = "v1_sha256_b83a47664d8acce7de17ac5972d9fd5e708c8cd3d8ebedc2bacf1397fd25f5d3"
        version = "1.0"
        date = "2022-09-22"
        modified = "2022-10-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "8b57e96e90cd95fc2ba421204b482005fe41c28f506730b6148bcef8316a3201"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 48 D3 EA 48 89 D0 83 E0 01 48 85 C0 0F 95 C0 84 C0 74 0B 8B }
    condition:
        all of them
}

rule Linux_Ransomware_Conti_a89c26cf {
    meta:
        id = "7X93QmIQWuJDbnAjh9KhJp"
        fingerprint = "v1_sha256_301f3f3ece06a1cd6788db6e3003497b27470780eaaad95f40ed926e7623793e"
        version = "1.0"
        date = "2023-07-30"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Conti"
        reference_sample = "95776f31cbcac08eb3f3e9235d07513a6d7a6bf9f1b7f3d400b2cf0afdb088a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "paremeter --size cannot be %d" fullword
        $a2 = "--vmkiller" fullword
        $a3 = ".conti" fullword
        $a4 = "Cannot create file vm-list.txt" fullword
    condition:
        3 of them
}

