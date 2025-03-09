rule GravityRAT_G1_PDB
{
    meta:
        id = "3w3lojL39eanuMmgZaXgIO"
        fingerprint = "v1_sha256_4a174d08fde20aeffd3a59a21fa2f18263f74ee5c393ac0dd19f10947b65ff8f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Michael Worth"
        description = "PDB path for Gravity RAT G1"
        category = "INFO"
        reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"

    strings:
        $PDB1 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\G1 Main Virus\\systemInterrupts\\gravity\\obj\\x86\\Debug\\systemInterrupts.pdb"
        $PDB2 = "f:\\F\\Windows Work\\G1\\Adeel's Laptop\\"
               $PDB3 = "\\gravity\\obj\\x86\\Debug\\"
    condition:
        any of them
}

rule GravityRAT_G2_PDB
{
    meta:
        id = "1pvjEXfEMWbxipWdp7vs9I"
        fingerprint = "v1_sha256_afc044aa5dbef53ac3cc8108f149e0ac9ae60fd8b5d4697af5c51f1538f88cef"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Michael Worth"
        description = "PDB path for Gravity RAT G2"
        category = "INFO"
        reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"

    strings:
        $PDB1 = "e:\\Windows Work\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2 v5) (Current)\\Microsoft Virus Solutions\\obj\\Debug\\Windows Wireless 802.11.pdb"
        $PDB2 = "e:\\Windows Work\\G2\\"
            $PDB3 = "\\G2\\G2 Main Virus\\Microsoft Virus Solutions (G2"
    condition:
        any of them
}

rule GravityRAT_G3_PDB
{
    meta:
        id = "33zcZFArDjExOrAKENCZOd"
        fingerprint = "v1_sha256_9bdc8c6796bdbd5600aa99d9320176d53e6002ecc021a1225e413e71797fc4df"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Michael Worth"
        description = "PDB path for Gravity RAT G3"
        category = "INFO"
        reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"

    strings:
        $PDB1 = "F:\\Projects\\g3\\G3 Version 4.0\\G3\\G3\\obj\\Release\\Intel Core.pdb"
        $PDB2 = "F:\\Projects\\g3\\G3 Version "
               $PDB3 = "\\G3\\G3\\obj\\Release\\"
    condition:
        any of them
}

rule GravityRAT_GX_PDB
{
    meta:
        id = "3vdYj9Ity5jGRWf3GNiY4H"
        fingerprint = "v1_sha256_cc7f074ad8c5753b9e4cfb2a19830b3ad52252fbffa59e1697c0b4f2fa267e33"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Michael Worth"
        description = "PDB path for Gravity RAT GX"
        category = "INFO"
        reference = "https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html"

    strings:
        $PDB1 = "C:\\Users\\The Invincible\\Desktop\\gx\\gx-current-program\\LSASS\\obj\\Release\\LSASS.pdb"
        $PDB2 = "C:\\Users\\The Invincible\\D"
               $PDB3 = "Desktop\\gx\\gx-"
    condition:
        any of them
}



