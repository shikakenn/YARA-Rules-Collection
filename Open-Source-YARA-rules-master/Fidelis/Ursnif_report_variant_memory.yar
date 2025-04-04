rule Ursnif_report_variant_memory
{
    meta:
        id = "7IAyilZULkG7tGlF7YSmKF"
        fingerprint = "v1_sha256_1673d166c726dd8ec0893912820725a3045a2180c94624163105d87b5d302b2b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fidelis Cybersecurity"
        description = "Ursnif"
        category = "INFO"
        reference = "New Ursnif Variant Targeting Italy and U.S - June 7, 2016"

strings:
     $isfb1 = "/data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s"
     $isfb2 = "client.dll"
     $ursnif1 = "soft=1&version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&crc=%x"
     $a1 = "grabs="
     $a2 = "HIDDEN"
     $ursnif2 = "/images/"
     $randvar = "%s=%s&"
     $specialchar = "%c%02X" nocase
     $serpent_setkey = {8b 70 ec 33 70 f8 33 70 08 33 30 33 f1 81 f6 b9 79 37 9e c1 c6 0b 89 70 08 41 81 f9 84 [0-3] 72 db}
condition:
    7 of them
}
