/*
from https://www.cert.pl/en/news/single/analysis-of-emotet-v4/
*/

rule emotet4_basic: trojan
{
    meta:
        id = "2n3LiSX2Oq7lEYwJBBPf9I"
        fingerprint = "v1_sha256_ed8eb9b617e502d7ee961c29eafa4d8e00c60fb47e33228106968add99d942fe"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "psrok1/mak"
        description = "NA"
        category = "INFO"
        module = "emotet"

strings:
$emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
$emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
condition:
all of them
}

rule emotet4: trojan
{
    meta:
        id = "3pxgBXpnfNOqTOFOXIgP5e"
        fingerprint = "v1_sha256_e5b38c23eb2e659a24dd0660c4f4c0f48e74166937eda54e3db4a727130a0b9f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "psrok1"
        description = "NA"
        category = "INFO"
        module = "emotet"

strings:
$emotet4_x65599 = { 0f b6 ?? 8d ?? ?? 69 ?? 3f 00 01 00 4? 0? ?? 3? ?? 72 }
condition:
any of them and emotet4_basic
}

rule emotet4_spam : spambot
{
    meta:
        id = "7840tmYCKRfpz2qNMT2wFO"
        fingerprint = "v1_sha256_2847e3d3c2861c49177ad238c649aba506162ae5ab1c8ab3935ca21524ee3d7d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mak"
        description = "NA"
        category = "INFO"
        module = "emotet"

strings:
$login="LOGIN" fullword
$startls="STARTTLS" fullword
$mailfrom="MAIL FROM:"
condition:
all of them and emotet4_basic
}
