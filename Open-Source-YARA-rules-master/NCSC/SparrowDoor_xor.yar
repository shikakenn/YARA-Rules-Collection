rule SparrowDoor_xor {
    meta:
        id = "X47bJp8799VrtsQTZq2Za"
        fingerprint = "v1_sha256_3244e9017e5a0bf1c54e03b3191a5c695b2c1586b3ed4c529742f9b48903a348"
        version = "1.0"
        date = "2022-02-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCSC"
        description = "Highlights XOR routines in SparrowDoor. No MZ/PE match as the backdoor has no header. Targeting in memory."
        category = "INFO"
        reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

strings:
$xor_routine_outbound = {B8 39 8E E3 38 F7 E1 D1 EA 8D 14 D2 8B C1 2B C2 8A [4] 00 30 14 39 41 3B CE}
$xor_routine_inbound = {B8 25 49 92 24 F7 E1 8B C1 2B C2 D1 E8 03 C2 C1 E8 02 8D 14 C5 [4] 2B D0 8B C1 2B C2}
$xor_routine_config = {8B D9 83 E3 07 0F [6] 30 18 8D 1C 07 83 E3 07 0F [6] 30 58 01 8D 1C 28 83 E3 07 0F [6] 30 58 02 8D 1C 02 83 E3 07 0F [6] 30 58 03 8B DE 83 E3 07 0F [6] 30 58 04 83 C6 05 83 C1 05}
condition:
2 of them
}
