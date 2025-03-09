rule SparrowDoor_sleep_routine {
    meta:
        id = "3M1HmvyfgetCn8Xs8tm00X"
        fingerprint = "v1_sha256_8ae231cb43440e1771d9f7ecaccfedae33f4d14e5ebabd94a909e05bd9fe1bc1"
        version = "1.0"
        date = "2022-02-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCSC"
        description = "SparrowDoor implements a Sleep routine with value seeded on GetTickCount. This signature detects the previous and this variant of SparrowDoor. No MZ/PE match as the backdoor has no header."
        category = "INFO"
        reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

strings:
$sleep = {FF D7 33 D2 B9 [4] F7 F1 81 C2 [4] 8B C2 C1 E0 04 2B C2 03 C0 03 C0 03 C0 50}
condition:
all of them
}
