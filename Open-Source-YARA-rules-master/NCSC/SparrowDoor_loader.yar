rule SparrowDoor_loader {
    meta:
        id = "6I7GYVOx7HyKecuXL8WPv"
        fingerprint = "v1_sha256_fa1bd386114d912722a5101a0112355dec654e2e9446c885c12946c7fae1c8f4"
        version = "1.0"
        date = "2022-02-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCSC"
        description = "Targets code features of the SparrowDoor loader. This rule detects the previous variant and this new variant."
        category = "INFO"
        reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
        hash1 = "989b3798841d06e286eb083132242749c80fdd4d"

strings:
$xor_algo = {8B D0 83 E2 03 8A 54 14 10 30 14 30 40 3B C1}
$rva = {8D B0 [4] 8D 44 24 ?? 50 6A 40 6A 05 56} // load RVA of process exe
$lj = {2B CE 83 E9 05 8D [3] 52 C6 06 E9 89 4E 01 8B [3] 50 6A 05 56} // calculate long jump
condition:
(uint16(0) == 0x5A4D) and uint32(uint32(0x3C)) == 0x00004550 and
all of them
}
