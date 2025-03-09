rule SparrowDoor_config {
    meta:
        id = "6KTApQSiCXd1T5AdYZ8gwf"
        fingerprint = "v1_sha256_bd52496b6e7cabc875a277ce7d49f6b891c3f61591edef295dbee43716c15509"
        version = "1.0"
        date = "2022-02-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCSC"
        description = "Targets the XOR encoded loader config and shellcode in the file libhost.dll using the known position of the XOR key."
        category = "INFO"
        reference = "https://www.ncsc.gov.uk/files/NCSC-MAR-SparrowDoor.pdf"
        hash1 = "c1890a6447c991880467b86a013dbeaa66cc615f"

condition:
(uint16(0) != 0x5A4D) and
(uint16(0) != 0x8b55) and
(uint32(0) ^ uint32(0x4c) == 0x00) and
(uint32(0) ^ uint32(0x34) == 0x00) and
(uint16(0) ^ uint16(0x50) == 0x8b55)
}
