rule Themida
{
    meta:
        id = "p3mYwGu7cbr2tx5qXGAfo"
        fingerprint = "v1_sha256_c4f1e01a3fe3cb66062ce03253bfe9edc09dc6f1a77db99b281106e8ceff9257"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Themida Packer"
        category = "INFO"
        packed = "6337ff4cf413f56cc6c9a8e67f24b8d7f94f620eae06ac9f0b113b5ba82ea176"

    strings:
        $code = {FC 31 C9 49 89 CA 31 C0 31 DB AC 30 C8 88 E9 88 D5 88 F2 B6 08 66 D1 EB 66 D1 D8 73 09}
    condition:
        uint16(0) == 0x5A4D and all of them
}
