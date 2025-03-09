rule Embedded_PE
{
    meta:
        id = "hpCAGZmzamYp9qcrnZxaz"
        fingerprint = "v1_sha256_fac80234f39e40f71f98318ac50cc92428adf68de7c7e328b90f9144ea49e49a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "InQuest Labs"
        URL = "https://github.com/InQuest/yara-rules"
        Description = "Discover embedded PE files, without relying on easily stripped/modified header strings."

    strings:
        $mz = { 4D 5A }
    condition:
        for any i in (1..#mz):
        (
            uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
        )
}
