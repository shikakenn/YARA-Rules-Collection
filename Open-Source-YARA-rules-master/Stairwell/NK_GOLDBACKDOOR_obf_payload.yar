rule NK_GOLDBACKDOOR_obf_payload
{
    meta:
        id = "6Wy5Ilq3toeFonTmHtwRHx"
        fingerprint = "v1_sha256_5b403ca6f6db2301afa61ae12ff7bf20d0283c18e6543a84e5d26d16e0fae6e8"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for encoded shellcode payload downloaded by LNK file that drops GOLDBACKDOOR"
        category = "INFO"
        reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"

strings:
$init = { e6b3 6d0a 6502 1e67 0aee e7e6 e66b eac2 }
condition:
$init at 0
}
