rule NK_GOLDBACKDOOR_LNK_payload
{
    meta:
        id = "3Pn53Ro0SN7DgtbYGi5NR1"
        fingerprint = "v1_sha256_8e1862409de8983e94be918145221da01fa4d32ca2b6bab5d4f2a0937e328d01"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for obfuscated Powershell contained in LNK file that deploys GOLDBACKDOOR"
        category = "INFO"
        reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"

strings:
$ = "WriteByte($x0, $h-1, ($xmpw4[$h] -bxor $xmpw4[0]" ascii wide nocase
condition:
all of them
}
