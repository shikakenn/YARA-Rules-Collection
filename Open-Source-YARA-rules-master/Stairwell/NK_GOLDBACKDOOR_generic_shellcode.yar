rule NK_GOLDBACKDOOR_generic_shellcode
{
    meta:
        id = "76sjy7mLh13VFTazJjZmUv"
        fingerprint = "v1_sha256_e046a70b1dee020ba73d960a9d91daaccd0b5c262965c8647f608c5c83a28257"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (silas@Stairwell.com)"
        description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
        category = "INFO"
        reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"

strings:
$ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
$ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }
condition:
all of them
}
