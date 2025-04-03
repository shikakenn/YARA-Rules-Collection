rule NK_GOLDBACKDOOR_injected_shellcode
{
    meta:
        id = "LF5XIVcqednED7r2EFjHj"
        fingerprint = "v1_sha256_b45f408c0f342591e66ef0dfcfc1c09f8558c5e8f4bd7f824b30f00d531c7511"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for injected shellcode that decodes GOLDBACKDOOR"
        category = "INFO"
        reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"

strings:
$dec_routine = { 8A 19 57 8B FA 8B 51 01 83 C1 05 85 D2 74 0E 56 8B C1 8B F2 30 18 40 83 EE 01 75 F8 5E 57 }
$rtlfillmemory_load = {B9 4B 17 CD 5B 55 56 33 ED 55 6A 10 50 E8 86 00 00 00 FF D0}
$ = "StartModule"
$log_file_name = {C7 44 24 3C 25 6C 6F 63 50 8D 44 24 40 C7 44 24 44 61 6C 61 70 50 B9 BD 88 17 75 C7 44 24 4C 70 64 61 74 C7 44 24 50 61 25 5C 6C C7 44 24 54 6F 67 5F 67 C7 44 24 58 6F 6C 64 32 C7 44 24 5C 2E 74 78 74}
$ = { B9 8E 8A DD 8D 8B F0 E8 E9 FB FF FF FF D0 }
condition:
3 of them
}
