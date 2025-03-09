rule HeartBleedWin32
{
    meta:
        id = "6kdCiraVXORwV2E13kocuo"
        fingerprint = "v1_sha256_7b017ba0d15f98801480e7ae0323fc9bff8d783603ee3ac19584d3e9e7016c0a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "NCCGROUP"
        description = "rule to detect heartbleed"
        category = "INFO"
        reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2014/june/writing-robust-yara-detection-rules-for-heartbleed/"

 strings:
  $opensslmini = {E8 ?? ?? ?? ?? 8B 4C 24 24 8B E8 8D 7D 01 8B C3 C6 45 00 02 C1 E8 08 53 88 07 88 5F 01 51 83 C7 02 57 E8 ?? ?? ?? ??}
  $heartbleedpatch = {83 F9 13 73 ?? 5F 33 C0 5E 59 C3 0F ?? ?? ?? 0F ?? ??}
 condition:
  $opensslmini and not $heartbleedpatch
}
