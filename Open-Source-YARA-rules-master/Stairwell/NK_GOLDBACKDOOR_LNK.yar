rule NK_GOLDBACKDOOR_LNK
{
    meta:
        id = "3naEegEmCO7dJTSCIVEkeL"
        fingerprint = "v1_sha256_ae37c949658c201b99f11259bec3d4507e4d665133d55721f9e9b05bb06b26f8"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (silas@Stairwell.com)"
        description = "Detection for LNK file used to deploy GOLDBACKDOOR"
        category = "INFO"
        reference = "https://stairwell.com/news/threat-research-the-ink-stained-trail-of-goldbackdoor/"

strings:
$ = "WINWORD.exe" wide nocase
$ = "$won11 =\"$temple=" wide
$ = "dirPath -Match 'System32' -or $dirPath -Match 'Program Files'" wide
condition:
2 of them and uint16(0) == 0x4c
}
