rule swrort : rat
{
    meta:
        id = "6UsW25FFleTChV7XDm14mE"
        fingerprint = "v1_sha256_dae0847b2dfeec288ee157b09db924756b686afe2a3b629105c5708874e67255"
        version = "1.0"
        date = "2013-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Trojan:Win32/Swrort / Downloader"
        category = "INFO"
        filetype = "memory"

    strings:
        $path = "c:\\code\\httppump\\inner\\objchk_wxp_x86\\i386\\i.pdb"

    condition:
        all of them
}
