private rule VidgrabCode : Vidgrab Family 
{
    meta:
        id = "1G9PIV4zQg7oT1ZxMyodwg"
        fingerprint = "v1_sha256_7039568810935465f17084b2fcb40726e1368ce5abf6b3e6eacb454f2f0a55bd"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Vidgrab code tricks"
        category = "INFO"

    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        
    condition:
        all of them
}

private rule VidgrabStrings : Vidgrab Family
{
    meta:
        id = "3xTkMNPHLVJ8C1CmlyR5ke"
        fingerprint = "v1_sha256_b0507817660bd8149df70b7f33227549c09832d8c07491d59f0562125cc6b3cd"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Vidgrab Identifying Strings"
        category = "INFO"

    strings:
        $ = "IDI_ICON5" wide ascii
        $ = "starter.exe"
        $ = "wmifw.exe"
        $ = "Software\\rar"
        $ = "tmp092.tmp"
        $ = "temp1.exe"
        
    condition:
       3 of them
}

rule Vidgrab : Family
{
    meta:
        id = "6isbSM1vcDBC5ZbmVRsSFH"
        fingerprint = "v1_sha256_145777fc5df7595a2ae50442646239eef88b7c340c19110a7fbce841a874b309"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Vidgrab"
        category = "INFO"

    condition:
        VidgrabCode or VidgrabStrings
}
