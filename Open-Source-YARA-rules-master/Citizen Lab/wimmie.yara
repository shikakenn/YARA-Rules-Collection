private rule WimmieShellcode : Wimmie Family 
{
    meta:
        id = "1HyPD9zgfjFe58EKLCLxsB"
        fingerprint = "v1_sha256_662ca865b484b8aa1bfbef5332630db7198cf752e1a73c813166b32b5f39e5ab"
        version = "1.0"
        modified = "2014-07-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Wimmie code features"
        category = "INFO"

    strings:
        // decryption loop
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        
    condition:
        any of them
}

private rule WimmieStrings : Wimmie Family
{
    meta:
        id = "6VOiSMFBYRsD3vYbYlJsJk"
        fingerprint = "v1_sha256_c84086c7e58cd6f571f831b7942bfae7eb70a5bd07de939fa6fe6a4510308628"
        version = "1.0"
        modified = "2014-07-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Strings used by Wimmie"
        category = "INFO"

    strings:
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them

}

rule Wimmie : Family
{
    meta:
        id = "2lhG5QsBGcVmXtFSf4rkkZ"
        fingerprint = "v1_sha256_9df3ec37cbfe90c86a8d7b70d95e099988be220c3d3c8424df16a217803db4ff"
        version = "1.0"
        modified = "2014-07-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Wimmie family"
        category = "INFO"

    condition:
        WimmieShellcode or WimmieStrings
        
}
