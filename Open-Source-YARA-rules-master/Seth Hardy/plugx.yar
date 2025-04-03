private rule PlugXBootLDRCode : PlugX Family 
{
    meta:
        id = "YMCAhpbHnpDb0AKkHgQO9"
        fingerprint = "v1_sha256_75624472e2f2f0430f131deed34ac8ef34ca6db7343e1688c2a2170319734ef0"
        version = "1.0"
        modified = "2014-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PlugX boot.ldr code tricks"
        category = "INFO"

    strings:
        //$callpop = { E8 00 00 00 00 58 }
        // Compares [eax+n] to GetProcAdd, one character at a time. This goes up to GetP:
        $GetProcAdd = { 80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2A 80 78 03 50 }
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_LoadLibraryA = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 6F 61 64 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 69 62 72 }
        $L4_VirtualAlloc = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 41 }
        $L4_VirtualFree = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 46 }
        $L4_ExitThread = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 45 78 69 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 54 68 72 65 }
        $L4_ntdll = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6E 74 64 6C 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) C6 00 }
        $L4_RtlDecompressBuffer = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 52 74 6C 44 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 65 63 6F 6D }
        $L4_memcpy = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6D 65 6D 63 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 70 79 }
        
    condition:
        /*($callpop at 0) or*/ $GetProcAdd or (all of ($L4_*))
}

private rule PlugXStrings : PlugX Family
{
    meta:
        id = "qlbJFWcO3vNXTQRJbkvUm"
        fingerprint = "v1_sha256_ac2c311f9898636204471dfea1e5396829875c2d9e041303fa1cabc2974b838b"
        version = "1.0"
        modified = "2014-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PlugX Identifying Strings"
        category = "INFO"

    strings:
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
      
    condition:
        $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

rule PlugX : Family
{
    meta:
        id = "1aR9Hdjz5KmxARdnO4bfBE"
        fingerprint = "v1_sha256_aa44a5402383abc2927d7e8571baabf545e3c16ed256864e53dfc3ff29f496b5"
        version = "1.0"
        modified = "2014-06-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "PlugX"
        category = "INFO"

    condition:
        PlugXBootLDRCode or PlugXStrings
}
