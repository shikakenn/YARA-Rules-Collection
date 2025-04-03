rule dubseven_file_set
{
    meta:
        id = "31yEp9InFYwYDLMrrvWYIZ"
        fingerprint = "v1_sha256_af98ab901ca97a350aa837779d74208a780b1099e113cfa59bee2eb33690918e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for service files loading UP007"

    strings:
        $file1 = "\\Microsoft\\Internet Explorer\\conhost.exe"
        $file2 = "\\Microsoft\\Internet Explorer\\dll2.xor"
        $file3 = "\\Microsoft\\Internet Explorer\\HOOK.DLL"
        $file4 = "\\Microsoft\\Internet Explorer\\main.dll"
        $file5 = "\\Microsoft\\Internet Explorer\\nvsvc.exe"
        $file6 = "\\Microsoft\\Internet Explorer\\SBieDll.dll"
        $file7 = "\\Microsoft\\Internet Explorer\\mon"
        $file8 = "\\Microsoft\\Internet Explorer\\runas.exe"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        //Just a few of these as they differ
        3 of ($file*)
}

rule dubseven_dropper_registry_checks
{
    meta:
        id = "1Cs9JdYa77ycOFQrBIZnez"
        fingerprint = "v1_sha256_813ff641a4213cf9d56013768e284e7f622a223c6c4f585c3bbbcf69fc03723c"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for registry keys checked for by the dropper"

    strings:
        $reg1 = "SOFTWARE\\360Safe\\Liveup"
        $reg2 = "Software\\360safe"
        $reg3 = "SOFTWARE\\kingsoft\\Antivirus"
        $reg4 = "SOFTWARE\\Avira\\Avira Destop"
        $reg5 = "SOFTWARE\\rising\\RAV"
        $reg6 = "SOFTWARE\\JiangMin"
        $reg7 = "SOFTWARE\\Micropoint\\Anti-Attack"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        all of ($reg*)
}

rule dubseven_dropper_dialog_remains
{
    meta:
        id = "mRCwVYjnDrQnVk7zPjpvB"
        fingerprint = "v1_sha256_322ddc1210b6bde393970c61113e6efcb87a3529db386323dfd08973e5d2703e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for related dialog remnants. How rude."

    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        any of them
}
        

rule maindll_mutex
{
    meta:
        id = "2xWP5QJEPwgVfVZbaUkYFX"
        fingerprint = "v1_sha256_8d3311164104198e02e700c2e9a5293e55d75d63b39c75c4e375b7f35eb5fde4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Matches on the maindll mutex"

    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}


rule SLServer_dialog_remains
{
    meta:
        id = "6ZYM788FpnSHOoWIgw8XkV"
        fingerprint = "v1_sha256_e414ce460f553d00f52e29f63b19f25b6172df2aebf5e71c31405f53950417c0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for related dialog remnants."

    strings:
        $slserver = "SLServer" wide
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $slserver
}

rule SLServer_mutex
{
    meta:
        id = "24vU4811cLPf6ISUPcoOZn"
        fingerprint = "v1_sha256_9bf3c6c93e77424463e3fb6f9f4d58e80254866462fe1287293b0a357737da20"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for the mutex."

    strings:
        $mutex = "M&GX^DSF&DA@F"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $mutex
}

rule SLServer_command_and_control
{
    meta:
        id = "5JwGJSO5HHspHXj0LVV2m5"
        fingerprint = "v1_sha256_48a13d27b7dc9a7f3a65752142b2a291e7c3ee93ef67b36aa4202d065e74d80e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for the C2 server."

    strings:
        $c2 = "safetyssl.security-centers.com"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $c2
}

rule SLServer_campaign_code
{
    meta:
        id = "7BORft7U5KoM9K9t42D6eS"
        fingerprint = "v1_sha256_fbf53678399b0e14eae6f1bb6594b2aa665f76f10388e492bec2f9101a4dd4b1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for the related campaign code."

    strings:
        $campaign = "wthkdoc0106"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $campaign
}

rule SLServer_unknown_string
{
    meta:
        id = "7VbJoHgFmeswHHMXStgKYS"
        fingerprint = "v1_sha256_18d3bb236282c506c161949883722da1cb0af6dd87bf5cb3d4a5b3d90f4a7db0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "NA"
        category = "INFO"
        desc = "Searches for a unique string."

    strings:
        $string = "test-b7fa835a39"
        
    condition:
        //MZ header
        uint16(0) == 0x5A4D and
        
        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and
        
        $string
}



