rule dubseven_file_set
{
    meta:
        id = "432TB4G0dyCuWI65arNKBa"
        fingerprint = "v1_sha256_af98ab901ca97a350aa837779d74208a780b1099e113cfa59bee2eb33690918e"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for service files loading UP007"
        category = "INFO"

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
        id = "47OBNv5PC90L3EywkUhYlh"
        fingerprint = "v1_sha256_813ff641a4213cf9d56013768e284e7f622a223c6c4f585c3bbbcf69fc03723c"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for registry keys checked for by the dropper"
        category = "INFO"

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
        id = "75bkGAqWYfhmt4boVtS0dm"
        fingerprint = "v1_sha256_322ddc1210b6bde393970c61113e6efcb87a3529db386323dfd08973e5d2703e"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for related dialog remnants. How rude."
        category = "INFO"

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
        id = "46MtBuX9VnpUhXUAWEz1Bo"
        fingerprint = "v1_sha256_8d3311164104198e02e700c2e9a5293e55d75d63b39c75c4e375b7f35eb5fde4"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Matches on the maindll mutex"
        category = "INFO"

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
        id = "7kmnTbX7NBz1m4Sjgi0RSr"
        fingerprint = "v1_sha256_5b18f4a6c54b456ae697e9639e8c3041fd4f3141d89850c3e1d3d4e220c3cea3"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks / modified by Florian Roth"
        description = "Searches for related dialog remnants."
        category = "INFO"

    strings:
        $slserver = "SLServer" wide fullword

        $fp1 = "Dell Inc." wide fullword
        $fp2 = "ScriptLogic Corporation" wide

        $extra1 = "SLSERVER" wide fullword
        $extra2 = "\\SLServer.pdb" ascii

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        // Reduce false positives
        not 1 of ($fp*) and
        1 of ($extra*) and

        $slserver
}

rule SLServer_mutex
{
    meta:
        id = "cBrechECVhHrOTa5ZLooZ"
        fingerprint = "v1_sha256_9bf3c6c93e77424463e3fb6f9f4d58e80254866462fe1287293b0a357737da20"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for the mutex."
        category = "INFO"

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
        id = "39Zk1inXmk8lbxSqzZWCea"
        fingerprint = "v1_sha256_48a13d27b7dc9a7f3a65752142b2a291e7c3ee93ef67b36aa4202d065e74d80e"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for the C2 server."
        category = "INFO"

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
        id = "3giYHXZpvuUaxiwHcWFn5r"
        fingerprint = "v1_sha256_fbf53678399b0e14eae6f1bb6594b2aa665f76f10388e492bec2f9101a4dd4b1"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for the related campaign code."
        category = "INFO"

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
        id = "4NkGSpuCfx2DcuEawABKWP"
        fingerprint = "v1_sha256_18d3bb236282c506c161949883722da1cb0af6dd87bf5cb3d4a5b3d90f4a7db0"
        version = "1.0"
        score = 75
        date = "2016/04/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Matt Brooks, @cmatthewbrooks"
        description = "Searches for a unique string."
        category = "INFO"

    strings:
        $string = "test-b7fa835a39"

    condition:
        //MZ header
        uint16(0) == 0x5A4D and

        //PE signature
        uint32(uint32(0x3C)) == 0x00004550 and

        $string
}
