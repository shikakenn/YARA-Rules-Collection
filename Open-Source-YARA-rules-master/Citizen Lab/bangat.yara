private rule BangatCode : Bangat Family 
{
    meta:
        id = "7kOJ3XQkMdae6ylz17Ydj"
        fingerprint = "v1_sha256_20c81d7fe5aec45e816a0d9e643c29bf359d254748013a96868683772b7b01df"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Bangat code features"
        category = "INFO"

    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $ = { FE 4D ?? 8D 4? ?? 50 5? FF }
    
    condition:
        any of them
}

private rule BangatStrings : Bangat Family
{
    meta:
        id = "69LfqBw5kcM2YtafwTWiY6"
        fingerprint = "v1_sha256_6e5e8218bbd4150a03bff4e1e89dd19a0d877bd9fd6c8148eec3fdf56b735d1e"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Bangat Identifying Strings"
        category = "INFO"

    strings:
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc
}

rule Bangat : Family
{
    meta:
        id = "4DTFAzV5OUWj7BQIDyhwwP"
        fingerprint = "v1_sha256_0f70c88d73ad4aa7bcaf443e28b30e56f979b6355d1d3d96340b883c769f9854"
        version = "1.0"
        modified = "2014-07-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Bangat"
        category = "INFO"

    condition:
        BangatCode or BangatStrings
}
