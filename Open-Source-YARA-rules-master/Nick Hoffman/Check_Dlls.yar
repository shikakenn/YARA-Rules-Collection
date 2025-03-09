rule Check_Dlls
{
    meta:
        id = "6raxgnV6JfOPCXbUYlaXOj"
        fingerprint = "v1_sha256_d9acb85559f1a7f38a37df8c6728f8a900246809df045f99f488a4b8d13cb4dc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for common sandbox dlls"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $dll1 = "sbiedll.dll" wide nocase ascii fullword
        $dll2 = "dbghelp.dll" wide nocase ascii fullword
        $dll3 = "api_log.dll" wide nocase ascii fullword
        $dll4 = "dir_watch.dll" wide nocase ascii fullword
        $dll5 = "pstorec.dll" wide nocase ascii fullword
        $dll6 = "vmcheck.dll" wide nocase ascii fullword
        $dll7 = "wpespy.dll" wide nocase ascii fullword
    condition:
        2 of them
}
