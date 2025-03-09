rule Check_VBox_Description
{
    meta:
        id = "7cnsidzJZCGH4YsubyKWRD"
        fingerprint = "v1_sha256_0d50c013eb8c33e090037d2d33c55c76964738ff2609cafcecddbcbc6a03f7f1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks Vbox description reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "VBOX" nocase wide ascii		
    condition:
        all of them
}
