rule Check_VmTools
{
    meta:
        id = "12Be9zTksg2T4SbUZ18yf"
        fingerprint = "v1_sha256_6c9797cac979a3090d164dfd43c91937aa0c6b0548b06ba3d99f6e27f431959b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmTools reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $tools = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
    condition:
        $tools
}
