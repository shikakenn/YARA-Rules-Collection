rule Check_VBox_Guest_Additions
{
    meta:
        id = "6cu77TZWVnh05lOTO3xzdt"
        fingerprint = "v1_sha256_746d18bf2ca2dcbfb0f1a2033650bc454e9e7e426228273d51ac0ec508d50703"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of the guest additions registry key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
    condition:
        any of them	
}
