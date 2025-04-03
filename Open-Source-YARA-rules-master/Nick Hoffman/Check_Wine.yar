import "pe"
rule Check_Wine
{
    meta:
        id = "49nVOXVVX98SDNmGIybe2x"
        fingerprint = "v1_sha256_46756d3e028b086becb8ae50476427c80bb66634ac66eb9f6b89b15f75d95e52"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of Wine"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $wine = "wine_get_unix_file_name"
    condition:
        $wine and pe.imports("kernel32.dll","GetModuleHandleA")
}
