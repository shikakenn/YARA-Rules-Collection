import "pe"
rule Check_UserNames
{
    meta:
        id = "6vkbroaEXHFcVE3hFP0b1g"
        fingerprint = "v1_sha256_8c1c311f0fdb11769582e339339d0dc9328e62a68e47e4f2b81bdf843551463a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Looks for malware checking for common sandbox usernames"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $user1 = "MALTEST" wide ascii
        $user2 = "TEQUILABOOMBOOM" wide ascii
        $user3 = "SANDBOX" wide ascii
        $user4 = "VIRUS" wide ascii
        $user5 = "MALWARE" wide ascii
    condition:
        all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}
