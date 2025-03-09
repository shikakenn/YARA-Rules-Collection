rule Check_Qemu_Description
{
    meta:
        id = "3pGEJjXBbRZ22taZY8YI76"
        fingerprint = "v1_sha256_22da3ad33533cf52e06cc1185f53a4ad4f300e8ac36eed765e409ba4420ff703"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for QEMU systembiosversion key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}
