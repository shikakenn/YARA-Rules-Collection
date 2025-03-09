import "pe"
rule Check_DriveSize
{
    meta:
        id = "7cYHlM0M6D4R8vdr1ihJKv"
        fingerprint = "v1_sha256_6e651a96ad1301eef365deb7eaa9ea1d6867c4ff3a458b110cb83e66e6ddcab0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
        $dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO	
    condition:
        pe.imports("kernel32.dll","CreateFileA") and 	
        pe.imports("kernel32.dll","DeviceIoControl") and 
        $dwIoControlCode and
        $physicaldrive
}
