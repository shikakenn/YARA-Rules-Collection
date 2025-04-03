rule Check_Qemu_DeviceMap
{
    meta:
        id = "45AM0kbtew3imCe8V63XGF"
        fingerprint = "v1_sha256_c37a34eec7bb8be8cc7643bed67508af4265dd479f8f46eb555fb0ed72b3fef4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for Qemu reg keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}
