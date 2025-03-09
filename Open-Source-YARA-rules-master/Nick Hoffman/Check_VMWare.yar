rule Check_VMWare_DeviceMap
{
    meta:
        id = "22qnJkOVkok9S3JGBWMvlr"
        fingerprint = "v1_sha256_dbcc2d5bba61af66cd62f028c6d57b7eab2a14127327d5c38926b4ca07dc75cc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmWare Registry Keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
        $value = "Identifier" wide nocase ascii
        $data = "VMware" wide nocase ascii
    condition:
        all of them
}
