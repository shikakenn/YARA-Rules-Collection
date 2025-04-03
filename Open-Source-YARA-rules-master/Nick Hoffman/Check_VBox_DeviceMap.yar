rule Check_VBox_DeviceMap
{
    meta:
        id = "52StOmMOka85A1Rdkt82oz"
        fingerprint = "v1_sha256_0ab9014d640577e09ea7f8ce0bbebd81ec3b40ec2f8bdb84ea1f47c4e4ab9eee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks Vbox registry keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "VBOX" nocase wide ascii
    condition:
        all of them
}
