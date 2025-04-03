rule Quickbind
{
    meta:
        id = "29fs5Uj571pofiz6vkM0Tj"
        fingerprint = "v1_sha256_43da808e363e203483a4574438f06b85d449ec2409808e4ccf4a7a8ac31288c7"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "enzok"
        description = "Quickbind"
        category = "INFO"
        cape_type = "Quickbind Payload"

    strings:
        $anti_appdirs = {E8 [4] 83 F8 0? 7? ?? E8}
        $anti_procs_ram = {E8 [4] 83 F8 0? 7? ?? E8 [4] 3D (FF 0E | 00 0F | FF 16) 00 00}
        $anti_procs = {4C 89 F1 [0-9] FF D3 83 7C 24 ?? (03 | 07)}
        $anti_ram = {E8 [4] 3D (FF 1F | 00 20 | 00 17 | FF 0E | FF 16 | FF 2F) 00 00}
        $sleep = {B9 64 00 00 00 [0-7] FF}
        $mutex_api = "CreateMutexW"
        $mutex_error = {FF [1-5] 3D B7 00 00 00}
    condition:
        //any of them
        3 of ($anti_*) and all of ($mutex_*) and $sleep
}
