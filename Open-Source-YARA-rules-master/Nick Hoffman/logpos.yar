rule LogPOS
{
    meta:
        id = "2ORzPEndpRt5PgdXfDx47I"
        fingerprint = "v1_sha256_828346389b6507288a173e35c692bc87d005c69d6f3f2ad4c6eda76cd5b6e113"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Nick Hoffman - Morphick Security"
        description = "Detects Versions of LogPOS"
        category = "INFO"
        md5 = "af13e7583ed1b27c4ae219e344a37e2b"

    strings:
        $mailslot = "\\\\.\\mailslot\\LogCC"
        $get = "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
        //64A130000000      mov eax, dword ptr fs:[0x30]
        //8B400C        mov eax, dword ptr [eax + 0xc]
        //8B401C        mov eax, dword ptr [eax + 0x1c]
        //8B4008        mov eax, dword ptr [eax + 8]
        $sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }
    condition:
        $sc and 1 of ($mailslot,$get)
}
