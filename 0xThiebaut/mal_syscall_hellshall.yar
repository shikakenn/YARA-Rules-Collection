rule mal_syscall_hellshall: RELEASED MALWARE OBFUSCATOR TA0002 T1106 {
    meta:
        id = "okKC4Zt2kjWBvbcVqTf6F"
        fingerprint = "v1_sha256_2adc3a82101a9f6cca33a76240705bfdbd87393cccb8f2611a4dad35bb1f9f58"
        version = "1.0"
        date = "2023-04-11"
        modified = "2023-04-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects suspicious syscall extraction and indirect syscall used in HellsHall"
        category = "MALWARE"
        malware = "OBFUSCATOR"
        mitre_att = "T1106"
        reference = "https://github.com/Maldev-Academy/HellHall"
        hash = "b3dc5d08346a76c235ce29f0b4557abb0ef049c3cd7b676a615196a74dfbc5f9"
        first_imported = "2023-04-11"

    strings:
        $convert = {
            80 ?? 4c    // cmp     byte ptr [??], 4Ch
            75 ??       // jnz     ??
            80 ?? 01 8b // cmp     byte ptr [??+1], 8Bh
            75 ??       // jnz     ??
            80 ?? 02 d1 // cmp     byte ptr [??+2], 0D1h
            75 ??       // jnz     ??
            80 ?? 03 b8 // cmp     byte ptr [??+3], 0B8h
            75 ??       // jnz     ??
            80 ?? 08 f6 // cmp     byte ptr [??+8], 0F6h
            75 ??       // jnz     ??
            80 ?? 09 04 // cmp     byte ptr [??+9], 4
            75 ??       // jnz     ??
            80 ?? 0a 25 // cmp     byte ptr [??+0Ah], 25h
            74          // jz      ??
        }
        $syscall = {
            49 89 ca    // mov     r10, rcx
            8b 44 24 ?? // mov     eax, [rsp+dwNumber]
            ff 64 24 ?? // jmp     [rsp+pSyscall]
        }
    condition:
        any of them
}
