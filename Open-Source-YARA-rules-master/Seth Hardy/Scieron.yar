rule Scieron
{
    meta:
        id = "5Q5LMLKzOHrv048Ss5TEKp"
        fingerprint = "v1_sha256_472622efdf3fd06323ed4699d78644d8c1d7b1a410e896d4a2fa1713b4afe9d5"
        version = "1.0"
        date = "22.01.15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Symantec Security Response"
        description = "NA"
        category = "INFO"
        ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"

    strings:
        // .text:10002069 66 83 F8 2C                       cmp     ax, ','
        // .text:1000206D 74 0C                             jz      short loc_1000207B
        // .text:1000206F 66 83 F8 3B                       cmp     ax, ';'
        // .text:10002073 74 06                             jz      short loc_1000207B
        // .text:10002075 66 83 F8 7C                       cmp     ax, '|'
        // .text:10002079 75 05                             jnz     short loc_10002080
        $code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}
        
        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases
        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case
        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump
        $code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}
        
        $str1  = "IP_PADDING_DATA" wide ascii
        $str2  = "PORT_NUM" wide ascii
        
    condition:
        all of them
}
