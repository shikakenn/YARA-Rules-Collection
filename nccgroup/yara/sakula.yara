rule malware_sakula_xorloop {
    meta:
        id = "5YvuTWboxdpSkJ94qMGwXG"
        fingerprint = "v1_sha256_c1012b97eedc57e53e304e84d61f69fc8c02cf4297c44a2616ee0c07f2f4d6cf"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "XOR loops from Sakula malware"
        category = "INFO"
        md5 = "fc6497fe708dbda9355139721b6181e7"

  strings:
    $mz = "MZ"
    
    // XOR decode loop (non-null, non-key byte only)
    $opcodes_decode_loop01 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
    
    // XOR decode
    $opcodes_decode_loop02 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }

  condition:
    $mz at 0 and any of ($opcodes*)
}

rule malware_sakula_memory {
    meta:
        id = "6q7cVN8d31OHNXTHtX04bH"
        fingerprint = "v1_sha256_ba6d93a1fc5fd81748eb462fc55b681987126ba853ddb677a5f1f9b74ba5cde8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Sakula malware - strings after unpacking (memory rule)"
        category = "INFO"
        md5 = "b3852b9e7f2b8954be447121bb6b65c3"

  strings:
    $str01 = "cmd.exe /c ping 127.0.0.1 & del \"%s\""
    $str02 = "cmd.exe /c rundll32 \"%s\" Play \"%s\""
    $str03 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1)"
    $str04 = "cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c cmd.exe /c \"%s\""
    $str05 = "Self Process Id:%d"
    $str06 = "%d_%d_%d_%s"
    $str07 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)"
    $str08 = "cmd.exe /c rundll32 \"%s\" ActiveQvaw \"%s\""
    
    // Encode loop, operations: rol 1; xor ??;
    $opcodes01 = { 83 F9 00 74 0E 31 C0 8A 03 D0 C0 34 ?? 88 03 49 43 EB ED }
    
    // Encode loop, single byte XOR
    $opcodes02 = { 31 C0 8A 04 13 32 01 83 F8 00 75 0E 83 FA 00 74 04 49 4A }

  condition:
    4 of them
}

rule malware_sakula_shellcode {
    meta:
        id = "5YEEHPzA96brjGdeRm8EXE"
        fingerprint = "v1_sha256_0e84d91cd1bb0455ac7d2ca78583510388f39cebd95523c5f6f173a50e0c1951"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Sakula shellcode - taken from decoded setup.msi but may not be unique enough to identify Sakula"
        category = "INFO"

  strings:
    /*
      55                      push    ebp
      89 E5                   mov     ebp, esp
      E8 00 00 00 00          call    $+5
      58                      pop     eax
      83 C0 06                add     eax, 6
      C9                      leave
      C3                      retn
    */
    // Get EIP technique (may not be unique enough to identify Sakula)
    // Note this only appears in memory or decoded files
    $opcodes01 = { 55 89 E5 E8 00 00 00 00 58 83 C0 06 C9 C3 }    
    
    /*
      8B 5E 3C                mov     ebx, [esi+3Ch]  ; Offset to PE header
      8B 5C 1E 78             mov     ebx, [esi+ebx+78h] ; Length of headers
      8B 4C 1E 20             mov     ecx, [esi+ebx+20h] ; Number of data directories
      53                      push    ebx
      8B 5C 1E 24             mov     ebx, [esi+ebx+24h] ; Export table
      01 F3                   add     ebx, esi
    */
    // Export parser
    $opcodes02 = { 8B 5E 3C 8B 5C 1E 78 8B 4C 1E 20 53 8B 5C 1E 24 01 F3 }
    
  condition:
    any of them
}


rule malware_sakula_loader {
    meta:
        id = "Qz8oaDnhJUjan8753PdSo"
        fingerprint = "v1_sha256_d84566089a2efd1640d41c819fd7be7b542c1cf226d8b2b31987dcd38f5646e8"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "A small DLL loader (~6KiB) for Sakula malware"
        category = "INFO"
        md5 = "58d56d6e2cafca33e5a9303a36228ef6"

  strings:
    /*
      59                      pop     ecx
      5B                      pop     ebx
      6A 69                   push    'i'
      68 70 2E 6D 73          push    'sm.p'
      68 73 65 74 75          push    'utes'
      54                      push    esp             ; Source
      FF 35 04 20 00 10       push    ds:lpFileName   ; Dest
      E8 29 1F 00 00          call    strcat
    */
    // String stacking for 'setup.msi'
    $opcodes_string_stack01 = { 6A 69 68 70 2E 6D 73 68 73 65 74 75 }
    
    /*
      48                      dec     eax
      83 F8 00                cmp     eax, 0
      0F 84 B2 00 00 00       jz      loc_10001171
      8A 18                   mov     bl, [eax]
      80 F3 5C                xor     bl, 5Ch
      80 FB 00                cmp     bl, 0
    */
    $opcodes_decode_loop = { 48 83 F8 00 0F ?? ?? ?? ?? ?? 8A 18 80 F3 ?? 80 FB 00 }
    
    // Generic toolmarks from the compiler
    $str01 = "Win32 Program!"
    $str02 = "GoLink, GoAsm www.GoDevTool.com"
    
  condition:
    1 of ($opcodes*) and 1 of ($str*)
}

