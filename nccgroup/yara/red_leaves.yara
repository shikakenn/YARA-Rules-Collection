import "pe"

rule malware_red_leaves_generic {
    meta:
        id = "zG6tZqtt6ljZb8Ko4L0gL"
        fingerprint = "v1_sha256_0b048be853fc19b226e5542a67aec3a2562c28bdee08a26e5853caf699d915a7"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Red Leaves malware, related to APT10"
        category = "INFO"
        sha256 = "2e1f902de32b999642bb09e995082c37a024f320c683848edadaf2db8e322c3c"

  strings:
    // MiniLZO compile date
    $ = "Feb 04 2015"
    $ = "I can not start %s"
    $ = "dwConnectPort" fullword
    $ = "dwRemoteLanPort" fullword
    $ = "strRemoteLanAddress" fullword
    $ = "strLocalConnectIp" fullword
    $ = "\\\\.\\pipe\\NamePipe_MoreWindows" wide
    $ = "RedLeavesCMDSimulatorMutex" wide
    $ = "(NT %d.%d Build %d)" wide
    $ = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)" wide
    
    // Found unencrypted in early samples
    $ = "owlmedia.mefound.com" wide ascii
    
    $ = "red_autumnal_leaves_dllmain.dll" wide ascii
    $ = "__data" wide
    $ = "__serial" wide
    $ = "__upt" wide
    $ = "__msgid" wide
    
  condition:
    7 of them
}

rule malware_red_leaves_opcodes {
    meta:
        id = "4yoBKsUlNDKcpfTkov6z5X"
        fingerprint = "v1_sha256_f2e3c87f45b85b2198a7b4a694b6253fa5a7e9240c2cde4bcd9c9036bc6a2a9d"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Opcode sequences from the Red Leaves malware, related to APT10"
        category = "INFO"

  strings:
    /*
      33 45 14          xor     eax, [ebp+arg_C]
      81 F1 AE CB D9 BF xor     ecx, 0BFD9CBAEh
    */
    // This magic value used for XOR repeatedly
    $opcode_magic_value = { 33 45 14 81 F1 AE CB D9 BF }
    
    /*
      56                      push    esi
      33 F6                   xor     esi, esi
      33 C0                   xor     eax, eax
      80 B0 68 94 03 10 53    xor     byte_10039468[eax], 53h
      40                      inc     eax
      3D 40 09 00 00          cmp     eax, 940h
      72 F1                   jb      short loc_100119B0
    */
    // Configuration decode using XOR, from newer sample (internal date 2017-2-22)
    $opcodes_xor_config = { 56 33 F6 33 C0 80 B0 ?? ?? ?? ?? ?? 40 3D ?? ?? 00 00 72 F1 }
    
    /*
      8B 85 BC FE FF FF mov     eax, [ebp+lpEmbeddedPE]
      03 85 B0 FE FF FF add     eax, [ebp+dwOffset]

                        loc_6D:
      0F B6 48 01       movzx   ecx, byte ptr [eax+1]

                        loc_71:
      81 F9 AF 00 00 00 cmp     ecx, 0AFh
      75 52             jnz     short loc_CB
    */
    // Part of shellcode egghunt, looking for signature AFBFAFBF
    $opcodes_egghunt = { FF FF 0F B6 48 01 81 F9 AF 00 00 00 75 52 }

    /*
      .text:10001143 33 C9                             xor     ecx, ecx
      .text:10001145
      .text:10001145                   loc_10001145:                           ; CODE XREF: cef_string_utf16_set+141
      .text:10001145 32 04 39                          xor     al, [ecx+edi]
      .text:10001148 83 C1 02                          add     ecx, 2
      .text:1000114B 88 04 32                          mov     [edx+esi], al
      .text:1000114E 83 F9 0A                          cmp     ecx, 0Ah
      .text:10001151 7C F2                             jl      short loc_10001145
    */
    // Part of XOR decode loop from hijacked AOL Instant Messenger DLL (libcef.dll)
    $opcodes_hijacked_aim_dll = { 33 C9 32 04 39 83 C1 02 88 04 32 83 F9 0A } 

  condition:
    any of them
}

rule malware_red_leaves_loader_libcef {
    meta:
        id = "3vwYgZN0iVEPJjgGdkY9oG"
        fingerprint = "v1_sha256_e4fab4d4041b3143bd957529f192525c03e73cf205d87fd013d18a7bf710de50"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Possible APT10 loader using libcef.dll (Chromium Embedded Framework)"
        category = "INFO"
        sha256 = "02e702af02a6b9a8b31cd470c18e383093ef4ed404811b414d6d131df01f9acd"

  condition:
    // The legitimate libcef.dll is >10MiB
    //
    // Avoid a Tencent signed DLL which FPs
    //
    pe.exports("cef_string_utf16_set") and filesize < 200KB and not
    for any i in (0..pe.number_of_signatures - 1):
    (
      pe.signatures[i].subject contains "O=Tencent Technology(Shenzhen) Company Limited"
    )
}

rule malware_red_leaves_loader_starburn_generic {
    meta:
        id = "2mF7ntbPoUja4qJeZp8U00"
        fingerprint = "v1_sha256_f0afba3a9e899c9416ecc08e2f342623b33fb3a8886000b856bef6318402c3ae"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Possible APT10 loader using starburn.dll (function GetVersion modified)"
        category = "INFO"
        sha256 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

  strings:
    /*
      loc_10001DD0:
      32 0C 3A          xor     cl, [edx+edi]
      83 C2 02          add     edx, 2
      88 0E             mov     [esi], cl
      83 FA 08          cmp     edx, 8
      7C F3             jl      short loc_10001DD0
    */
    $xor_loop = { 32 0C 3A 83 C2 02 88 0E 83 FA ?? 7C F3 }

    $dat_file = "handkerchief.dat" fullword
    $lnk_file = "persuasion.lnk" fullword
    $unknown = "pedetdata" fullword

  condition:
    $xor_loop or (2 of them)
}

rule malware_red_leaves_loader_starburn {
    meta:
        id = "3zJPNCNaK07XovNccAm65I"
        fingerprint = "v1_sha256_c8b1e71dd4578acec7d401c38763021c3c8c0e88906965ed2e7beb7e0b594547"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "Possible APT10 loader using starburn.dll (function GetVersion modified)"
        category = "INFO"
        sha256 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

  condition:
    pe.exports("StarBurn_GetVersion") and filesize < 200KB
}

rule malware_red_leaves_memory {
    meta:
        id = "5MpYM05eNqPA6mM8ADowHJ"
        fingerprint = "v1_sha256_f102785e8a380f46ca6b50973490239c0d028281b5dab624ff85d6af789ecc2a"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "David Cannings"
        description = "C&C artefacts left in memory by the Red Leaves malware (use with Volatility / Rekall)"
        category = "INFO"

  strings:
    $ = "__msgid=" wide ascii
    $ = "__serial=" wide ascii
    $ = "OnlineTime=" wide

    // Indicates a file transfer
    $ = "clientpath=" wide ascii 
    $ = "serverpath=" wide ascii

  condition:
    3 of them
}
