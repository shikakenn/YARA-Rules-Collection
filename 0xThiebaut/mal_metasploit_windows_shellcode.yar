rule mal_metasploit_shellcode_windows_pingback_reverse_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "5G85R2pF2ch4aUwWEzqu5t"
        fingerprint = "v1_sha256_1d6d32baaf81fff131511ee3da88d4b56935c4ca7c7b7ef55fe25a8b6b43e071"
        version = "1.0"
        date = "2021-09-02"
        modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/pingback_reverse_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "6675cdf56a8dbde5b5d745145ad41c7a717000d7dd03ac4baa88c8647733d0ab"
        first_imported = "2023-02-23"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            02 00       // AF_INET
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [05-25]
                            99 a5 74 61 // ws2_32.dll::connect
                            [45-65]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [15-35]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                          }
    condition:
        any of ($import_*) and $imphashes
}

rule mal_metasploit_shellcode_windows_powershell_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "6an4dnzmZYlWYU4nyMMJoM"
        fingerprint = "v1_sha256_ee787aba8a9dd09c001a3209c3f0299ba9815055452a1ce9ce737b8aefb4ea05"
        version = "1.0"
        date = "2021-09-02"
        modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/powershell_bind_tcp and windows/powershell_reverse_tcp payloads"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "e26603ef85151596b0faf5ab7dc82ae655d37ec8aef204b329553cf5bc5b730b"
        hash = "9e017c8a6e0078f06dfb898721f3ef7c49f797bc8e2073ff338407dbb5a92297"
        first_imported = "2023-02-23"

    strings:
        $imphashes      = {
                            31 8b 6f 87 // kernel32.dll::WinExec
                            [01-20]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [01-20]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        all of them
}

rule mal_metasploit_shellcode_windows_shell_bind_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "4uKthQU886pm3rYwVJD705"
        fingerprint = "v1_sha256_aeb84bec347000fa3bf22bf9ab91c68aae6023abe6f3115400607f64e3b9df1b"
        version = "1.0"
        date = "2021-09-02"
        modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/shell_bind_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "826232cee9ccd0ee22c82685d7841e09c4fd17e2101736f43d8c6f1621e2fcb3"
        first_imported = "2023-02-23"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [02-20]
                            02 00       // AF_INET
                            [05-25]
                            c2 db 37 67 // ws2_32.dll::bind
                            [02-10]
                            b7 e9 38 ff // ws2_32.dll::listen
                            [02-10]
                            74 ec 3b e1 // ws2_32.dll::accept
                            [02-20]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [35-55]
                            79 cc 3f 86 // kernel32.dll::CreateProcessA
                            [05-25]
                            08 87 1d 60 // kernel32.dll::WaitForSingleObject
                            [00-10]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [00-10]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        any of ($import_*) and $imphashes
}

rule mal_metasploit_shellcode_windows_shell_hidden_bind_tcp: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "6HQ4oEHcqNUBbmJxwjBpVZ"
        fingerprint = "v1_sha256_3f7c165fd732df358264d370ffeaed06a3c330a1091ac2e0a3ca2feae100b458"
        version = "1.0"
        date = "2021-09-02"
        modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/shell_hidden_bind_tcp payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1095"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "166a5d9715d238d7902dbc505df2b2769fa68db337a2de1405be430513f7a938"
        first_imported = "2023-02-23"

    strings:
        $import_full    = "ws2_32"                  // 64-bit
        $import_part    = {33 32 [03] 77 73 32 5F}  // 32-bit
        $imphashes      = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [10-30]
                            29 80 6b 00 // ws2_32.dll::WSAStartup
                            [10-30]
                            ea 0f df e0 // ws2_32.dll::WSASocketA
                            [02-20]
                            02 00       // AF_INET
                            [05-25]
                            c2 db 37 67 // ws2_32.dll::bind
                            [05-25]
                            f1 a2 77 29 // ws2_32.dll::setsockopt
                            [02-15]
                            b7 e9 38 ff // ws2_32.dll::listen
                            [30-50]
                            94 ac be 33 // ws2_32.dll::WSAAccept
                            [05-25]
                            75 6e 4d 61 // ws2_32.dll::closesocket
                            [40-60]
                            79 cc 3f 86 // kernel32.dll::CreateProcessA
                            [05-25]
                            08 87 1d 60 // kernel32.dll::WaitForSingleObject
                            [02-15]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                            [01-10]
                            a6 95 bd 9d // kernel32.dll::GetVersion
                            [10-30]
                            47 13 72 6f // ntdll.dll::RtlExitUserThread
                          }
    condition:
        any of ($import_*) and $imphashes
}

rule mal_metasploit_encode_xor_x64 : RELEASED MALWARE BACKDOOR TA0005 T1027 T1027_002 {
    meta:
        id = "zGjRO3lps1ui10W9jN19C"
        fingerprint = "v1_sha256_b0620e6a0eb773501541b2b46a4bf5a21b9a6f08e2e7d48ee50b55a4848b9823"
        version = "1.1"
        date = "2023-02-28"
        modified = "2023-02-28"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects XOR-encoded Metasploit shellcode"
        category = "MALWARE"
        malware = "OBFUSCATOR"
        mitre_att = "T1027"
        reference = "https://github.com/rapid7/metasploit-framework/blob/b8178397a9aba19dc7a80ee1346d8685674cc0ff/modules/encoders/x64/xor.rb#L36-L42"
        hash = "37cf2f4a421ff8feb097f62eefcca647bc50acc571f7f620885d10741a2d09a5"
        first_imported = "2023-02-28"

    strings:
        $encryption = {
            48 31 c9                        // xor rcx, rcx
            48 81 e9 ?? ?? ?? ??            // sub ecx, block_count
            48 8d 05 ef ff ff ff            // lea rax, [rel 0x0]
            48 bb ?? ?? ?? ?? ?? ?? ?? ??   // mov rbx, xor_key
            48 31 58 27                     // xor [rax+0x27], rbx
            48 2d f8 ff ff ff               // sub rax, -8
            e2 f4                           // loop 0x1b
        }
    condition:
        // Detect the encryption stub
        $encryption and
        // And validate the XOR'ed section is shellcode
        for any i in (1..#encryption) : (
            uint8(@encryption[i] + 0x27) == 0xfc or                             // cld decrypted (e.g. memory dump)
            uint8(@encryption[i] + 0x13) ^ uint8(@encryption[i] + 0x27) == 0xfc // cld encrypted (i.e. pre-execution)
        )
}

rule mal_metasploit_shellcode_windows_meterpreter_reverse_http_x64: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "4jQXv3cD0UvsQfhgndgWy8"
        fingerprint = "v1_sha256_023a9784c540def8c948d67e85c3f5129e9da21cbd55992eb61a327393cd5c45"
        version = "1.0"
        date = "2023-03-01"
        modified = "2023-03-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/x64/meterpreter/reverse_http payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1071"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "2c4c41f21a5b8681a23b2a500b844dc7c4ad5d3ec6c92c841a23f6068567326a"
        first_imported = "2023-03-01"

    strings:
        $import         = "wininet" fullword
        $imphashes_1    = {
                            4c 77 26 07 // kernel32.dll::LoadLibraryA
                            [15-25]
                            3a 56 79 a7 // wininet.dll::InternetOpenA
                            [40-60]
                            57 89 9f c6 // wininet.dll::InternetConnectA
                          }
        $imphashes_2    = {
                            eb 55 2e 3b // wininet.dll::HttpOpenRequestA
                            [20-30]
                            2d 06 18 7b // wininet.dll::HttpSendRequestA
                            [10-20]
                            44 f0 35 e0 // kernel32.dll::Sleep
                            [25-40]
                            58 a4 53 e5 // kernel32.dll::VirtualAlloc
                            [20-35]
                            12 96 89 e2 // wininet.dll::InternetReadFile
                          }
    condition:
        all of them
}

rule mal_metasploit_shellcode_windows_meterpreter_reverse_http_x86: RELEASED MALWARE BACKDOOR TA0011 T1095 {
    meta:
        id = "70MTcX1QJqCy2yCgyLIa00"
        fingerprint = "v1_sha256_6e4e4c3dcb474653a44a6152c1b3deb201b8240cb98f83dbfadcbce80c1d3d04"
        version = "1.0"
        date = "2023-03-01"
        modified = "2023-03-01"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects Metasploit import-hashes from the windows/meterpreter/reverse_http payload"
        category = "MALWARE"
        malware = "BACKDOOR"
        mitre_att = "T1071"
        reference = "https://blog.nviso.eu/2021/09/02/anatomy-and-disruption-of-metasploit-shellcode/"
        hash = "6675cdf56a8dbde5b5d745145ad41c7a717000d7dd03ac4baa88c8647733d0ab"
        first_imported = "2023-03-01"

    strings:
        $LoadLibraryA   = {
                            6E 65 74 00 // wini(net)
                            [01-03]
                            77 69 6E 69 // (wini)net
                            [01-05]
                            4C 77 26 07 // kernel32.dll::LoadLibraryA
                        }
        $InternetOpenA  = { 3a 56 79 a7 } // wininet.dll::InternetOpenA
        $imphashes      = {
                            57 89 9f c6 // wininet.dll::InternetConnectA
                            [15-25]
                            eb 55 2e 3b // wininet.dll::HttpOpenRequestA
                            [05-15]
                            2d 06 18 7b // wininet.dll::HttpSendRequestA
                            [05-15]
                            44 f0 35 e0 // kernel32.dll::Sleep
                            [20-30]
                            58 a4 53 e5 // kernel32.dll::VirtualAlloc
                            [10-20]
                            12 96 89 e2 // wininet.dll::InternetReadFile
                            [30-50]
                            f0 b5 a2 56 // kernel32.dll::ExitProcess
                          }
    condition:
        all of them
}
