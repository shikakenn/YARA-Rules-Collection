rule Windows_Hacktool_Mimikatz_1388212a {
    meta:
        id = "60syWVORcjJZgSLAD0bQOi"
        fingerprint = "v1_sha256_1b717453810455e3f530e399f5f9f163d1ad0d71a5464fa5c68aa82edd699cda"
        version = "1.0"
        date = "2021-04-13"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "   Password: %s" wide fullword
        $a2 = "  * Session Key   : 0x%08x - %s" wide fullword
        $a3 = "   * Injecting ticket : " wide fullword
        $a4 = " ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" wide fullword
        $a5 = "Remove mimikatz driver (mimidrv)" wide fullword
        $a6 = "mimikatz(commandline) # %s" wide fullword
        $a7 = "  Password: %s" wide fullword
        $a8 = " - SCardControl(FEATURE_CCID_ESC_COMMAND)" wide fullword
        $a9 = " * to 0 will take all 'cmd' and 'mimikatz' process" wide fullword
        $a10 = "** Pass The Ticket **" wide fullword
        $a11 = "-> Ticket : %s" wide fullword
        $a12 = "Busylight Lync model (with bootloader)" wide fullword
        $a13 = "mimikatz.log" wide fullword
        $a14 = "Log mimikatz input/output to file" wide fullword
        $a15 = "ERROR kuhl_m_dpapi_masterkey ; kull_m_dpapi_unprotect_domainkey_with_key" wide fullword
        $a16 = "ERROR kuhl_m_lsadump_dcshadow ; unable to start the server: %08x" wide fullword
        $a17 = "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformation (0x%08x)" wide fullword
        $a18 = "ERROR mimikatz_doLocal ; \"%s\" module not found !" wide fullword
        $a19 = "Install and/or start mimikatz driver (mimidrv)" wide fullword
        $a20 = "Target: %hhu (0x%02x - %s)" wide fullword
        $a21 = "mimikatz Ho, hey! I'm a DC :)" wide fullword
        $a22 = "mimikatz service (mimikatzsvc)" wide fullword
        $a23 = "[masterkey] with DPAPI_SYSTEM (machine, then user): " wide fullword
        $a24 = "$http://blog.gentilkiwi.com/mimikatz 0" ascii fullword
        $a25 = " * Username : %wZ" wide fullword
    condition:
        3 of ($a*)
}

rule Windows_Hacktool_Mimikatz_674fd079 {
    meta:
        id = "2RTbXpAGBNpfO0PVLEQkGy"
        fingerprint = "v1_sha256_f63f3de05dd4f4f40cda6df67b75e37d7baa82c4b4cafd3ebdca35adfb0b15f8"
        version = "1.0"
        date = "2021-04-14"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detection for default mimikatz memssp module"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 44 30 00 38 00 }
        $a2 = { 48 78 00 3A 00 }
        $a3 = { 4C 25 00 30 00 }
        $a4 = { 50 38 00 78 00 }
        $a5 = { 54 5D 00 20 00 }
        $a6 = { 58 25 00 77 00 }
        $a7 = { 5C 5A 00 5C 00 }
        $a8 = { 60 25 00 77 00 }
        $a9 = { 64 5A 00 09 00 }
        $a10 = { 6C 5A 00 0A 00 }
        $a11 = { 68 25 00 77 00 }
        $a12 = { 68 25 00 77 00 }
        $a13 = { 6C 5A 00 0A 00 }
        $b1 = { 6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67 }
    condition:
        all of ($a*) or $b1
}

rule Windows_Hacktool_Mimikatz_355d5d3a {
    meta:
        id = "1ZlVHqhS73UIzqOiAP5M6E"
        fingerprint = "v1_sha256_c6b48ab2cc92deb507d7eead1fb6381ee40b698e84d9eaac45288f95dbda66b3"
        version = "1.0"
        date = "2021-04-14"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Detection for Invoke-Mimikatz"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "945245ca795e0a3575ee4fdc174df9d377a598476c2bf4bf0cdb0cde4286af96"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "$PEBytes32 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $a2 = "$PEBytes64 = \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAEAAA4fug4AtAnNIbgBTM0hVGhpcyBwc"
        $b1 = "Write-BytesToMemory -Bytes $Shellcode"
        $b2 = "-MemoryAddress $GetCommandLineWAddrTemp"
        $b3 = "-MemoryAddress $GetCommandLineAAddrTemp"
        $c1 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword
        $c2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs) -ComputerNam"
        $c3 = "at: http://blog.gentilkiwi.com"
        $c4 = "on the local computer to dump certificates."
        $c5 = "Throw \"Unable to write shellcode to remote process memory.\"" fullword
        $c6 = "-Command \"privilege::debug exit\" -ComputerName \"computer1\""
        $c7 = "dump credentials without"
        $c8 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword
        $c9 = "two remote computers to dump credentials."
        $c10 = "#If a remote process to inject in to is specified, get a handle to it" fullword
    condition:
        (1 of ($a*) or 2 of ($b*)) or 5 of ($c*)
}

rule Windows_Hacktool_Mimikatz_71fe23d9 {
    meta:
        id = "6a85g3BrZQQKsvHE5ArSLM"
        fingerprint = "v1_sha256_6d1e84bb8532c6271ad3966055eac8d60ec019d8ae6632efb59463c35b46ad9b"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: Benjamin Delpy"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "856687718b208341e7caeea2d96da10f880f9b5a75736796a1158d4c8755f678"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_Hacktool_Mimikatz_b393864f {
    meta:
        id = "wRRJWwM2vFXnpOt0d0N9F"
        fingerprint = "v1_sha256_d09cb7f753675e0b6ecd8a7977ca7f8d313e5d525f05170fc54b265c2ae6c188"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: Open Source Developer, Benjamin Delpy"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "8206ce9c42582ac980ff5d64f8e3e310bc2baa42d1a206dd831c6ab397fbd8fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_Hacktool_Mimikatz_1ff74f7e {
    meta:
        id = "1fqeUF2YQFiFmZxbIPBPbk"
        fingerprint = "v1_sha256_f47f760b4c373a073399c69681e76eb9dde6cfdb36c1cc31d7131376493931c0"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Mimikatz"
        reference_sample = "1b6aad500d45de7b076942d31b7c3e77487643811a335ae5ce6783368a4a5081"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 74 65 48 8B 44 24 28 0F B7 80 E0 00 00 00 83 F8 10 75 54 48 8B 44 }
        $a2 = { 74 69 48 8B 44 24 28 0F B7 80 D0 00 00 00 83 F8 10 75 58 48 8B 44 }
    condition:
        all of them
}

