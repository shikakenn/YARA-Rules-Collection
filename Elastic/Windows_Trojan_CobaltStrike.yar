rule Windows_Trojan_CobaltStrike_c851687a {
    meta:
        id = "20QCb096cuJOEgMt7OF1lQ"
        fingerprint = "v1_sha256_7fac6fb24ac18bd69dd9f8f4090c4a77d1cc6554b6ae5c846e32d7666e5a1971"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies UAC Bypass module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "bypassuac.dll" ascii fullword
        $a2 = "bypassuac.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
        $b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
        $b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
        $b3 = "[*] Cleanup successful" ascii fullword
        $b4 = "\\System32\\cliconfg.exe" wide fullword
        $b5 = "\\System32\\eventvwr.exe" wide fullword
        $b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
        $b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
        $b8 = "\\System32\\sysprep\\" wide fullword
        $b9 = "[-] COM initialization failed." ascii fullword
        $b10 = "[-] Privileged file copy failed: %S" ascii fullword
        $b11 = "[-] Failed to start %S: %d" ascii fullword
        $b12 = "ReflectiveLoader"
        $b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
        $b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
        $b15 = "[+] %S ran and exited." ascii fullword
        $b16 = "[+] Privileged file copy success! %S" ascii fullword
    condition:
        2 of ($a*) or 10 of ($b*)
}

rule Windows_Trojan_CobaltStrike_0b58325e {
    meta:
        id = "1ftOFbgapJxAqjkCDx9TTo"
        fingerprint = "v1_sha256_3822431e946fcc38c700cc8ce213e95f33a155d7f38b6ab2a24cb998d42c8521"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Keylogger module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "keylogger.dll" ascii fullword
        $a2 = "keylogger.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\keylogger" ascii fullword
        $a4 = "%cE=======%c" ascii fullword
        $a5 = "[unknown: %02X]" ascii fullword
        $b1 = "ReflectiveLoader"
        $b2 = "%c2%s%c" ascii fullword
        $b3 = "[numlock]" ascii fullword
        $b4 = "%cC%s" ascii fullword
        $b5 = "[backspace]" ascii fullword
        $b6 = "[scroll lock]" ascii fullword
        $b7 = "[control]" ascii fullword
        $b8 = "[left]" ascii fullword
        $b9 = "[page up]" ascii fullword
        $b10 = "[page down]" ascii fullword
        $b11 = "[prtscr]" ascii fullword
        $b12 = "ZRich9" ascii fullword
        $b13 = "[ctrl]" ascii fullword
        $b14 = "[home]" ascii fullword
        $b15 = "[pause]" ascii fullword
        $b16 = "[clear]" ascii fullword
    condition:
        1 of ($a*) and 14 of ($b*)
}

rule Windows_Trojan_CobaltStrike_2b8cddf8 {
    meta:
        id = "1Q5a4iuQgurHonuQhUFzj"
        fingerprint = "v1_sha256_5502c06d33b93bae3bc25ba7dd6a5a9a3b0b2b43bb7e867e601ecb206bf503ed"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies dll load module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\dllload.x86.o" ascii fullword
        $b1 = "__imp_BeaconErrorDD" ascii fullword
        $b2 = "__imp_BeaconErrorNA" ascii fullword
        $b3 = "__imp_BeaconErrorD" ascii fullword
        $b4 = "__imp_BeaconDataInt" ascii fullword
        $b5 = "__imp_KERNEL32$WriteProcessMemory" ascii fullword
        $b6 = "__imp_KERNEL32$OpenProcess" ascii fullword
        $b7 = "__imp_KERNEL32$CreateRemoteThread" ascii fullword
        $b8 = "__imp_KERNEL32$VirtualAllocEx" ascii fullword
        $c1 = "__imp__BeaconErrorDD" ascii fullword
        $c2 = "__imp__BeaconErrorNA" ascii fullword
        $c3 = "__imp__BeaconErrorD" ascii fullword
        $c4 = "__imp__BeaconDataInt" ascii fullword
        $c5 = "__imp__KERNEL32$WriteProcessMemory" ascii fullword
        $c6 = "__imp__KERNEL32$OpenProcess" ascii fullword
        $c7 = "__imp__KERNEL32$CreateRemoteThread" ascii fullword
        $c8 = "__imp__KERNEL32$VirtualAllocEx" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59b44767 {
    meta:
        id = "4zXOMSYhwxB6Jn6WoBY0rl"
        fingerprint = "v1_sha256_7027d0dcbdb1961d2604f29392a923957d298a047c268553599ea8c881f76a98"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies getsystem module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x86.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\getsystem.x64.o" ascii fullword
        $b1 = "getsystem failed." ascii fullword
        $b2 = "_isSystemSID" ascii fullword
        $b3 = "__imp__NTDLL$NtQuerySystemInformation@16" ascii fullword
        $c1 = "getsystem failed." ascii fullword
        $c2 = "$pdata$isSystemSID" ascii fullword
        $c3 = "$unwind$isSystemSID" ascii fullword
        $c4 = "__imp_NTDLL$NtQuerySystemInformation" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 3 of ($c*)
}

rule Windows_Trojan_CobaltStrike_7efd3c3f {
    meta:
        id = "3D1xxUU9bkNa9Vgu3qbPLp"
        fingerprint = "v1_sha256_45a0aaba6c1be016fc5f4051680ee7e3aa62e8a5d9730b7adab08c14ae37da24"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Hashdump module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 70
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "hashdump.dll" ascii fullword
        $a2 = "hashdump.x64.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\hashdump" ascii fullword
        $a4 = "ReflectiveLoader"
        $a5 = "Global\\SAM" ascii fullword
        $a6 = "Global\\FREE" ascii fullword
        $a7 = "[-] no results." ascii fullword
    condition:
        4 of ($a*)
}

rule Windows_Trojan_CobaltStrike_6e971281 {
    meta:
        id = "1uk8wHoBS7T6v1gg2XVHMK"
        fingerprint = "v1_sha256_f204965c0118dbdfe7e134d319c92b30d22585e888609ff31df90643116a2c38"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Interfaces module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\interfaces.x86.o" ascii fullword
        $b1 = "__imp_BeaconFormatAlloc" ascii fullword
        $b2 = "__imp_BeaconFormatPrintf" ascii fullword
        $b3 = "__imp_BeaconOutput" ascii fullword
        $b4 = "__imp_KERNEL32$LocalAlloc" ascii fullword
        $b5 = "__imp_KERNEL32$LocalFree" ascii fullword
        $b6 = "__imp_LoadLibraryA" ascii fullword
        $c1 = "__imp__BeaconFormatAlloc" ascii fullword
        $c2 = "__imp__BeaconFormatPrintf" ascii fullword
        $c3 = "__imp__BeaconOutput" ascii fullword
        $c4 = "__imp__KERNEL32$LocalAlloc" ascii fullword
        $c5 = "__imp__KERNEL32$LocalFree" ascii fullword
        $c6 = "__imp__LoadLibraryA" ascii fullword
    condition:
        1 of ($a*) or 4 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_09b79efa {
    meta:
        id = "4BY43A1NBiREPsczBR2BdP"
        fingerprint = "v1_sha256_75fd003b9adf03aff8479b1b10da9c94955870b5fa4f1958f870e14acb2793c7"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Invoke Assembly module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "invokeassembly.x64.dll" ascii fullword
        $a2 = "invokeassembly.dll" ascii fullword
        $b1 = "[-] Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b2 = "[-] Failed to load the assembly w/hr 0x%08lx" ascii fullword
        $b3 = "[-] Failed to create the runtime host" ascii fullword
        $b4 = "[-] Invoke_3 on EntryPoint failed." ascii fullword
        $b5 = "[-] CLR failed to start w/hr 0x%08lx" ascii fullword
        $b6 = "ReflectiveLoader"
        $b7 = ".NET runtime [ver %S] cannot be loaded" ascii fullword
        $b8 = "[-] No .NET runtime found. :(" ascii fullword
        $b9 = "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { FF 57 0C 85 C0 78 40 8B 45 F8 8D 55 F4 8B 08 52 50 }
    condition:
        1 of ($a*) or 3 of ($b*) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_6e77233e {
    meta:
        id = "3VBAhv0PCdg8rBohxiLLDK"
        fingerprint = "v1_sha256_93aa11523b794402b257d02d4f9edc5ad320bfdb5b8b0f671ff08f399ef9e674"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Kerberos module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x64.o" ascii fullword
        $a2 = "$unwind$command_kerberos_ticket_use" ascii fullword
        $a3 = "$pdata$command_kerberos_ticket_use" ascii fullword
        $a4 = "command_kerberos_ticket_use" ascii fullword
        $a5 = "$pdata$command_kerberos_ticket_purge" ascii fullword
        $a6 = "command_kerberos_ticket_purge" ascii fullword
        $a7 = "$unwind$command_kerberos_ticket_purge" ascii fullword
        $a8 = "$unwind$kerberos_init" ascii fullword
        $a9 = "$unwind$KerberosTicketUse" ascii fullword
        $a10 = "KerberosTicketUse" ascii fullword
        $a11 = "$unwind$KerberosTicketPurge" ascii fullword
        $b1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\kerberos.x86.o" ascii fullword
        $b2 = "_command_kerberos_ticket_use" ascii fullword
        $b3 = "_command_kerberos_ticket_purge" ascii fullword
        $b4 = "_kerberos_init" ascii fullword
        $b5 = "_KerberosTicketUse" ascii fullword
        $b6 = "_KerberosTicketPurge" ascii fullword
        $b7 = "_LsaCallKerberosPackage" ascii fullword
    condition:
        5 of ($a*) or 3 of ($b*)
}

rule Windows_Trojan_CobaltStrike_de42495a {
    meta:
        id = "FGJF7stQNUoAwsgRCzBiF"
        fingerprint = "v1_sha256_2a13c73d221d80d25a432f9e0a1387153a78f58719066586e9d80d17613293ef"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Mimikatz module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\\\.\\pipe\\mimikatz" ascii fullword
        $b1 = "ERROR kuhl_m_dpapi_chrome ; Input 'Login Data' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Da" wide
        $b2 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" wide fullword
        $b3 = "ERROR kuhl_m_lsadump_getUsersAndSamKey ; kuhl_m_lsadump_getSamKey KO" wide fullword
        $b4 = "ERROR kuhl_m_lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx LSA KO" wide fullword
        $b5 = "ERROR kuhl_m_lsadump_lsa_getHandle ; OpenProcess (0x%08x)" wide fullword
        $b6 = "ERROR kuhl_m_lsadump_enumdomains_users ; SamLookupNamesInDomain: %08x" wide fullword
        $b7 = "mimikatz(powershell) # %s" wide fullword
        $b8 = "powershell_reflective_mimikatz" ascii fullword
        $b9 = "mimikatz_dpapi_cache.ndr" wide fullword
        $b10 = "mimikatz.log" wide fullword
        $b11 = "ERROR mimikatz_doLocal" wide
        $b12 = "mimikatz_x64.compressed" wide
    condition:
        1 of ($a*) and 7 of ($b*)
}

rule Windows_Trojan_CobaltStrike_72f68375 {
    meta:
        id = "6QRHqAURctICVkkm2JOkZh"
        fingerprint = "v1_sha256_912e37829a9f99e00326745343c9e4593cd7cfb8d4dfafc66027cddcb4d883be"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Netdomain module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\net_domain.x86.o" ascii fullword
        $b1 = "__imp_BeaconPrintf" ascii fullword
        $b2 = "__imp_NETAPI32$NetApiBufferFree" ascii fullword
        $b3 = "__imp_NETAPI32$DsGetDcNameA" ascii fullword
        $c1 = "__imp__BeaconPrintf" ascii fullword
        $c2 = "__imp__NETAPI32$NetApiBufferFree" ascii fullword
        $c3 = "__imp__NETAPI32$DsGetDcNameA" ascii fullword
    condition:
        1 of ($a*) or 2 of ($b*) or 2 of ($c*)
}

rule Windows_Trojan_CobaltStrike_15f680fb {
    meta:
        id = "4dSi7FN7e6MoSnbcSLkMvB"
        fingerprint = "v1_sha256_0efe368ad82f5b0f6301121bfda9fd049b008ac246368bfa22bd976fa2c56b79"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Netview module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "netview.x64.dll" ascii fullword
        $a2 = "netview.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\netview" ascii fullword
        $b1 = "Sessions for \\\\%s:" ascii fullword
        $b2 = "Account information for %s on \\\\%s:" ascii fullword
        $b3 = "Users for \\\\%s:" ascii fullword
        $b4 = "Shares at \\\\%s:" ascii fullword
        $b5 = "ReflectiveLoader" ascii fullword
        $b6 = "Password changeable" ascii fullword
        $b7 = "User's Comment" wide fullword
        $b8 = "List of hosts for domain '%s':" ascii fullword
        $b9 = "Password changeable" ascii fullword
        $b10 = "Logged on users at \\\\%s:" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_5b4383ec {
    meta:
        id = "5gBSJ48uI4wJ0upQxTQcbL"
        fingerprint = "v1_sha256_033bd831209958674f6309739d65c58d05acb9d17e53cede1cf171c6d6e84efa"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Portscan module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "portscan.x64.dll" ascii fullword
        $a2 = "portscan.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\portscan" ascii fullword
        $b1 = "(ICMP) Target '%s' is alive. [read %d bytes]" ascii fullword
        $b2 = "(ARP) Target '%s' is alive. " ascii fullword
        $b3 = "TARGETS!12345" ascii fullword
        $b4 = "ReflectiveLoader" ascii fullword
        $b5 = "%s:%d (platform: %d version: %d.%d name: %S domain: %S)" ascii fullword
        $b6 = "Scanner module is complete" ascii fullword
        $b7 = "pingpong" ascii fullword
        $b8 = "PORTS!12345" ascii fullword
        $b9 = "%s:%d (%s)" ascii fullword
        $b10 = "PREFERENCES!12345" ascii fullword
    condition:
        2 of ($a*) or 6 of ($b*)
}

rule Windows_Trojan_CobaltStrike_91e08059 {
    meta:
        id = "464xawTsZL096ZfJsMkoz1"
        fingerprint = "v1_sha256_d5a8c1a0baa5e915cff29bcac33e30a7d7260f938ecaa6171d3aa88425a69266"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Post Ex module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "postex.x64.dll" ascii fullword
        $a2 = "postex.dll" ascii fullword
        $a3 = "RunAsAdminCMSTP" ascii fullword
        $a4 = "KerberosTicketPurge" ascii fullword
        $b1 = "GetSystem" ascii fullword
        $b2 = "HelloWorld" ascii fullword
        $b3 = "KerberosTicketUse" ascii fullword
        $b4 = "SpawnAsAdmin" ascii fullword
        $b5 = "RunAsAdmin" ascii fullword
        $b6 = "NetDomain" ascii fullword
    condition:
        2 of ($a*) or 4 of ($b*)
}

rule Windows_Trojan_CobaltStrike_ee756db7 {
    meta:
        id = "35x1YkmKU4myb77dYwFRmg"
        fingerprint = "v1_sha256_8d594aa1b889e80000cfcedbfc470a1b768bdcc2a9c436cd449b495c91011918"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
        $a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
        $a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
        $a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
        $a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
        $a11 = "Could not open service control manager on %s: %d" ascii fullword
        $a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
        $a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
        $a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
        $a15 = "could not create remote thread in %d: %d" ascii fullword
        $a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a17 = "could not write to process memory: %d" ascii fullword
        $a18 = "Could not create service %s on %s: %d" ascii fullword
        $a19 = "Could not delete service %s on %s: %d" ascii fullword
        $a20 = "Could not open process token: %d (%u)" ascii fullword
        $a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a22 = "Could not start service %s on %s: %d" ascii fullword
        $a23 = "Could not query service %s on %s: %d" ascii fullword
        $a24 = "Could not connect to pipe (%s): %d" ascii fullword
        $a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a26 = "could not spawn %s (token): %d" ascii fullword
        $a27 = "could not open process %d: %d" ascii fullword
        $a28 = "could not run %s as %s\\%s: %d" ascii fullword
        $a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
        $a30 = "kerberos ticket use failed:" ascii fullword
        $a31 = "Started service %s on %s" ascii fullword
        $a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
        $a33 = "I'm already in SMB mode" ascii fullword
        $a34 = "could not spawn %s: %d" ascii fullword
        $a35 = "could not open %s: %d" ascii fullword
        $a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
        $a37 = "Could not open '%s'" ascii fullword
        $a38 = "%s.1%08x.%x%x.%s" ascii fullword
        $a39 = "%s as %s\\%s: %d" ascii fullword
        $a40 = "%s.1%x.%x%x.%s" ascii fullword
        $a41 = "beacon.x64.dll" ascii fullword
        $a42 = "%s on %s: %d" ascii fullword
        $a43 = "www6.%x%x.%s" ascii fullword
        $a44 = "cdn.%x%x.%s" ascii fullword
        $a45 = "api.%x%x.%s" ascii fullword
        $a46 = "%s (admin)" ascii fullword
        $a47 = "beacon.dll" ascii fullword
        $a48 = "%s%s: %s" ascii fullword
        $a49 = "@%d.%s" ascii fullword
        $a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
        $a51 = "Content-Length: %d" ascii fullword
    condition:
        6 of ($a*)
}

rule Windows_Trojan_CobaltStrike_9c0d5561 {
    meta:
        id = "1NJYtbl7UaOIOaQdmORONR"
        fingerprint = "v1_sha256_a8929266950e0f540a68c4fedf708e8ddc27f208f9f2866245ad7bb7f6d87913"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies PowerShell Runner module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "PowerShellRunner.dll" wide fullword
        $a2 = "powershell.x64.dll" ascii fullword
        $a3 = "powershell.dll" ascii fullword
        $a4 = "\\\\.\\pipe\\powershell" ascii fullword
        $b1 = "PowerShellRunner.PowerShellRunner" ascii fullword
        $b2 = "Failed to invoke GetOutput w/hr 0x%08lx" ascii fullword
        $b3 = "Failed to get default AppDomain w/hr 0x%08lx" ascii fullword
        $b4 = "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x%08lx" ascii fullword
        $b5 = "CustomPSHostUserInterface" ascii fullword
        $b6 = "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x%08lx" ascii fullword
        $b7 = "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x%08lx" ascii fullword
        $c1 = { 8B 08 50 FF 51 08 8B 7C 24 1C 8D 4C 24 10 51 C7 }
        $c2 = "z:\\devcenter\\aggressor\\external\\PowerShellRunner\\obj\\Release\\PowerShellRunner.pdb" ascii fullword
    condition:
        (1 of ($a*) and 4 of ($b*)) or 1 of ($c*)
}

rule Windows_Trojan_CobaltStrike_59ed9124 {
    meta:
        id = "2DFNNMqle3yq3zYaCNn7OR"
        fingerprint = "v1_sha256_a50fd291f5f1bf7ec41b1938a32473a23c3c082018b86eab87aff0d95b26ba06"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies PsExec module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\psexec_command.x86.o" ascii fullword
        $b1 = "__imp_BeaconDataExtract" ascii fullword
        $b2 = "__imp_BeaconDataParse" ascii fullword
        $b3 = "__imp_BeaconDataParse" ascii fullword
        $b4 = "__imp_BeaconDataParse" ascii fullword
        $b5 = "__imp_ADVAPI32$StartServiceA" ascii fullword
        $b6 = "__imp_ADVAPI32$DeleteService" ascii fullword
        $b7 = "__imp_ADVAPI32$QueryServiceStatus" ascii fullword
        $b8 = "__imp_ADVAPI32$CloseServiceHandle" ascii fullword
        $c1 = "__imp__BeaconDataExtract" ascii fullword
        $c2 = "__imp__BeaconDataParse" ascii fullword
        $c3 = "__imp__BeaconDataParse" ascii fullword
        $c4 = "__imp__BeaconDataParse" ascii fullword
        $c5 = "__imp__ADVAPI32$StartServiceA" ascii fullword
        $c6 = "__imp__ADVAPI32$DeleteService" ascii fullword
        $c7 = "__imp__ADVAPI32$QueryServiceStatus" ascii fullword
        $c8 = "__imp__ADVAPI32$CloseServiceHandle" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_8a791eb7 {
    meta:
        id = "NjOJMTE8aXb1roB7qMddo"
        fingerprint = "v1_sha256_d1765e6cac9b1560d6484baa1fa5a1bc0b768a72b389c7c6a60e34115669933e"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Registry module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\registry.x86.o" ascii fullword
        $b1 = "__imp_ADVAPI32$RegOpenKeyExA" ascii fullword
        $b2 = "__imp_ADVAPI32$RegEnumKeyA" ascii fullword
        $b3 = "__imp_ADVAPI32$RegOpenCurrentUser" ascii fullword
        $b4 = "__imp_ADVAPI32$RegCloseKey" ascii fullword
        $b5 = "__imp_BeaconFormatAlloc" ascii fullword
        $b6 = "__imp_BeaconOutput" ascii fullword
        $b7 = "__imp_BeaconFormatFree" ascii fullword
        $b8 = "__imp_BeaconDataPtr" ascii fullword
        $c1 = "__imp__ADVAPI32$RegOpenKeyExA" ascii fullword
        $c2 = "__imp__ADVAPI32$RegEnumKeyA" ascii fullword
        $c3 = "__imp__ADVAPI32$RegOpenCurrentUser" ascii fullword
        $c4 = "__imp__ADVAPI32$RegCloseKey" ascii fullword
        $c5 = "__imp__BeaconFormatAlloc" ascii fullword
        $c6 = "__imp__BeaconOutput" ascii fullword
        $c7 = "__imp__BeaconFormatFree" ascii fullword
        $c8 = "__imp__BeaconDataPtr" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_d00573a3 {
    meta:
        id = "3pwQbxWN0hIZt6IoLbNmL7"
        fingerprint = "v1_sha256_e458d41d28b76c989af6385f183f33aa9e11b93e529f032e95bd75433b80bd69"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Screenshot module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "screenshot.x64.dll" ascii fullword
        $a2 = "screenshot.dll" ascii fullword
        $a3 = "\\\\.\\pipe\\screenshot" ascii fullword
        $b1 = "1I1n1Q3M5Q5U5Y5]5a5e5i5u5{5" ascii fullword
        $b2 = "GetDesktopWindow" ascii fullword
        $b3 = "CreateCompatibleBitmap" ascii fullword
        $b4 = "GDI32.dll" ascii fullword
        $b5 = "ReflectiveLoader"
        $b6 = "Adobe APP14 marker: version %d, flags 0x%04x 0x%04x, transform %d" ascii fullword
    condition:
        2 of ($a*) or 5 of ($b*)
}

rule Windows_Trojan_CobaltStrike_7bcd759c {
    meta:
        id = "58pXv3uqTe42jiksqBNd14"
        fingerprint = "v1_sha256_bfbb8e8009182e87c49242ec3da6e98b23447b646f5c7ea5f97196ae929d7c5f"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies SSH Agent module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "sshagent.x64.dll" ascii fullword
        $a2 = "sshagent.dll" ascii fullword
        $b1 = "\\\\.\\pipe\\sshagent" ascii fullword
        $b2 = "\\\\.\\pipe\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii fullword
    condition:
        1 of ($a*) and 1 of ($b*)
}

rule Windows_Trojan_CobaltStrike_a56b820f {
    meta:
        id = "4xbYeD9FiBF6166WAAjPLz"
        fingerprint = "v1_sha256_52de8110727c29b0f5c75cd470ce6b80ba7821d0ba78ad074536323e2e80b460"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Timestomp module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\timestomp.x86.o" ascii fullword
        $b1 = "__imp_KERNEL32$GetFileTime" ascii fullword
        $b2 = "__imp_KERNEL32$SetFileTime" ascii fullword
        $b3 = "__imp_KERNEL32$CloseHandle" ascii fullword
        $b4 = "__imp_KERNEL32$CreateFileA" ascii fullword
        $b5 = "__imp_BeaconDataExtract" ascii fullword
        $b6 = "__imp_BeaconPrintf" ascii fullword
        $b7 = "__imp_BeaconDataParse" ascii fullword
        $b8 = "__imp_BeaconDataExtract" ascii fullword
        $c1 = "__imp__KERNEL32$GetFileTime" ascii fullword
        $c2 = "__imp__KERNEL32$SetFileTime" ascii fullword
        $c3 = "__imp__KERNEL32$CloseHandle" ascii fullword
        $c4 = "__imp__KERNEL32$CreateFileA" ascii fullword
        $c5 = "__imp__BeaconDataExtract" ascii fullword
        $c6 = "__imp__BeaconPrintf" ascii fullword
        $c7 = "__imp__BeaconDataParse" ascii fullword
        $c8 = "__imp__BeaconDataExtract" ascii fullword
    condition:
        1 of ($a*) or 5 of ($b*) or 5 of ($c*)
}

rule Windows_Trojan_CobaltStrike_92f05172 {
    meta:
        id = "6lydEexrowyK5LMxnSE7M3"
        fingerprint = "v1_sha256_7f0ff4ee14a043d72810826ab9d2b90b0f66724550ba9d3cdd2abe749f4874d0"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies UAC cmstp module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uaccmstp.x86.o" ascii fullword
        $b1 = "elevate_cmstp" ascii fullword
        $b2 = "$pdata$elevate_cmstp" ascii fullword
        $b3 = "$unwind$elevate_cmstp" ascii fullword
        $c1 = "_elevate_cmstp" ascii fullword
        $c2 = "__imp__OLE32$CoGetObject@16" ascii fullword
        $c3 = "__imp__KERNEL32$GetModuleFileNameA@12" ascii fullword
        $c4 = "__imp__KERNEL32$GetSystemWindowsDirectoryA@8" ascii fullword
        $c5 = "OLDNAMES"
        $c6 = "__imp__BeaconDataParse" ascii fullword
        $c7 = "_willAutoElevate" ascii fullword
    condition:
        1 of ($a*) or 3 of ($b*) or 4 of ($c*)
}

rule Windows_Trojan_CobaltStrike_417239b5 {
    meta:
        id = "6bQbzmrhvNQRWWE4RANZOm"
        fingerprint = "v1_sha256_fda252747359e677459d82d65c4c9c8f2ff80bc8fd6a38712f858039f3cb8dd1"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies UAC token module from Cobalt Strike"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\uactoken2.x86.o" ascii fullword
        $b1 = "$pdata$is_admin_already" ascii fullword
        $b2 = "$unwind$is_admin" ascii fullword
        $b3 = "$pdata$is_admin" ascii fullword
        $b4 = "$unwind$is_admin_already" ascii fullword
        $b5 = "$pdata$RunAsAdmin" ascii fullword
        $b6 = "$unwind$RunAsAdmin" ascii fullword
        $b7 = "is_admin_already" ascii fullword
        $b8 = "is_admin" ascii fullword
        $b9 = "process_walk" ascii fullword
        $b10 = "get_current_sess" ascii fullword
        $b11 = "elevate_try" ascii fullword
        $b12 = "RunAsAdmin" ascii fullword
        $b13 = "is_ctfmon" ascii fullword
        $c1 = "_is_admin_already" ascii fullword
        $c2 = "_is_admin" ascii fullword
        $c3 = "_process_walk" ascii fullword
        $c4 = "_get_current_sess" ascii fullword
        $c5 = "_elevate_try" ascii fullword
        $c6 = "_RunAsAdmin" ascii fullword
        $c7 = "_is_ctfmon" ascii fullword
        $c8 = "_reg_query_dword" ascii fullword
        $c9 = ".drectve" ascii fullword
        $c10 = "_is_candidate" ascii fullword
        $c11 = "_SpawnAsAdmin" ascii fullword
        $c12 = "_SpawnAsAdminX64" ascii fullword
    condition:
        1 of ($a*) or 9 of ($b*) or 7 of ($c*)
}

rule Windows_Trojan_CobaltStrike_29374056 {
    meta:
        id = "a2lIg5u2rjjlV7aNAMHoi"
        fingerprint = "v1_sha256_09755b23a7057c70f3ea242ec48549de65ebc6f13bdc38cbe22d6d758c3718cf"
        version = "1.0"
        date = "2021-03-23"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Cobalt Strike MZ Reflective Loader."
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 4D 5A 41 52 55 48 89 E5 48 81 EC 20 00 00 00 48 8D 1D ?? FF FF FF 48 81 C3 ?? ?? 00 00 FF D3 }
        $a2 = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_949f10e3 {
    meta:
        id = "kIWKQZsyV9oCHYsEsd8QY"
        fingerprint = "v1_sha256_e4b726c83013f4b9c9d61683f78a4a91935225e9ed3de0ce164b96b5a6719579"
        version = "1.0"
        date = "2021-03-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies the API address lookup function used by Cobalt Strike along with XOR implementation by Cobalt Strike."
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_8751cdf9 {
    meta:
        id = "3BS9pcnLEmc3R8mqouohPo"
        fingerprint = "v1_sha256_64fae95fd89ad46a50a00c943cf98a997a0842a83be64b3728b25151867b75a8"
        version = "1.0"
        date = "2021-03-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies Cobalt Strike wininet reverse shellcode along with XOR implementation by Cobalt Strike."
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 99
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
        $a2 = { 8B 07 01 C3 85 C0 75 E5 58 C3 E8 [2] FF FF 31 39 32 2E 31 36 38 2E ?? 2E }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_663fc95d {
    meta:
        id = "7brw3kG230UbE3P9YtWkv5"
        fingerprint = "v1_sha256_842a0a372cfb2316293f4a08e1690194fa98368a9f6ffe9c63222b2c4ab6532c"
        version = "1.0"
        date = "2021-04-01"
        modified = "2021-12-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies CobaltStrike via unidentified function code"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 48 8B F9 48 8B 49 08 FF 17 33 D2 41 B8 00 80 00 00 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_b54b94ac {
    meta:
        id = "5qzAxkEqY8wMGviaS4S6AE"
        fingerprint = "v1_sha256_6f63e4c31e55da2008f95e9d05391e40d44e2757c511e666032563ab798e274c"
        version = "1.0"
        date = "2021-10-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for beacon sleep obfuscation routine"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a_x64 = { 4C 8B 53 08 45 8B 0A 45 8B 5A 04 4D 8D 52 08 45 85 C9 75 05 45 85 DB 74 33 45 3B CB 73 E6 49 8B F9 4C 8B 03 }
        $a_x64_smbtcp = { 4C 8B 07 B8 4F EC C4 4E 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 38 10 42 30 0C 06 48 }
        $a_x86 = { 8B 46 04 8B 08 8B 50 04 83 C0 08 89 55 08 89 45 0C 85 C9 75 04 85 D2 74 23 3B CA 73 E6 8B 06 8D 3C 08 33 D2 }
        $a_x86_2 = { 8B 06 8D 3C 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 32 08 30 07 41 3B 4D 08 72 E6 8B 45 FC EB C7 }
        $a_x86_smbtcp = { 8B 07 8D 34 08 33 D2 6A 0D 8B C1 5B F7 F3 8A 44 3A 08 30 06 41 3B 4D 08 72 E6 8B 45 FC EB }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_f0b627fc {
    meta:
        id = "20eVQ4Mt1UP5xCkbnnwUC2"
        fingerprint = "v1_sha256_1087294af3a9ef59c00098f5fd7adfe0b335525e135d95e45ac30e44c6739a72"
        version = "1.0"
        date = "2021-10-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for beacon reflective loader"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "b362951abd9d96d5ec15d281682fa1c8fe8f8e4e2f264ca86f6b061af607f79b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $beacon_loader_x64 = { 25 FF FF FF 00 3D 41 41 41 00 75 [5-10] 25 FF FF FF 00 3D 42 42 42 00 75 }
        $beacon_loader_x86 = { 25 FF FF FF 00 3D 41 41 41 00 75 [4-8] 81 E1 FF FF FF 00 81 F9 42 42 42 00 75 }
        $beacon_loader_x86_2 = { 81 E1 FF FF FF 00 81 F9 41 41 41 00 75 [4-8] 81 E2 FF FF FF 00 81 FA 42 42 42 00 75 }
        $generic_loader_x64 = { 89 44 24 20 48 8B 44 24 40 0F BE 00 8B 4C 24 20 03 C8 8B C1 89 44 24 20 48 8B 44 24 40 48 FF C0 }
        $generic_loader_x86 = { 83 C4 04 89 45 FC 8B 4D 08 0F BE 11 03 55 FC 89 55 FC 8B 45 08 83 C0 01 89 45 08 8B 4D 08 0F BE }
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_dcdcdd8c {
    meta:
        id = "5V2bz4NRerALtYqYxxHbnZ"
        fingerprint = "v1_sha256_f3ae07282b763d3720e45a84878cc457f65041f381951cdc9affd5e3ce67e6cc"
        version = "1.0"
        date = "2021-10-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for beacon sleep PDB"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
        $a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
        $a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
        $a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
        $a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
        $a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword
    condition:
        any of them
}

rule Windows_Trojan_CobaltStrike_a3fb2616 {
    meta:
        id = "5gevrX9D0F4bQteHmUU5t9"
        fingerprint = "v1_sha256_a3c36326ccc2bc828f6654ccaba507a283f92146fdc52f71d7d934f6908793e2"
        version = "1.0"
        date = "2021-10-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for browser pivot "
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "browserpivot.dll" ascii fullword
        $a2 = "browserpivot.x64.dll" ascii fullword
        $b1 = "$$$THREAD.C$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" ascii fullword
        $b2 = "COBALTSTRIKE" ascii fullword
    condition:
        1 of ($a*) and 2 of ($b*)
}

rule Windows_Trojan_CobaltStrike_8ee55ee5 {
    meta:
        id = "2iSFW5Lwz48QoJEhCVH0yM"
        fingerprint = "v1_sha256_d0cc321e15660311ae0b8e3261abe716a50a2455f82635c1b02d0a5444c8a89a"
        version = "1.0"
        date = "2021-10-21"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Rule for wmi exec module"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
        $a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_8d5963a2 {
    meta:
        id = "1PtKQ15yPzRAW1M5FM0AJI"
        fingerprint = "v1_sha256_f4f8fba807256bd885ccf4946eec8c2fb76eb04f86ed76d015178fe512a3c091"
        version = "1.0"
        date = "2022-08-10"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_1787eef5 {
    meta:
        id = "59F6ZtbNDBMDnu219ypVbI"
        fingerprint = "v1_sha256_0b70c61e986dee3126fec6eea127e01fce4b647aff8e2d2d5072eb8328549225"
        version = "1.0"
        date = "2022-08-29"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "CS shellcode variants"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? C7 04 24 ?? ?? ?? ?? 89 44 24 ?? E8 ?? ?? ?? ?? 31 C0 C9 C3 55 }
        $a2 = { 55 89 E5 83 EC ?? A1 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 31 C0 C9 C3 55 89 E5 83 EC ?? 83 7D ?? ?? }
        $a3 = { 55 89 E5 8B 45 ?? 5D FF E0 55 8B 15 ?? ?? ?? ?? 89 E5 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a4 = { 55 89 E5 8B 45 ?? 5D FF E0 55 89 E5 83 EC ?? 8B 15 ?? ?? ?? ?? 8B 45 ?? 85 D2 7E ?? 83 3D ?? ?? ?? ?? ?? }
        $a5 = { 4D 5A 41 52 55 48 89 E5 48 81 EC ?? ?? ?? ?? 48 8D 1D ?? ?? ?? ?? 48 89 DF 48 81 C3 ?? ?? ?? ?? }
    condition:
        1 of ($a*)
}

rule Windows_Trojan_CobaltStrike_4106070a {
    meta:
        id = "5A0xE5Jl2wJe2eCxGk8AJ5"
        fingerprint = "v1_sha256_90f0209a55ca381ca58264664e04c007c799cf558f143d0c02983d4caf47bfb8"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
        $a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_3dc22d14 {
    meta:
        id = "3DWCfPlzzzygu0AHeoMAaq"
        fingerprint = "v1_sha256_2f52cd5f3b782c28e372c3daa9b7ddc4d2b9f68832f5250983412c2e7a755e73"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "7898194ae0244611117ec948eb0b0a5acbc15cd1419b1ecc553404e63bc519f9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
        $a2 = "%s as %s\\%s: %d" fullword
    condition:
        all of them
}

rule Windows_Trojan_CobaltStrike_7f8da98a {
    meta:
        id = "7B31ZzYl0j1YmmsQa1cPaQ"
        fingerprint = "v1_sha256_6c8698d65cbbf893f79ca1de5273535891418c87c234a2542f5f8079e56d9507"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.CobaltStrike"
        reference_sample = "e3bc2bec4a55ad6cfdf49e5dbd4657fc704af1758ca1d6e31b83dcfb8bf0f89d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4D 53 53 45 2D 25 64 2D 73 65 72 76 65 72 }
    condition:
        all of them
}

