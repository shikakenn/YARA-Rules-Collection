/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2014-11-23
    Identifier: Regin

    Warning: Don't use this rule set without excluding the false positive hashes listed in 
             the file falsepositive-hashes.txt

*/

/* REGIN ---------------------------------------------------------------------------------- */

rule Regin_APT_KernelDriver_Generic_A {
    meta:
        id = "2vQMjYWV8t3FNhuiR1TGAL"
        fingerprint = "v1_sha256_4863b1c1f49a1e083305282c6e038a76c18999401b70c211f921d9de8950ecff"
        version = "1.0"
        date = "23.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@Malwrsignatures - included in APT Scanner THOR"
        description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
        category = "INFO"
        hash1 = "187044596bc1328efa0ed636d8aa4a5c"
        hash2 = "06665b96e293b23acc80451abb413e50"
        hash3 = "d240f06e98c8d3e647cbf4d442d79475"

    strings:
        $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
        $m1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
        
        $s0 = "atapi.sys" fullword wide
        $s1 = "disk.sys" fullword wide
        $s3 = "h.data" fullword ascii
        $s4 = "\\system32" fullword ascii
        $s5 = "\\SystemRoot" fullword ascii
        $s6 = "system" fullword ascii
        $s7 = "temp" fullword ascii
        $s8 = "windows" fullword ascii

        $x1 = "LRich6" fullword ascii
        $x2 = "KeServiceDescriptorTable" fullword ascii		
    condition:
        $m0 at 0 and $m1 and  	
        all of ($s*) and 1 of ($x*)
}

rule Regin_APT_KernelDriver_Generic_B {
    meta:
        id = "6u2zb9xvyyr73KGJ80nn4"
        fingerprint = "v1_sha256_2f2661d4d3be4502f99c27dbbecfc2e149f26980d0d0b212a714cec2c1f65007"
        version = "1.0"
        date = "23.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@Malwrsignatures - included in APT Scanner THOR"
        description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
        category = "INFO"
        hash1 = "ffb0b9b5b610191051a7bdf0806e1e47"
        hash2 = "bfbe8c3ee78750c3a520480700e440f8"
        hash3 = "b29ca4f22ae7b7b25f79c1d4a421139d"
        hash4 = "06665b96e293b23acc80451abb413e50"
        hash5 = "2c8b9d2885543d7ade3cae98225e263b"
        hash6 = "4b6b86c7fec1c574706cecedf44abded"
        hash7 = "187044596bc1328efa0ed636d8aa4a5c"
        hash8 = "d240f06e98c8d3e647cbf4d442d79475"
        hash9 = "6662c390b2bbbd291ec7987388fc75d7"
        hash10 = "1c024e599ac055312a4ab75b3950040a"
        hash11 = "ba7bb65634ce1e30c1e5415be3d1db1d"
        hash12 = "b505d65721bb2453d5039a389113b566"
        hash13 = "b269894f434657db2b15949641a67532"

    strings:
        $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
        $s1 = { 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e }
        $s2 = "H.data" fullword ascii nocase
        $s3 = "INIT" fullword ascii
        $s4 = "ntoskrnl.exe" fullword ascii
        
        $v1 = "\\system32" fullword ascii
        $v2 = "\\SystemRoot" fullword ascii
        $v3 = "KeServiceDescriptorTable" fullword ascii	
        
        $w1 = "\\system32" fullword ascii
        $w2 = "\\SystemRoot" fullword ascii		
        $w3 = "LRich6" fullword ascii
        
        $x1 = "_snprintf" fullword ascii
        $x2 = "_except_handler3" fullword ascii
        
        $y1 = "mbstowcs" fullword ascii
        $y2 = "wcstombs" fullword ascii
        $y3 = "KeGetCurrentIrql" fullword ascii
        
        $z1 = "wcscpy" fullword ascii
        $z2 = "ZwCreateFile" fullword ascii
        $z3 = "ZwQueryInformationFile" fullword ascii
        $z4 = "wcslen" fullword ascii
        $z5 = "atoi" fullword ascii
    condition:
        $m0 at 0 and all of ($s*) and 
        ( all of ($v*) or all of ($w*) or all of ($x*) or all of ($y*) or all of ($z*) ) 
        and filesize < 20KB
}

rule Regin_APT_KernelDriver_Generic_C {
    meta:
        id = "yJ5bH4HcBPR6gbay5x74M"
        fingerprint = "v1_sha256_82a84a84aa600aa1ab9622ef8161ffc435a3bbbb6a949a534c178cad273dce76"
        version = "1.0"
        date = "23.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@Malwrsignatures - included in APT Scanner THOR"
        description = "Generic rule for Regin APT kernel driver Malware - Symantec http://t.co/qu53359Cb2"
        category = "INFO"
        hash1 = "e0895336617e0b45b312383814ec6783556d7635"
        hash2 = "732298fa025ed48179a3a2555b45be96f7079712"

    strings:
        $m0 = { 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } 
    
        $s0 = "KeGetCurrentIrql" fullword ascii
        $s1 = "5.2.3790.0 (srv03_rtm.030324-2048)" fullword wide
        $s2 = "usbclass" fullword wide
        
        $x1 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
        $x2 = "Universal Serial Bus Class Driver" fullword wide
        $x3 = "5.2.3790.0" fullword wide
        
        $y1 = "LSA Shell" fullword wide
        $y2 = "0Richw" fullword ascii		
    condition:
        $m0 at 0 and all of ($s*) and 
        ( all of ($x*) or all of ($y*) ) 
        and filesize < 20KB
}

/* Update 27.11.14 */

rule Regin_sig_svcsstat {
    meta:
        id = "2f1shSo206yS1MqzEyf0CR"
        fingerprint = "v1_sha256_b8dd4304c7e29c91d96d9f4662c17f1496ad909c77aaf2c616cd8ac3811ec052"
        version = "1.0"
        date = "26.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@MalwrSignatures"
        description = "Detects svcstat from Regin report - file svcsstat.exe_sample"
        category = "INFO"
        hash = "5164edc1d54f10b7cb00a266a1b52c623ab005e2"

    strings:
        $s0 = "Service Control Manager" fullword ascii
        $s1 = "_vsnwprintf" fullword ascii
        $s2 = "Root Agency" fullword ascii
        $s3 = "Root Agency0" fullword ascii
        $s4 = "StartServiceCtrlDispatcherA" fullword ascii
        $s5 = "\\\\?\\UNC" fullword wide
        $s6 = "%ls%ls" fullword wide
    condition:
        all of them and filesize < 15KB and filesize > 10KB 
}

rule Regin_Sample_1 {
    meta:
        id = "6F0pbCpM1AflO7mDuGqn3q"
        fingerprint = "v1_sha256_a506a6ec30e07e1996cdd4173878605f006b9ad517bbbc211b6693ff043ee705"
        version = "1.0"
        date = "26.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@MalwrSignatures"
        description = "Auto-generated rule - file-3665415_sys"
        category = "INFO"
        hash = "773d7fab06807b5b1bc2d74fa80343e83593caf2"

    strings:
        $s0 = "Getting PortName/Identifier failed - %x" fullword ascii
        $s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
        $s2 = "External Naming Failed - Status %x" fullword ascii
        $s3 = "------- Same multiport - different interrupts" fullword ascii
        $s4 = "%x occurred prior to the wait - starting the" fullword ascii
        $s5 = "'user registry info - userPortIndex: %d" fullword ascii
        $s6 = "Could not report legacy device - %x" fullword ascii
        $s7 = "entering SerialGetPortInfo" fullword ascii
        $s8 = "'user registry info - userPort: %x" fullword ascii
        $s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
        $s10 = "Kernel debugger is using port at address %X" fullword ascii
        $s12 = "Release - freeing multi context" fullword ascii
        $s13 = "Serial driver will not load port" fullword ascii
        $s14 = "'user registry info - userAddressSpace: %d" fullword ascii
        $s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
        $s20 = "'user registry info - userIndexed: %d" fullword ascii
    condition:
        all of them and filesize < 110KB and filesize > 80KB
}

rule Regin_Sample_2 {
    meta:
        id = "Lj6bKfL2fi3kONFSLjNC7"
        fingerprint = "v1_sha256_81ac8d4180aecc4721c046d971af15ce8dfa366abeee693904bd81edb21b3546"
        version = "1.0"
        date = "26.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@MalwrSignatures"
        description = "Auto-generated rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
        category = "INFO"
        hash = "a7b285d4b896b66fce0ebfcd15db53b3a74a0400"

    strings:
        $s0 = "\\SYSTEMROOT\\system32\\lsass.exe" fullword wide
        $s1 = "atapi.sys" fullword wide
        $s2 = "disk.sys" fullword wide
        $s3 = "IoGetRelatedDeviceObject" fullword ascii
        $s4 = "HAL.dll" fullword ascii
        $s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" fullword ascii
        $s6 = "PsGetCurrentProcessId" fullword ascii
        $s7 = "KeGetCurrentIrql" fullword ascii
        $s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
        $s9 = "KeSetImportanceDpc" fullword ascii
        $s10 = "KeQueryPerformanceCounter" fullword ascii
        $s14 = "KeInitializeEvent" fullword ascii
        $s15 = "KeDelayExecutionThread" fullword ascii
        $s16 = "KeInitializeTimerEx" fullword ascii
        $s18 = "PsLookupProcessByProcessId" fullword ascii
        $s19 = "ExReleaseFastMutexUnsafe" fullword ascii
        $s20 = "ExAcquireFastMutexUnsafe" fullword ascii
    condition:
        all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_3 {
    meta:
        id = "49tl4WK40NrTBQ7jhckXQD"
        fingerprint = "v1_sha256_68a70ece3144132ab2c9c288f7374dfdd663073829c4a2f8e2422301da4363c5"
        version = "1.0"
        date = "27.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@Malwrsignatures"
        description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
        category = "INFO"
        hash = "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"

    strings:
        $hd = { fe ba dc fe }
    
        $s0 = "Service Pack x" fullword wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
        $s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide
        $s3 = "mntoskrnl.exe" fullword wide
        $s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" fullword wide
        $s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
        $s6 = "Service Pack" fullword wide
        $s7 = ".sys" fullword wide
        $s8 = ".dll" fullword wide		
        
        $s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" fullword wide
        $s11 = "IoGetRelatedDeviceObject" fullword ascii
        $s12 = "VMEM.sys" fullword ascii
        $s13 = "RtlGetVersion" fullword wide
        $s14 = "ntkrnlpa.exe" fullword ascii
    condition:
        ( $hd at 0 ) and all of ($s*) and filesize > 160KB and filesize < 200KB
}

rule Regin_Sample_Set_1 {
    meta:
        id = "4ghxqv8JxrKZ5AaaihV1T3"
        fingerprint = "v1_sha256_4c2028d5fa3e2f5096c3d8c1b7b81687d83be6d8c1731eed14555684d44701c0"
        version = "1.0"
        date = "26.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@MalwrSignatures"
        description = "Auto-generated rule - file SHF-000052 and ndisips.sys"
        category = "INFO"
        hash1 = "8487a961c8244004c9276979bb4b0c14392fc3b8"
        hash2 = "bcf3461d67b39a427c83f9e39b9833cfec977c61"

    strings:
        $s0 = "HAL.dll" fullword ascii
        $s1 = "IoGetDeviceObjectPointer" fullword ascii
        $s2 = "MaximumPortsServiced" fullword wide
        $s3 = "KeGetCurrentIrql" fullword ascii
        $s4 = "ntkrnlpa.exe" fullword ascii
        $s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
        $s6 = "ConnectMultiplePorts" fullword wide
        $s7 = "\\SYSTEMROOT" fullword wide
        $s8 = "IoWriteErrorLogEntry" fullword ascii
        $s9 = "KeQueryPerformanceCounter" fullword ascii
        $s10 = "KeServiceDescriptorTable" fullword ascii
        $s11 = "KeRemoveEntryDeviceQueue" fullword ascii
        $s12 = "SeSinglePrivilegeCheck" fullword ascii
        $s13 = "KeInitializeEvent" fullword ascii
        $s14 = "IoBuildDeviceIoControlRequest" fullword ascii
        $s15 = "KeRemoveDeviceQueue" fullword ascii
        $s16 = "IofCompleteRequest" fullword ascii
        $s17 = "KeInitializeSpinLock" fullword ascii
        $s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
        $s19 = "IoCreateDevice" fullword ascii
        $s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
    condition:
        all of them and filesize < 40KB and filesize > 30KB
}

rule Regin_Sample_Set_2 {
    meta:
        id = "kBq433IIeiNmNPqmUWhT"
        fingerprint = "v1_sha256_98d9c8bef4f63b26b06452228752e4e0a72547a1dafa1d88287fd2698e9c2598"
        version = "1.0"
        date = "27.11.14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@MalwrSignatures"
        description = "Detects Regin Backdoor sample 4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be and e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"
        category = "INFO"
        hash1 = "4139149552b0322f2c5c993abccc0f0d1b38db4476189a9f9901ac0d57a656be"
        hash2 = "e420d0cf7a7983f78f5a15e6cb460e93c7603683ae6c41b27bf7f2fa34b2d935"

    strings:
        $hd = { fe ba dc fe }
    
        $s0 = "d%ls%ls" fullword wide
        $s1 = "\\\\?\\UNC" fullword wide
        $s2 = "Software\\Microsoft\\Windows\\CurrentVersion" fullword wide
        $s3 = "\\\\?\\UNC\\" fullword wide
        $s4 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}" fullword wide
        $s5 = "System\\CurrentControlSet\\Services\\Tcpip\\Linkage" wide fullword
        $s6 = "\\\\.\\Global\\%s" fullword wide
        $s7 = "temp" fullword wide
        $s8 = "\\\\.\\%s" fullword wide
        $s9 = "Memory location: 0x%p, size 0x%08x" fullword wide		
        
        $s10 = "sscanf" fullword ascii
        $s11 = "disp.dll" fullword ascii
        $s12 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii
        $s13 = "%d.%d.%d.%d%c" fullword ascii
        $s14 = "imagehlp.dll" fullword ascii
        $s15 = "%hd %d" fullword ascii
    condition:
        ( $hd at 0 ) and all of ($s*) and filesize < 450KB and filesize > 360KB
}

rule apt_regin_legspin {
    meta:
        id = "4RZv5HeVI1OtgIdu2ETSKt"
        fingerprint = "v1_sha256_9a488cd3a86213be27b9be8014b16e897c4477183109a5711acfa30a7be76d93"
        version = "1.0"
        modified = "2015-01-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect Regin's Legspin module"
        category = "INFO"
        reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
        copyright = "Kaspersky Lab"
        md5 = "29105f46e4d33f66fee346cfd099d1cc"

    strings:
        $mz="MZ"
        $a1="sharepw"
        $a2="reglist"
        $a3="logdump"
        $a4="Name:" wide
        $a5="Phys Avail:"
        $a6="cmd.exe" wide
        $a7="ping.exe" wide
        $a8="millisecs"
    condition:
        ($mz at 0) and all of ($a*)
}

rule apt_regin_hopscotch {
    meta:
        id = "fkGsooRBno6gKGsP9hGu0"
        fingerprint = "v1_sha256_b7606f977216b34f04edafd52cdc478e50eeb41d22effabf9528d40c2b54d534"
        version = "1.0"
        modified = "2015-01-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect Regin's Hopscotch module"
        category = "INFO"
        reference = "https://securelist.com/blog/research/68438/an-analysis-of-regins-hopscotch-and-legspin/"
        copyright = "Kaspersky Lab"
        md5 = "6c34031d7a5fc2b091b623981a8ae61c"

    strings:

        $mz="MZ"

        $a1="AuthenticateNetUseIpc"
        $a2="Failed to authenticate to"
        $a3="Failed to disconnect from"
        $a4="%S\\ipc$" wide
        $a5="Not deleting..."
        $a6="CopyServiceToRemoteMachine"
        $a7="DH Exchange failed"
        $a8="ConnectToNamedPipes"
    condition:
        ($mz at 0) and all of ($a*)
}

rule Regin_Related_Malware {
    meta:
        id = "3oc5xadBRdTjNIdZarEyAw"
        fingerprint = "v1_sha256_61ce7a69ab357740158e355455362a4f5fddc67ee60af120733f509e7407216f"
        version = "1.0"
        score = 70
        date = "2015-06-03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Malware Sample - maybe Regin related"
        category = "INFO"
        reference = "VT Analysis"
        hash = "76c355bfeb859a347e38da89e3d30a6ff1f94229"

    strings:
        $s1 = "%c%s%c -p %d -e %d -pv -c \"~~[%x] s; .%c%c%s %s /u %s_%d.dmp; q\"" fullword wide /* score: '22.015' */

        $s0 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" fullword wide /* PEStudio Blacklist: os */ /* score: '26.02' */
        $s2 = "%x:%x:%x:%x:%x:%x:%x:%x%c" fullword ascii /* score: '13.01' */
        $s3 = "disp.dll" fullword ascii /* score: '11.01' */
        $s4 = "msvcrtd.dll" fullword ascii /* score: '11.005' */
        $s5 = "%d.%d.%d.%d%c" fullword ascii /* score: '11.0' */
        $s6 = "%ls_%08x" fullword wide /* score: '8.0' */
        $s8 = "d%ls%ls" fullword wide /* score: '7.005' */
        $s9 = "Memory location: 0x%p, size 0x%08x" fullword wide /* score: '6.025' */
    condition:
        $s1 or 3 of ($s*)
}
