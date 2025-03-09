

import "pe"
rule Check_Debugger
{
    meta:
        id = "512jhBbpNV3xWbKsv8y5n3"
        fingerprint = "v1_sha256_40ea29c3e45363b559c64e9e6b13fad01ea2f2d5e01cb7604b6af5af8eabbe3d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    condition:
        pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and 
        pe.imports("kernel32.dll","IsDebuggerPresent")
}
rule Check_Dlls
{
    meta:
        id = "6jWnNlNbYUt0cERLenqen9"
        fingerprint = "v1_sha256_d9acb85559f1a7f38a37df8c6728f8a900246809df045f99f488a4b8d13cb4dc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for common sandbox dlls"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $dll1 = "sbiedll.dll" wide nocase ascii fullword
        $dll2 = "dbghelp.dll" wide nocase ascii fullword
        $dll3 = "api_log.dll" wide nocase ascii fullword
        $dll4 = "dir_watch.dll" wide nocase ascii fullword
        $dll5 = "pstorec.dll" wide nocase ascii fullword
        $dll6 = "vmcheck.dll" wide nocase ascii fullword
        $dll7 = "wpespy.dll" wide nocase ascii fullword
    condition:
        2 of them
}
import "pe"
rule Check_DriveSize
{
    meta:
        id = "3gssXdomRX8OcDlu2X2rOo"
        fingerprint = "v1_sha256_6e651a96ad1301eef365deb7eaa9ea1d6867c4ff3a458b110cb83e66e6ddcab0"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
        $dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO	
    condition:
        pe.imports("kernel32.dll","CreateFileA") and 	
        pe.imports("kernel32.dll","DeviceIoControl") and 
        $dwIoControlCode and
        $physicaldrive
}
import "pe"
rule Check_FilePaths
{
    meta:
        id = "FG7sFGUfok4TqhIfRlkQX"
        fingerprint = "v1_sha256_e57506f937e1d8f39f1487e4e6ab86fa770fd31231273512d78bcb3a2f65de73"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for filepaths containing popular sandbox names"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings: 
        $path1 = "SANDBOX" wide ascii
        $path2 = "\\SAMPLE" wide ascii
        $path3 = "\\VIRUS" wide ascii
    condition:
        all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}
rule Check_Qemu_Description
{
    meta:
        id = "5sUQt6i6Dgi5vaO03Vn2F8"
        fingerprint = "v1_sha256_22da3ad33533cf52e06cc1185f53a4ad4f300e8ac36eed765e409ba4420ff703"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for QEMU systembiosversion key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}
rule Check_Qemu_DeviceMap
{
    meta:
        id = "7aJDr0JfUFo5OnSmGjPqmq"
        fingerprint = "v1_sha256_c37a34eec7bb8be8cc7643bed67508af4265dd479f8f46eb555fb0ed72b3fef4"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for Qemu reg keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "QEMU" wide nocase ascii
    condition:
        all of them
}
import "pe"
rule Check_UserNames
{
    meta:
        id = "6YWDwMXYVSDhX2lgv52NLr"
        fingerprint = "v1_sha256_8c1c311f0fdb11769582e339339d0dc9328e62a68e47e4f2b81bdf843551463a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Looks for malware checking for common sandbox usernames"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $user1 = "MALTEST" wide ascii
        $user2 = "TEQUILABOOMBOOM" wide ascii
        $user3 = "SANDBOX" wide ascii
        $user4 = "VIRUS" wide ascii
        $user5 = "MALWARE" wide ascii
    condition:
        all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}
rule Check_VBox_Description
{
    meta:
        id = "7ZT2UxKBakZTK9VBLPdbXZ"
        fingerprint = "v1_sha256_0d50c013eb8c33e090037d2d33c55c76964738ff2609cafcecddbcbc6a03f7f1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks Vbox description reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "SystemBiosVersion" nocase wide ascii
        $data = "VBOX" nocase wide ascii		
    condition:
        all of them
}
rule Check_VBox_DeviceMap
{
    meta:
        id = "6fQ86WDgJJJmIprxQfgWNS"
        fingerprint = "v1_sha256_0ab9014d640577e09ea7f8ce0bbebd81ec3b40ec2f8bdb84ea1f47c4e4ab9eee"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks Vbox registry keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
        $value = "Identifier" nocase wide ascii
        $data = "VBOX" nocase wide ascii
    condition:
        all of them
}
rule Check_VBox_Guest_Additions
{
    meta:
        id = "24S0SR2lkmnEkzbCcrRvwN"
        fingerprint = "v1_sha256_746d18bf2ca2dcbfb0f1a2033650bc454e9e7e426228273d51ac0ec508d50703"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of the guest additions registry key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
    condition:
        any of them	
}
rule Check_VBox_VideoDrivers
{
    meta:
        id = "3VYF6SwfypZFirAGThy0P1"
        fingerprint = "v1_sha256_7601e8d1eebf3a8aca4d6fae7f70855a5615ee3c7d1010ff9d5dbd5ac662ec59"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for reg keys of Vbox video drivers"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\Description\\System" nocase wide ascii
        $value = "VideoBiosVersion" wide nocase ascii
        $data = "VIRTUALBOX" nocase wide ascii
    condition:
        all of them
}
rule Check_VmTools
{
    meta:
        id = "5FAo5eRyWzCjQWizbtvO0S"
        fingerprint = "v1_sha256_6c9797cac979a3090d164dfd43c91937aa0c6b0548b06ba3d99f6e27f431959b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmTools reg key"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $tools = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
    condition:
        $tools
}
rule Check_VMWare_DeviceMap
{
    meta:
        id = "RbwkSfqXMIy8SQSoSM5SO"
        fingerprint = "v1_sha256_dbcc2d5bba61af66cd62f028c6d57b7eab2a14127327d5c38926b4ca07dc75cc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of VmWare Registry Keys"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
        $value = "Identifier" wide nocase ascii
        $data = "VMware" wide nocase ascii
    condition:
        all of them
}
import "pe"
rule Check_Wine
{
    meta:
        id = "6EdFvU1w1UbTwGll6gPF6E"
        fingerprint = "v1_sha256_46756d3e028b086becb8ae50476427c80bb66634ac66eb9f6b89b15f75d95e52"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for the existence of Wine"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings:
        $wine = "wine_get_unix_file_name"
    condition:
        $wine and pe.imports("kernel32.dll","GetModuleHandleA")
}

rule LogPOS
{
    meta:
        id = "2SizXoSlzBUKmbX2Hurcti"
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

rule BernhardPOS {
    meta:
        id = "266X23327Tjlf51oG7p5qQ"
        fingerprint = "v1_sha256_c00f2fda5a391b44767d918945069f18cef084dd4dc6aa94d8f945bf97ac462a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MORPHICK INC."
        author = "Nick Hoffman / Jeremy Humble"
        description = "BernhardPOS Credit Card dumping tool"
        category = "INFO"
        reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
        last_update = "2015-07-14"
        md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"

   strings:
     /*
     33C0        xor    eax, eax
     83C014        add    eax, 0x14
     83E814        sub    eax, 0x14
     64A130000000        mov    eax, dword ptr fs:[0x30]
     83C028        add    eax, 0x28
     83E828        sub    eax, 0x28
     8B400C        mov    eax, dword ptr [eax + 0xc]
     83C063        add    eax, 0x63
     83E863        sub    eax, 0x63
     8B4014        mov    eax, dword ptr [eax + 0x14]
     83C078        add    eax, 0x78
     83E878        sub    eax, 0x78
     8B00        mov    eax, dword ptr [eax]
     05DF030000        add    eax, 0x3df
     2DDF030000        sub    eax, 0x3df
     8B00        mov    eax, dword ptr [eax]
     83C057        add    eax, 0x57
     83E857        sub    eax, 0x57
     8B4010        mov    eax, dword ptr [eax + 0x10]
     83C063        add    eax, 0x63
     */
     $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
     $mutex_name = "OPSEC_BERNHARD" 
     $build_path = "C:\\bernhard\\Debug\\bernhard.pdb" 
     /*
     55        push    ebp
     8BEC        mov    ebp, esp
     83EC50        sub    esp, 0x50
     53        push    ebx
     56        push    esi
     57        push    edi
     A178404100        mov    eax, dword ptr [0x414078]
     8945F8        mov    dword ptr [ebp - 8], eax
     668B0D7C404100        mov    cx, word ptr [0x41407c]
     66894DFC        mov    word ptr [ebp - 4], cx
     8A157E404100        mov    dl, byte ptr [0x41407e]
     8855FE        mov    byte ptr [ebp - 2], dl
     8D45F8        lea    eax, dword ptr [ebp - 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     8945F0        mov    dword ptr [ebp - 0x10], eax
     C745F400000000        mov    dword ptr [ebp - 0xc], 0
     EB09        jmp    0x412864
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     83C001        add    eax, 1
     8945F4        mov    dword ptr [ebp - 0xc], eax
     8B4508        mov    eax, dword ptr [ebp + 8]
     50        push    eax
     FF150CB04200        call    dword ptr [0x42b00c]
     3945F4        cmp    dword ptr [ebp - 0xc], eax
     7D21        jge    0x412894
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     0FBE08        movsx    ecx, byte ptr [eax]
     8B45F4        mov    eax, dword ptr [ebp - 0xc]
     99        cdq
     F77DF0        idiv    dword ptr [ebp - 0x10]
     0FBE5415F8        movsx    edx, byte ptr [ebp + edx - 8]
     33CA        xor    ecx, edx
     8B4508        mov    eax, dword ptr [ebp + 8]
     0345F4        add    eax, dword ptr [ebp - 0xc]
     8808        mov    byte ptr [eax], cl
     EBC7        jmp    0x41285b
     5F        pop    edi
     5E        pop    esi
     5B        pop    ebx
     8BE5        mov    esp, ebp
     5D        pop    ebp
     */
     $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
   condition:
     any of them
 }



rule Mozart
{
    meta:
        id = "6Dp2GuW8uX7AFhnecyIwgd"
        fingerprint = "v1_sha256_0b5aaae20739c704075cceefd6d4517ab306d9b75005aa1f4575dbd3ad3ce262"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Nick Hoffman - Morphick Inc"
        description = "Detects samples of the Mozart POS RAM scraping utility"
        category = "INFO"

   strings:
       $pdb = "z:\\Slender\\mozart\\mozart\\Release\\mozart.pdb" nocase wide ascii
       $output = {67 61 72 62 61 67 65 2E 74 6D 70 00}
       $service_name = "NCR SelfServ Platform Remote Monitor" nocase wide ascii
       $service_name_short = "NCR_RemoteMonitor"
       $encode_data = {B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}
   condition:
      any of ($pdb, $output, $encode_data) or
      all of ($service*)
}


