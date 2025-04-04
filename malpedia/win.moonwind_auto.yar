rule win_moonwind_auto {

    meta:
        id = "2gZjP3jSbnW7hQIvq2dfMR"
        fingerprint = "v1_sha256_e8ac75896a4e3b1235e6b43c3207bc2e4011dd5892e4b54601195386441510bf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.moonwind."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moonwind"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c706???????? 8d4e18 c744241003000000 e8???????? 8d4e14 c644241002 }
            // n = 6, score = 100
            //   c706????????         |                     
            //   8d4e18               | lea                 ecx, [esi + 0x18]
            //   c744241003000000     | mov                 dword ptr [esp + 0x10], 3
            //   e8????????           |                     
            //   8d4e14               | lea                 ecx, [esi + 0x14]
            //   c644241002           | mov                 byte ptr [esp + 0x10], 2

        $sequence_1 = { 83c404 c1e002 03d8 8b1b 895dc4 8b5de0 895dc0 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   c1e002               | shl                 eax, 2
            //   03d8                 | add                 ebx, eax
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   895dc4               | mov                 dword ptr [ebp - 0x3c], ebx
            //   8b5de0               | mov                 ebx, dword ptr [ebp - 0x20]
            //   895dc0               | mov                 dword ptr [ebp - 0x40], ebx

        $sequence_2 = { 8945f0 6802000080 6a00 6800000000 6801030080 6a00 6801000000 }
            // n = 7, score = 100
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   6802000080           | push                0x80000002
            //   6a00                 | push                0
            //   6800000000           | push                0
            //   6801030080           | push                0x80000301
            //   6a00                 | push                0
            //   6801000000           | push                1

        $sequence_3 = { ff75d0 e8???????? 83c408 83f800 0f841d000000 68???????? ff75d0 }
            // n = 7, score = 100
            //   ff75d0               | push                dword ptr [ebp - 0x30]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83f800               | cmp                 eax, 0
            //   0f841d000000         | je                  0x23
            //   68????????           |                     
            //   ff75d0               | push                dword ptr [ebp - 0x30]

        $sequence_4 = { 83d8ff 85c0 750b c70201000000 e9???????? be???????? 8bc7 }
            // n = 7, score = 100
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd
            //   c70201000000         | mov                 dword ptr [edx], 1
            //   e9????????           |                     
            //   be????????           |                     
            //   8bc7                 | mov                 eax, edi

        $sequence_5 = { 6a08 51 8bcd 89542418 8944241c c644242000 e8???????? }
            // n = 7, score = 100
            //   6a08                 | push                8
            //   51                   | push                ecx
            //   8bcd                 | mov                 ecx, ebp
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   c644242000           | mov                 byte ptr [esp + 0x20], 0
            //   e8????????           |                     

        $sequence_6 = { 50 6803000000 bb70020000 e8???????? 83c428 a3???????? 6801030080 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6803000000           | push                3
            //   bb70020000           | mov                 ebx, 0x270
            //   e8????????           |                     
            //   83c428               | add                 esp, 0x28
            //   a3????????           |                     
            //   6801030080           | push                0x80000301

        $sequence_7 = { ff75f0 e8???????? 83c408 83f800 0f8518000000 c705????????00000000 8d45ec }
            // n = 7, score = 100
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   83f800               | cmp                 eax, 0
            //   0f8518000000         | jne                 0x1e
            //   c705????????00000000     |     
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_8 = { dc05???????? dd5dd4 dd45d4 e8???????? 8945f0 837df006 0f8469050000 }
            // n = 7, score = 100
            //   dc05????????         |                     
            //   dd5dd4               | fstp                qword ptr [ebp - 0x2c]
            //   dd45d4               | fld                 qword ptr [ebp - 0x2c]
            //   e8????????           |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   837df006             | cmp                 dword ptr [ebp - 0x10], 6
            //   0f8469050000         | je                  0x56f

        $sequence_9 = { f3a5 8b45f0 40 c1e002 83c008 50 ff75f4 }
            // n = 7, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   40                   | inc                 eax
            //   c1e002               | shl                 eax, 2
            //   83c008               | add                 eax, 8
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]

    condition:
        7 of them and filesize < 1417216
}
