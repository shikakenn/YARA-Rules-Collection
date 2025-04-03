rule win_unidentified_038_auto {

    meta:
        id = "6R3nyqke09KDoSp0OwhhaG"
        fingerprint = "v1_sha256_bcb6fefd014fecb64c3a86011abd92b7e4cc2ded46e9ae5992ce1dd5c22645e6"
        version = "1"
        date = "2019-11-26"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_038"
        malpedia_version = "20190204"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 57 6aff ff75f4 6a00 6a00 e8???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6aff                 | push                -1
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_1 = { e8???????? 0bc0 7411 8bc8 2b4dfc 83f900 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax
            //   7411                 | je                  0x13
            //   8bc8                 | mov                 ecx, eax
            //   2b4dfc               | sub                 ecx, dword ptr [ebp - 4]
            //   83f900               | cmp                 ecx, 0

        $sequence_2 = { e8???????? 68d11bfa7f ff75fc e8???????? 68331cfa7f }
            // n = 5, score = 100
            //   e8????????           |                     
            //   68d11bfa7f           | push                0x7ffa1bd1
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   68331cfa7f           | push                0x7ffa1c33

        $sequence_3 = { e8???????? e8???????? 8b7dfc 8bf0 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8bf0                 | mov                 esi, eax

        $sequence_4 = { 8bec 6a01 e8???????? 68f4010000 }
            // n = 4, score = 100
            //   8bec                 | mov                 ebp, esp
            //   6a01                 | push                1
            //   e8????????           |                     
            //   68f4010000           | push                0x1f4

        $sequence_5 = { 6a20 6a01 6a62 6a00 e8???????? 6a73 6a01 }
            // n = 7, score = 100
            //   6a20                 | push                0x20
            //   6a01                 | push                1
            //   6a62                 | push                0x62
            //   6a00                 | push                0
            //   e8????????           |                     
            //   6a73                 | push                0x73
            //   6a01                 | push                1

        $sequence_6 = { 2b4508 ff750c ff7514 ff7508 }
            // n = 4, score = 100
            //   2b4508               | sub                 eax, dword ptr [ebp + 8]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_7 = { e8???????? 8d85d8feffff 50 ffb5d4feffff e8???????? 85c0 7402 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d85d8feffff         | lea                 eax, [ebp - 0x128]
            //   50                   | push                eax
            //   ffb5d4feffff         | push                dword ptr [ebp - 0x12c]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7402                 | je                  4

        $sequence_8 = { 837d0801 7566 68f4010000 e8???????? 8945a4 6890010000 50 }
            // n = 7, score = 100
            //   837d0801             | cmp                 dword ptr [ebp + 8], 1
            //   7566                 | jne                 0x68
            //   68f4010000           | push                0x1f4
            //   e8????????           |                     
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   6890010000           | push                0x190
            //   50                   | push                eax

        $sequence_9 = { 6a00 683424fa7f e8???????? eb3b 837d0c05 752c }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   683424fa7f           | push                0x7ffa2434
            //   e8????????           |                     
            //   eb3b                 | jmp                 0x3d
            //   837d0c05             | cmp                 dword ptr [ebp + 0xc], 5
            //   752c                 | jne                 0x2e

    condition:
        7 of them
}
