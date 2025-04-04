rule win_plugx_auto {

    meta:
        id = "4cHhLGjiTYjiAa2MRwz6Db"
        fingerprint = "v1_sha256_15190bb8aae3c81242a3f62c3118fe86de191513b0096b3d3022dcd142f4bd88"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.plugx."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 56 57 6a1c 8bf8 e8???????? 8bf0 }
            // n = 7, score = 1300
            //   51                   | push                ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a1c                 | push                0x1c
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { 41 3bca 7ce0 3bca }
            // n = 4, score = 1300
            //   41                   | inc                 ecx
            //   3bca                 | cmp                 ecx, edx
            //   7ce0                 | jl                  0xffffffe2
            //   3bca                 | cmp                 ecx, edx

        $sequence_2 = { 56 8b750c 8b4604 050070ffff }
            // n = 4, score = 1300
            //   56                   | push                esi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   050070ffff           | add                 eax, 0xffff7000

        $sequence_3 = { 33d2 f7f3 33d2 8945fc }
            // n = 4, score = 1300
            //   33d2                 | xor                 edx, edx
            //   f7f3                 | div                 ebx
            //   33d2                 | xor                 edx, edx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_4 = { 55 8bec 8b450c 81780402700000 }
            // n = 4, score = 1300
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   81780402700000       | cmp                 dword ptr [eax + 4], 0x7002

        $sequence_5 = { 51 53 6a00 6a00 6a02 ffd0 85c0 }
            // n = 7, score = 1300
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax

        $sequence_6 = { 0145f4 8b45fc 0fafc3 33d2 }
            // n = 4, score = 1300
            //   0145f4               | add                 dword ptr [ebp - 0xc], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fafc3               | imul                eax, ebx
            //   33d2                 | xor                 edx, edx

        $sequence_7 = { 50 ff15???????? a3???????? 8b4d18 }
            // n = 4, score = 900
            //   50                   | push                eax
            //   ff15????????         |                     
            //   a3????????           |                     
            //   8b4d18               | mov                 ecx, dword ptr [ebp + 0x18]

        $sequence_8 = { e8???????? 3de5030000 7407 e8???????? }
            // n = 4, score = 900
            //   e8????????           |                     
            //   3de5030000           | cmp                 eax, 0x3e5
            //   7407                 | je                  9
            //   e8????????           |                     

        $sequence_9 = { e8???????? 85c0 7508 e8???????? 8945fc }
            // n = 5, score = 900
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_10 = { 85c0 7413 e8???????? 3de5030000 }
            // n = 4, score = 900
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   e8????????           |                     
            //   3de5030000           | cmp                 eax, 0x3e5

        $sequence_11 = { e8???????? 85c0 7407 b84f050000 }
            // n = 4, score = 800
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   b84f050000           | mov                 eax, 0x54f

        $sequence_12 = { 6a00 6a00 6a04 6a00 6a01 6800000040 57 }
            // n = 7, score = 700
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a04                 | push                4
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000040           | push                0x40000000
            //   57                   | push                edi

        $sequence_13 = { e8???????? 85c0 750a e8???????? 8945fc }
            // n = 5, score = 700
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_14 = { 85c0 750d e8???????? 8945f4 }
            // n = 4, score = 600
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_15 = { 51 6a00 6800100000 6800100000 68ff000000 6a00 6803000040 }
            // n = 7, score = 600
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6800100000           | push                0x1000
            //   6800100000           | push                0x1000
            //   68ff000000           | push                0xff
            //   6a00                 | push                0
            //   6803000040           | push                0x40000003

        $sequence_16 = { 6819000200 6a00 6a00 6a00 51 }
            // n = 5, score = 600
            //   6819000200           | push                0x20019
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   51                   | push                ecx

        $sequence_17 = { 57 e8???????? eb0c e8???????? }
            // n = 4, score = 500
            //   57                   | push                edi
            //   e8????????           |                     
            //   eb0c                 | jmp                 0xe
            //   e8????????           |                     

        $sequence_18 = { 81ec90010000 e8???????? e8???????? e8???????? }
            // n = 4, score = 400
            //   81ec90010000         | sub                 esp, 0x190
            //   e8????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_19 = { 68???????? e8???????? 6800080000 68???????? e8???????? }
            // n = 5, score = 400
            //   68????????           |                     
            //   e8????????           |                     
            //   6800080000           | push                0x800
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_20 = { 50 56 ffb42480000000 ff15???????? }
            // n = 4, score = 400
            //   50                   | push                eax
            //   56                   | push                esi
            //   ffb42480000000       | push                dword ptr [esp + 0x80]
            //   ff15????????         |                     

        $sequence_21 = { 89742434 89f1 8b442434 e8???????? }
            // n = 4, score = 400
            //   89742434             | mov                 dword ptr [esp + 0x34], esi
            //   89f1                 | mov                 ecx, esi
            //   8b442434             | mov                 eax, dword ptr [esp + 0x34]
            //   e8????????           |                     

        $sequence_22 = { 89442424 8b442424 6808020000 6a00 }
            // n = 4, score = 400
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   8b442424             | mov                 eax, dword ptr [esp + 0x24]
            //   6808020000           | push                0x208
            //   6a00                 | push                0

        $sequence_23 = { 6a02 6a00 e8???????? c705????????00000000 }
            // n = 4, score = 400
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   e8????????           |                     
            //   c705????????00000000     |     

        $sequence_24 = { 5d c21000 55 53 57 56 83ec18 }
            // n = 7, score = 400
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   83ec18               | sub                 esp, 0x18

        $sequence_25 = { 6a00 6a00 6a01 6a00 e8???????? a3???????? 6800080000 }
            // n = 7, score = 400
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   e8????????           |                     
            //   a3????????           |                     
            //   6800080000           | push                0x800

        $sequence_26 = { 6808020000 6a00 ff74242c e8???????? 83c40c }
            // n = 5, score = 400
            //   6808020000           | push                0x208
            //   6a00                 | push                0
            //   ff74242c             | push                dword ptr [esp + 0x2c]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_27 = { 50 ff75e8 6802000080 e8???????? }
            // n = 4, score = 400
            //   50                   | push                eax
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   6802000080           | push                0x80000002
            //   e8????????           |                     

        $sequence_28 = { 50 6802000080 53 e8???????? }
            // n = 4, score = 300
            //   50                   | push                eax
            //   6802000080           | push                0x80000002
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_29 = { 68000000a0 6aff ffb424c8000000 ff74241c }
            // n = 4, score = 300
            //   68000000a0           | push                0xa0000000
            //   6aff                 | push                -1
            //   ffb424c8000000       | push                dword ptr [esp + 0xc8]
            //   ff74241c             | push                dword ptr [esp + 0x1c]

        $sequence_30 = { 6808020000 6a00 ff74245c e8???????? }
            // n = 4, score = 300
            //   6808020000           | push                0x208
            //   6a00                 | push                0
            //   ff74245c             | push                dword ptr [esp + 0x5c]
            //   e8????????           |                     

        $sequence_31 = { 6a5c ff74241c e8???????? 83c408 }
            // n = 4, score = 300
            //   6a5c                 | push                0x5c
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_32 = { 5e 5f 5b 5d c20400 50 64a118000000 }
            // n = 7, score = 300
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   50                   | push                eax
            //   64a118000000         | mov                 eax, dword ptr fs:[0x18]

    condition:
        7 of them and filesize < 1284096
}
