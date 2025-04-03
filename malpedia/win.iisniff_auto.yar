rule win_iisniff_auto {

    meta:
        id = "1pVrVg2SmmdXWio8uSFF5G"
        fingerprint = "v1_sha256_110e5f48ca56611bc57ccb877448c194f26647c840b794b9ff7133caff38a207"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.iisniff."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iisniff"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d7dd4 e8???????? 8b45e8 8d5d9c 8bf7 8945bc e8???????? }
            // n = 7, score = 200
            //   8d7dd4               | lea                 edi, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8d5d9c               | lea                 ebx, [ebp - 0x64]
            //   8bf7                 | mov                 esi, edi
            //   8945bc               | mov                 dword ptr [ebp - 0x44], eax
            //   e8????????           |                     

        $sequence_1 = { 8b4c240c 51 53 8d8424b4000000 e8???????? }
            // n = 5, score = 200
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8d8424b4000000       | lea                 eax, [esp + 0xb4]
            //   e8????????           |                     

        $sequence_2 = { 56 83c710 e8???????? 59 }
            // n = 4, score = 200
            //   56                   | push                esi
            //   83c710               | add                 edi, 0x10
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { 8d742434 e8???????? 33db 6aff }
            // n = 4, score = 200
            //   8d742434             | lea                 esi, [esp + 0x34]
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   6aff                 | push                -1

        $sequence_4 = { 83c404 39bc24d8000000 7210 8b8424c4000000 }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   39bc24d8000000       | cmp                 dword ptr [esp + 0xd8], edi
            //   7210                 | jb                  0x12
            //   8b8424c4000000       | mov                 eax, dword ptr [esp + 0xc4]

        $sequence_5 = { 59 59 e9???????? 33ff eb90 56 }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   e9????????           |                     
            //   33ff                 | xor                 edi, edi
            //   eb90                 | jmp                 0xffffff92
            //   56                   | push                esi

        $sequence_6 = { 56 8bcf e8???????? 8b442460 3bf0 770c 6aff }
            // n = 7, score = 200
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b442460             | mov                 eax, dword ptr [esp + 0x60]
            //   3bf0                 | cmp                 esi, eax
            //   770c                 | ja                  0xe
            //   6aff                 | push                -1

        $sequence_7 = { 8d4c0c50 6a02 e8???????? 397c2414 0f8db1feffff }
            // n = 5, score = 200
            //   8d4c0c50             | lea                 ecx, [esp + ecx + 0x50]
            //   6a02                 | push                2
            //   e8????????           |                     
            //   397c2414             | cmp                 dword ptr [esp + 0x14], edi
            //   0f8db1feffff         | jge                 0xfffffeb7

        $sequence_8 = { ff704c e8???????? 59 83f8ff 0f852cffffff }
            // n = 5, score = 200
            //   ff704c               | push                dword ptr [eax + 0x4c]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   83f8ff               | cmp                 eax, -1
            //   0f852cffffff         | jne                 0xffffff32

        $sequence_9 = { e8???????? 3bf0 7429 8b542418 4e ebd9 837c240c10 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   3bf0                 | cmp                 esi, eax
            //   7429                 | je                  0x2b
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   4e                   | dec                 esi
            //   ebd9                 | jmp                 0xffffffdb
            //   837c240c10           | cmp                 dword ptr [esp + 0xc], 0x10

        $sequence_10 = { 6a03 68000000c0 68???????? ff15???????? 6a02 }
            // n = 5, score = 200
            //   6a03                 | push                3
            //   68000000c0           | push                0xc0000000
            //   68????????           |                     
            //   ff15????????         |                     
            //   6a02                 | push                2

        $sequence_11 = { 889c24c4000000 39bc24f4000000 7210 8b8424e0000000 50 e8???????? 83c404 }
            // n = 7, score = 200
            //   889c24c4000000       | mov                 byte ptr [esp + 0xc4], bl
            //   39bc24f4000000       | cmp                 dword ptr [esp + 0xf4], edi
            //   7210                 | jb                  0x12
            //   8b8424e0000000       | mov                 eax, dword ptr [esp + 0xe0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_12 = { e8???????? 8b442414 8b4004 6a0a 8d440418 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   6a0a                 | push                0xa
            //   8d440418             | lea                 eax, [esp + eax + 0x18]
            //   50                   | push                eax

        $sequence_13 = { 50 8975ec e8???????? 8975fc 807de800 7507 be04000000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   e8????????           |                     
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   807de800             | cmp                 byte ptr [ebp - 0x18], 0
            //   7507                 | jne                 9
            //   be04000000           | mov                 esi, 4

        $sequence_14 = { 51 8d842434010000 50 894c2418 }
            // n = 4, score = 200
            //   51                   | push                ecx
            //   8d842434010000       | lea                 eax, [esp + 0x134]
            //   50                   | push                eax
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx

    condition:
        7 of them and filesize < 1441792
}
