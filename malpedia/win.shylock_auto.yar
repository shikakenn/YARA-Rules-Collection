rule win_shylock_auto {

    meta:
        id = "il3TU3oHFG2oNFt0PToRe"
        fingerprint = "v1_sha256_34460d345c77d949d300b4c007098ec528b095570601731f99128cb864a10989"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shylock."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shylock"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 b8???????? e8???????? 59 8bd8 51 54 }
            // n = 7, score = 500
            //   50                   | push                eax
            //   b8????????           |                     
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8bd8                 | mov                 ebx, eax
            //   51                   | push                ecx
            //   54                   | push                esp

        $sequence_1 = { ffb0b0000000 ffb0ac000000 e8???????? 83c410 85c0 0f849a060000 833d????????01 }
            // n = 7, score = 500
            //   ffb0b0000000         | push                dword ptr [eax + 0xb0]
            //   ffb0ac000000         | push                dword ptr [eax + 0xac]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   0f849a060000         | je                  0x6a0
            //   833d????????01       |                     

        $sequence_2 = { 8d85b0fdffff e8???????? 59 8b45fc 5f 5e 5b }
            // n = 7, score = 500
            //   8d85b0fdffff         | lea                 eax, [ebp - 0x250]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_3 = { 8d7318 e8???????? 8d7314 e8???????? 8d7310 e8???????? 8d730c }
            // n = 7, score = 500
            //   8d7318               | lea                 esi, [ebx + 0x18]
            //   e8????????           |                     
            //   8d7314               | lea                 esi, [ebx + 0x14]
            //   e8????????           |                     
            //   8d7310               | lea                 esi, [ebx + 0x10]
            //   e8????????           |                     
            //   8d730c               | lea                 esi, [ebx + 0xc]

        $sequence_4 = { e8???????? 8d75e0 e8???????? 8d75ec e8???????? 8d75f4 e8???????? }
            // n = 7, score = 500
            //   e8????????           |                     
            //   8d75e0               | lea                 esi, [ebp - 0x20]
            //   e8????????           |                     
            //   8d75ec               | lea                 esi, [ebp - 0x14]
            //   e8????????           |                     
            //   8d75f4               | lea                 esi, [ebp - 0xc]
            //   e8????????           |                     

        $sequence_5 = { 59 50 e8???????? 83c40c 8d75fc 8bf8 e8???????? }
            // n = 7, score = 500
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d75fc               | lea                 esi, [ebp - 4]
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     

        $sequence_6 = { e9???????? 8b45f0 8d4de4 40 51 33d2 8d5df8 }
            // n = 7, score = 500
            //   e9????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   40                   | inc                 eax
            //   51                   | push                ecx
            //   33d2                 | xor                 edx, edx
            //   8d5df8               | lea                 ebx, [ebp - 8]

        $sequence_7 = { e8???????? 59 833d????????00 74ef e9???????? 8b0d???????? 83b93401000001 }
            // n = 7, score = 500
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   833d????????00       |                     
            //   74ef                 | je                  0xfffffff1
            //   e9????????           |                     
            //   8b0d????????         |                     
            //   83b93401000001       | cmp                 dword ptr [ecx + 0x134], 1

        $sequence_8 = { 8d75f0 e8???????? 8bc7 e8???????? 3c01 0f84d5020000 8d4dcc }
            // n = 7, score = 500
            //   8d75f0               | lea                 esi, [ebp - 0x10]
            //   e8????????           |                     
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   3c01                 | cmp                 al, 1
            //   0f84d5020000         | je                  0x2db
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]

        $sequence_9 = { 750a 6a01 8b7d88 e8???????? 0fb645e4 83f801 750a }
            // n = 7, score = 500
            //   750a                 | jne                 0xc
            //   6a01                 | push                1
            //   8b7d88               | mov                 edi, dword ptr [ebp - 0x78]
            //   e8????????           |                     
            //   0fb645e4             | movzx               eax, byte ptr [ebp - 0x1c]
            //   83f801               | cmp                 eax, 1
            //   750a                 | jne                 0xc

    condition:
        7 of them and filesize < 630784
}
