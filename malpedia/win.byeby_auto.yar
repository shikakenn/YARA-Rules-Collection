rule win_byeby_auto {

    meta:
        id = "1pL8hvcoOizKrkJIDkEGty"
        fingerprint = "v1_sha256_50a28d5ba51c4cf2da918fb2e13d81e48eb5727c5e9589337c757040c753f599"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.byeby."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.byeby"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb0c befdffffff eb05 befeffffff }
            // n = 4, score = 100
            //   eb0c                 | jmp                 0xe
            //   befdffffff           | mov                 esi, 0xfffffffd
            //   eb05                 | jmp                 7
            //   befeffffff           | mov                 esi, 0xfffffffe

        $sequence_1 = { 8907 ff15???????? 40 8d8c243f0a0000 034c241c 8d7f04 03f0 }
            // n = 7, score = 100
            //   8907                 | mov                 dword ptr [edi], eax
            //   ff15????????         |                     
            //   40                   | inc                 eax
            //   8d8c243f0a0000       | lea                 ecx, [esp + 0xa3f]
            //   034c241c             | add                 ecx, dword ptr [esp + 0x1c]
            //   8d7f04               | lea                 edi, [edi + 4]
            //   03f0                 | add                 esi, eax

        $sequence_2 = { 741a 6a00 8bc7 2bc6 50 8b44241c 03c6 }
            // n = 7, score = 100
            //   741a                 | je                  0x1c
            //   6a00                 | push                0
            //   8bc7                 | mov                 eax, edi
            //   2bc6                 | sub                 eax, esi
            //   50                   | push                eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   03c6                 | add                 eax, esi

        $sequence_3 = { c745e400000000 85c9 7404 33ff eb03 8d7e48 }
            // n = 6, score = 100
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   85c9                 | test                ecx, ecx
            //   7404                 | je                  6
            //   33ff                 | xor                 edi, edi
            //   eb03                 | jmp                 5
            //   8d7e48               | lea                 edi, [esi + 0x48]

        $sequence_4 = { ff15???????? 8b35???????? 8d84243c060000 50 8d8424380a0000 50 ffd6 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8d84243c060000       | lea                 eax, [esp + 0x63c]
            //   50                   | push                eax
            //   8d8424380a0000       | lea                 eax, [esp + 0xa38]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_5 = { 80bc05e7feffff5c 7411 8d85e8feffff 50 ffd6 }
            // n = 5, score = 100
            //   80bc05e7feffff5c     | cmp                 byte ptr [ebp + eax - 0x119], 0x5c
            //   7411                 | je                  0x13
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_6 = { 50 57 ff15???????? 85c0 7461 8d642400 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7461                 | je                  0x63
            //   8d642400             | lea                 esp, [esp]

        $sequence_7 = { 8d85a8feffff 50 8d8584fcffff 50 6a00 }
            // n = 5, score = 100
            //   8d85a8feffff         | lea                 eax, [ebp - 0x158]
            //   50                   | push                eax
            //   8d8584fcffff         | lea                 eax, [ebp - 0x37c]
            //   50                   | push                eax
            //   6a00                 | push                0

        $sequence_8 = { 0fbec2 0fb680d0450110 83e00f eb02 33c0 8bbdc8fdffff 6bc009 }
            // n = 7, score = 100
            //   0fbec2               | movsx               eax, dl
            //   0fb680d0450110       | movzx               eax, byte ptr [eax + 0x100145d0]
            //   83e00f               | and                 eax, 0xf
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   8bbdc8fdffff         | mov                 edi, dword ptr [ebp - 0x238]
            //   6bc009               | imul                eax, eax, 9

        $sequence_9 = { 57 ff15???????? 85c0 0f84f6010000 8b542418 03542414 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84f6010000         | je                  0x1fc
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   03542414             | add                 edx, dword ptr [esp + 0x14]

    condition:
        7 of them and filesize < 253952
}
