rule win_glasses_auto {

    meta:
        id = "1aRpEYFWgZjTi3GFmRPHiI"
        fingerprint = "v1_sha256_f33966ab45324eba7508399d9cadcd3a853fcf3a139e1b51ccdad3cd57192d5a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.glasses."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glasses"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd0 8d8d38f9ffff e8???????? 53 8d8d38f9ffff 898534f9ffff 51 }
            // n = 7, score = 100
            //   ffd0                 | call                eax
            //   8d8d38f9ffff         | lea                 ecx, [ebp - 0x6c8]
            //   e8????????           |                     
            //   53                   | push                ebx
            //   8d8d38f9ffff         | lea                 ecx, [ebp - 0x6c8]
            //   898534f9ffff         | mov                 dword ptr [ebp - 0x6cc], eax
            //   51                   | push                ecx

        $sequence_1 = { e8???????? 8d8d5cfaffff e8???????? 8bf8 33c0 89b5c0f9ffff 68c7000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8d5cfaffff         | lea                 ecx, [ebp - 0x5a4]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   33c0                 | xor                 eax, eax
            //   89b5c0f9ffff         | mov                 dword ptr [ebp - 0x640], esi
            //   68c7000000           | push                0xc7

        $sequence_2 = { e8???????? 8d8d58f7ffff c745fcffffffff e8???????? eb2e 8b8d94f7ffff 8a1439 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8d58f7ffff         | lea                 ecx, [ebp - 0x8a8]
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   e8????????           |                     
            //   eb2e                 | jmp                 0x30
            //   8b8d94f7ffff         | mov                 ecx, dword ptr [ebp - 0x86c]
            //   8a1439               | mov                 dl, byte ptr [ecx + edi]

        $sequence_3 = { e8???????? 83c404 80bea100000000 b301 0f8585000000 8b86a4000000 6a01 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   80bea100000000       | cmp                 byte ptr [esi + 0xa1], 0
            //   b301                 | mov                 bl, 1
            //   0f8585000000         | jne                 0x8b
            //   8b86a4000000         | mov                 eax, dword ptr [esi + 0xa4]
            //   6a01                 | push                1

        $sequence_4 = { e8???????? 8bf8 83c404 85ff 0f84dbfdffff 683b960000 8bcf }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c404               | add                 esp, 4
            //   85ff                 | test                edi, edi
            //   0f84dbfdffff         | je                  0xfffffde1
            //   683b960000           | push                0x963b
            //   8bcf                 | mov                 ecx, edi

        $sequence_5 = { e8???????? 8bf0 83c404 85f6 0f84add7ffff 681b010000 8bce }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c404               | add                 esp, 4
            //   85f6                 | test                esi, esi
            //   0f84add7ffff         | je                  0xffffd7b3
            //   681b010000           | push                0x11b
            //   8bce                 | mov                 ecx, esi

        $sequence_6 = { e8???????? 8986b4010000 e8???????? 8986e8010000 e8???????? 8986ec010000 8d4de8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8986b4010000         | mov                 dword ptr [esi + 0x1b4], eax
            //   e8????????           |                     
            //   8986e8010000         | mov                 dword ptr [esi + 0x1e8], eax
            //   e8????????           |                     
            //   8986ec010000         | mov                 dword ptr [esi + 0x1ec], eax
            //   8d4de8               | lea                 ecx, [ebp - 0x18]

        $sequence_7 = { e8???????? 8d8d58ffffff e8???????? 8d8d3cffffff c645fc04 e8???????? 837f3803 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d8d58ffffff         | lea                 ecx, [ebp - 0xa8]
            //   e8????????           |                     
            //   8d8d3cffffff         | lea                 ecx, [ebp - 0xc4]
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4
            //   e8????????           |                     
            //   837f3803             | cmp                 dword ptr [edi + 0x38], 3

        $sequence_8 = { c645fc01 e8???????? 8d4d98 c645fc00 e8???????? 8d4de4 c745fcffffffff }
            // n = 7, score = 100
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   8d4d98               | lea                 ecx, [ebp - 0x68]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff

        $sequence_9 = { eb07 e8???????? 8bf8 33f6 85ff 7e2b 8bff }
            // n = 7, score = 100
            //   eb07                 | jmp                 9
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   33f6                 | xor                 esi, esi
            //   85ff                 | test                edi, edi
            //   7e2b                 | jle                 0x2d
            //   8bff                 | mov                 edi, edi

    condition:
        7 of them and filesize < 4177920
}
