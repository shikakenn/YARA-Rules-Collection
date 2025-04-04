rule win_sierras_auto {

    meta:
        id = "3f8QQH9jdiSwB9pecJZt46"
        fingerprint = "v1_sha256_c05b0e9c28fed253d00c96c986fab4dbaf0e644651c700ec0227f1b00097c981"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sierras."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sierras"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b8698010000 5e c3 56 8bf1 }
            // n = 5, score = 200
            //   8b8698010000         | mov                 eax, dword ptr [esi + 0x198]
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx

        $sequence_1 = { f3ab 8bce aa e8???????? }
            // n = 4, score = 200
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8bce                 | mov                 ecx, esi
            //   aa                   | stosb               byte ptr es:[edi], al
            //   e8????????           |                     

        $sequence_2 = { 33d2 eb19 8b0d???????? 2bc8 }
            // n = 4, score = 200
            //   33d2                 | xor                 edx, edx
            //   eb19                 | jmp                 0x1b
            //   8b0d????????         |                     
            //   2bc8                 | sub                 ecx, eax

        $sequence_3 = { 56 8bf1 e8???????? 8d8614010000 5e c3 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   8d8614010000         | lea                 eax, [esi + 0x114]
            //   5e                   | pop                 esi
            //   c3                   | ret                 

        $sequence_4 = { c705????????01000000 a3???????? a3???????? ff15???????? 85c0 }
            // n = 5, score = 200
            //   c705????????01000000     |     
            //   a3????????           |                     
            //   a3????????           |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 33c0 5b 81c474010000 c21000 56 68???????? }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   81c474010000         | add                 esp, 0x174
            //   c21000               | ret                 0x10
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_6 = { 397d08 897dfc 0f8cc0000000 837d0801 7e58 837d0803 0f8fb0000000 }
            // n = 7, score = 200
            //   397d08               | cmp                 dword ptr [ebp + 8], edi
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   0f8cc0000000         | jl                  0xc6
            //   837d0801             | cmp                 dword ptr [ebp + 8], 1
            //   7e58                 | jle                 0x5a
            //   837d0803             | cmp                 dword ptr [ebp + 8], 3
            //   0f8fb0000000         | jg                  0xb6

        $sequence_7 = { 8bfa 83c9ff 33c0 8d9c2498000000 }
            // n = 4, score = 200
            //   8bfa                 | mov                 edi, edx
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8d9c2498000000       | lea                 ebx, [esp + 0x98]

        $sequence_8 = { 83c302 f3a5 8bc8 83e103 f3a4 8bbc2410040000 }
            // n = 6, score = 200
            //   83c302               | add                 ebx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8bbc2410040000       | mov                 edi, dword ptr [esp + 0x410]

        $sequence_9 = { 51 e8???????? 83c40c 8d542400 6a01 6a00 52 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d542400             | lea                 edx, [esp]
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   52                   | push                edx

        $sequence_10 = { f3a4 8b0d???????? 8b15???????? 2bd1 b8abaaaa2a }
            // n = 5, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b0d????????         |                     
            //   8b15????????         |                     
            //   2bd1                 | sub                 edx, ecx
            //   b8abaaaa2a           | mov                 eax, 0x2aaaaaab

        $sequence_11 = { e8???????? 6a00 56 ff7514 8d4de0 e8???????? 0175f0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   e8????????           |                     
            //   0175f0               | add                 dword ptr [ebp - 0x10], esi

        $sequence_12 = { 8d1440 a1???????? c1e205 03d6 }
            // n = 4, score = 200
            //   8d1440               | lea                 edx, [eax + eax*2]
            //   a1????????           |                     
            //   c1e205               | shl                 edx, 5
            //   03d6                 | add                 edx, esi

        $sequence_13 = { 8b450c 7511 8b4dec 03c7 }
            // n = 4, score = 200
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   7511                 | jne                 0x13
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   03c7                 | add                 eax, edi

        $sequence_14 = { 83e103 f3a4 ffd3 50 68???????? }
            // n = 5, score = 200
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   ffd3                 | call                ebx
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_15 = { 837d0803 0f8fb0000000 397d10 897df0 0f86a4000000 8b7d14 }
            // n = 6, score = 200
            //   837d0803             | cmp                 dword ptr [ebp + 8], 3
            //   0f8fb0000000         | jg                  0xb6
            //   397d10               | cmp                 dword ptr [ebp + 0x10], edi
            //   897df0               | mov                 dword ptr [ebp - 0x10], edi
            //   0f86a4000000         | jbe                 0xaa
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]

    condition:
        7 of them and filesize < 131072
}
