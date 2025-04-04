rule win_glassrat_auto {

    meta:
        id = "xTSwtd7ooj9oxqUprWy0a"
        fingerprint = "v1_sha256_4ee9c1e6fb6f5290f1ce6d0e335f981f784c2b61e1aa9e3c4c33ebb2644983ee"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.glassrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glassrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 56 53 8bf1 53 6a01 }
            // n = 5, score = 200
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8bf1                 | mov                 esi, ecx
            //   53                   | push                ebx
            //   6a01                 | push                1

        $sequence_1 = { 50 e8???????? 84c0 754b 6860ea0000 ff15???????? 8d8c242c010000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   754b                 | jne                 0x4d
            //   6860ea0000           | push                0xea60
            //   ff15????????         |                     
            //   8d8c242c010000       | lea                 ecx, [esp + 0x12c]

        $sequence_2 = { f3a4 741a 6a02 50 ff15???????? 8b4d04 51 }
            // n = 7, score = 200
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   741a                 | je                  0x1c
            //   6a02                 | push                2
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4d04               | mov                 ecx, dword ptr [ebp + 4]
            //   51                   | push                ecx

        $sequence_3 = { 33c0 8b5504 8944241d 8d4c241c 89442421 c644241c00 89442425 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8b5504               | mov                 edx, dword ptr [ebp + 4]
            //   8944241d             | mov                 dword ptr [esp + 0x1d], eax
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   89442421             | mov                 dword ptr [esp + 0x21], eax
            //   c644241c00           | mov                 byte ptr [esp + 0x1c], 0
            //   89442425             | mov                 dword ptr [esp + 0x25], eax

        $sequence_4 = { 84c0 7404 b001 eb1e }
            // n = 4, score = 200
            //   84c0                 | test                al, al
            //   7404                 | je                  6
            //   b001                 | mov                 al, 1
            //   eb1e                 | jmp                 0x20

        $sequence_5 = { 50 51 ffd3 85c0 7e0a 2bf0 03f8 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   7e0a                 | jle                 0xc
            //   2bf0                 | sub                 esi, eax
            //   03f8                 | add                 edi, eax

        $sequence_6 = { 76cd b900080000 33c0 8dbdd8dfffff f3ab }
            // n = 5, score = 200
            //   76cd                 | jbe                 0xffffffcf
            //   b900080000           | mov                 ecx, 0x800
            //   33c0                 | xor                 eax, eax
            //   8dbdd8dfffff         | lea                 edi, [ebp - 0x2028]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_7 = { ff15???????? 8b4e34 6a00 51 ffd7 8b4618 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8b4e34               | mov                 ecx, dword ptr [esi + 0x34]
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]

        $sequence_8 = { f3a5 8bc8 33c0 83e103 c745fc00000000 f3a4 }
            // n = 6, score = 200
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bc8                 | mov                 ecx, eax
            //   33c0                 | xor                 eax, eax
            //   83e103               | and                 ecx, 3
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]

        $sequence_9 = { 6a00 ff15???????? a1???????? 8b15???????? 8b0d???????? 89442408 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   a1????????           |                     
            //   8b15????????         |                     
            //   8b0d????????         |                     
            //   89442408             | mov                 dword ptr [esp + 8], eax

    condition:
        7 of them and filesize < 81920
}
