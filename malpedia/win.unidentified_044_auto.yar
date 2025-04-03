rule win_unidentified_044_auto {

    meta:
        id = "5FGtKiUfDkmeNuOyuZDPnR"
        fingerprint = "v1_sha256_bba754b0708d8dcd8392b060bb16bcb2ec72e2dcb75dae26c5459c6dda294679"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_044."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_044"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 0f858afeffff e8???????? 5f 5e }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   0f858afeffff         | jne                 0xfffffe90
            //   e8????????           |                     
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_1 = { 53 32db 381d???????? 761f 56 8b35???????? 0fb6c3 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   32db                 | xor                 bl, bl
            //   381d????????         |                     
            //   761f                 | jbe                 0x21
            //   56                   | push                esi
            //   8b35????????         |                     
            //   0fb6c3               | movzx               eax, bl

        $sequence_2 = { 83f8ff 755f ff15???????? 3d1e270000 7552 }
            // n = 5, score = 100
            //   83f8ff               | cmp                 eax, -1
            //   755f                 | jne                 0x61
            //   ff15????????         |                     
            //   3d1e270000           | cmp                 eax, 0x271e
            //   7552                 | jne                 0x54

        $sequence_3 = { 893b 83ffff 7456 3935???????? 0f95c0 0fb6c8 }
            // n = 6, score = 100
            //   893b                 | mov                 dword ptr [ebx], edi
            //   83ffff               | cmp                 edi, -1
            //   7456                 | je                  0x58
            //   3935????????         |                     
            //   0f95c0               | setne               al
            //   0fb6c8               | movzx               ecx, al

        $sequence_4 = { 8bff 0fb74c7468 0fb717 0fafc8 8be9 81e5ffff0000 2bd5 }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   0fb74c7468           | movzx               ecx, word ptr [esp + esi*2 + 0x68]
            //   0fb717               | movzx               edx, word ptr [edi]
            //   0fafc8               | imul                ecx, eax
            //   8be9                 | mov                 ebp, ecx
            //   81e5ffff0000         | and                 ebp, 0xffff
            //   2bd5                 | sub                 edx, ebp

        $sequence_5 = { 55 56 8bf0 803e00 8be8 }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   803e00               | cmp                 byte ptr [esi], 0
            //   8be8                 | mov                 ebp, eax

        $sequence_6 = { 8d4c245c 51 6a00 c744246401000000 89742468 ffd5 85c0 }
            // n = 7, score = 100
            //   8d4c245c             | lea                 ecx, [esp + 0x5c]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   c744246401000000     | mov                 dword ptr [esp + 0x64], 1
            //   89742468             | mov                 dword ptr [esp + 0x68], esi
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax

        $sequence_7 = { c7460403000000 ffd3 5b 5f }
            // n = 4, score = 100
            //   c7460403000000       | mov                 dword ptr [esi + 4], 3
            //   ffd3                 | call                ebx
            //   5b                   | pop                 ebx
            //   5f                   | pop                 edi

        $sequence_8 = { 8d4c242c 51 e8???????? 8bbc24ec000000 668b4706 be10000000 2bf2 }
            // n = 7, score = 100
            //   8d4c242c             | lea                 ecx, [esp + 0x2c]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8bbc24ec000000       | mov                 edi, dword ptr [esp + 0xec]
            //   668b4706             | mov                 ax, word ptr [edi + 6]
            //   be10000000           | mov                 esi, 0x10
            //   2bf2                 | sub                 esi, edx

        $sequence_9 = { 7505 b8???????? e8???????? a1???????? 56 }
            // n = 5, score = 100
            //   7505                 | jne                 7
            //   b8????????           |                     
            //   e8????????           |                     
            //   a1????????           |                     
            //   56                   | push                esi

    condition:
        7 of them and filesize < 90112
}
