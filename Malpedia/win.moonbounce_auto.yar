rule win_moonbounce_auto {

    meta:
        id = "5yRmgh463g6aYIGy6e41PK"
        fingerprint = "v1_sha256_c88f40d1d857bf1c76177c0c7eb43f16650b71d1b80bdf0f0745bd71c4b7c892"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.moonbounce."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moonbounce"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b4120 83c114 894df8 85c0 0f857bffffff eb04 }
            // n = 6, score = 100
            //   8b4120               | mov                 eax, dword ptr [ecx + 0x20]
            //   83c114               | add                 ecx, 0x14
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   85c0                 | test                eax, eax
            //   0f857bffffff         | jne                 0xffffff81
            //   eb04                 | jmp                 6

        $sequence_1 = { f7c2feffffff 7640 eb03 8b4df0 8b5508 }
            // n = 5, score = 100
            //   f7c2feffffff         | test                edx, 0xfffffffe
            //   7640                 | jbe                 0x42
            //   eb03                 | jmp                 5
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

        $sequence_2 = { 50 ffd6 8b4310 33f6 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   33f6                 | xor                 esi, esi

        $sequence_3 = { ff15???????? 57 57 83c60c }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   57                   | push                edi
            //   57                   | push                edi
            //   83c60c               | add                 esi, 0xc

        $sequence_4 = { 7439 3bc6 7435 6a30 }
            // n = 4, score = 100
            //   7439                 | je                  0x3b
            //   3bc6                 | cmp                 eax, esi
            //   7435                 | je                  0x37
            //   6a30                 | push                0x30

        $sequence_5 = { 55 8bec 83ec30 53 33db 53 }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec30               | sub                 esp, 0x30
            //   53                   | push                ebx
            //   33db                 | xor                 ebx, ebx
            //   53                   | push                ebx

        $sequence_6 = { 56 8b30 57 8b7d08 6a05 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   6a05                 | push                5

        $sequence_7 = { 33d2 8d443018 663b5606 7342 }
            // n = 4, score = 100
            //   33d2                 | xor                 edx, edx
            //   8d443018             | lea                 eax, [eax + esi + 0x18]
            //   663b5606             | cmp                 dx, word ptr [esi + 6]
            //   7342                 | jae                 0x44

        $sequence_8 = { 50 e8???????? 8b7d08 81c700080000 b980000000 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   81c700080000         | add                 edi, 0x800
            //   b980000000           | mov                 ecx, 0x80

        $sequence_9 = { c745f4d2070100 895dec ff15???????? 53 6a01 53 }
            // n = 6, score = 100
            //   c745f4d2070100       | mov                 dword ptr [ebp - 0xc], 0x107d2
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   6a01                 | push                1
            //   53                   | push                ebx

    condition:
        7 of them and filesize < 70912
}
