rule win_arkei_stealer_auto {

    meta:
        id = "2pUepXIyPTGWQjCPYpmlQ7"
        fingerprint = "v1_sha256_fe6b8a6d2dda0769d1bf75ba6fd29670ffe1d15e24be98e7feb6639e87efec8a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.arkei_stealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.arkei_stealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8945e8 ffd3 6a0a 57 }
            // n = 4, score = 400
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   ffd3                 | call                ebx
            //   6a0a                 | push                0xa
            //   57                   | push                edi

        $sequence_1 = { 33ff 50 57 897e10 894614 }
            // n = 5, score = 400
            //   33ff                 | xor                 edi, edi
            //   50                   | push                eax
            //   57                   | push                edi
            //   897e10               | mov                 dword ptr [esi + 0x10], edi
            //   894614               | mov                 dword ptr [esi + 0x14], eax

        $sequence_2 = { 6a00 ffd6 8b55e8 52 6a00 ffd6 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   ffd6                 | call                esi
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   ffd6                 | call                esi

        $sequence_3 = { 6a00 8d4de4 51 6a0e 8d55ec 52 }
            // n = 6, score = 400
            //   6a00                 | push                0
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   51                   | push                ecx
            //   6a0e                 | push                0xe
            //   8d55ec               | lea                 edx, [ebp - 0x14]
            //   52                   | push                edx

        $sequence_4 = { 57 8945e8 ffd3 6a0a 57 8bf0 ffd3 }
            // n = 7, score = 400
            //   57                   | push                edi
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   ffd3                 | call                ebx
            //   6a0a                 | push                0xa
            //   57                   | push                edi
            //   8bf0                 | mov                 esi, eax
            //   ffd3                 | call                ebx

        $sequence_5 = { c3 50 8b45e8 50 }
            // n = 4, score = 400
            //   c3                   | ret                 
            //   50                   | push                eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax

        $sequence_6 = { 8b45e8 50 ff15???????? 85c0 74de 8b4de8 682000cc00 }
            // n = 7, score = 400
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74de                 | je                  0xffffffe0
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   682000cc00           | push                0xcc0020

        $sequence_7 = { e9???????? 83f810 770a bb10000000 e9???????? 83f818 0f8783010000 }
            // n = 7, score = 400
            //   e9????????           |                     
            //   83f810               | cmp                 eax, 0x10
            //   770a                 | ja                  0xc
            //   bb10000000           | mov                 ebx, 0x10
            //   e9????????           |                     
            //   83f818               | cmp                 eax, 0x18
            //   0f8783010000         | ja                  0x189

        $sequence_8 = { 8d448a0e 6a00 8d4de4 51 }
            // n = 4, score = 400
            //   8d448a0e             | lea                 eax, [edx + ecx*4 + 0xe]
            //   6a00                 | push                0
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]
            //   51                   | push                ecx

        $sequence_9 = { 51 ff15???????? 85c0 0f84c4feffff 57 6880000000 }
            // n = 6, score = 400
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84c4feffff         | je                  0xfffffeca
            //   57                   | push                edi
            //   6880000000           | push                0x80

    condition:
        7 of them and filesize < 1744896
}
