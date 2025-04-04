rule win_innaput_rat_auto {

    meta:
        id = "13nvMprY2oQVb1klwZxAR"
        fingerprint = "v1_sha256_9fc4a0f22b0936282c888c32e9151fce9421447e6433604a7df7c0949331d6ed"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.innaput_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.innaput_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3bc3 751b 53 53 53 6a06 }
            // n = 6, score = 500
            //   3bc3                 | cmp                 eax, ebx
            //   751b                 | jne                 0x1d
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a06                 | push                6

        $sequence_1 = { ffd7 8b4510 898618060000 8b4514 8b00 89861c060000 }
            // n = 6, score = 500
            //   ffd7                 | call                edi
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   898618060000         | mov                 dword ptr [esi + 0x618], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   89861c060000         | mov                 dword ptr [esi + 0x61c], eax

        $sequence_2 = { 740f 8b4d08 e8???????? 3b450c 72d9 eb02 }
            // n = 6, score = 500
            //   740f                 | je                  0x11
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   72d9                 | jb                  0xffffffdb
            //   eb02                 | jmp                 4

        $sequence_3 = { 50 56 ff15???????? 89be14040000 }
            // n = 4, score = 500
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   89be14040000         | mov                 dword ptr [esi + 0x414], edi

        $sequence_4 = { 8b4d08 e8???????? 3b450c 72d9 }
            // n = 4, score = 500
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   72d9                 | jb                  0xffffffdb

        $sequence_5 = { ff5704 59 8b0e 894104 8b06 }
            // n = 5, score = 500
            //   ff5704               | call                dword ptr [edi + 4]
            //   59                   | pop                 ecx
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_6 = { 53 53 53 6a06 6a01 6a02 ff15???????? }
            // n = 7, score = 500
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   6a06                 | push                6
            //   6a01                 | push                1
            //   6a02                 | push                2
            //   ff15????????         |                     

        $sequence_7 = { 8d8608020000 50 ffd7 8b4510 898618060000 }
            // n = 5, score = 500
            //   8d8608020000         | lea                 eax, [esi + 0x208]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   898618060000         | mov                 dword ptr [esi + 0x618], eax

        $sequence_8 = { 85c0 7413 3bc6 740f 8b4d08 e8???????? 3b450c }
            // n = 7, score = 500
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   3bc6                 | cmp                 eax, esi
            //   740f                 | je                  0x11
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]

        $sequence_9 = { 391e 75fa 6a0c ff5704 59 8906 3bc3 }
            // n = 7, score = 500
            //   391e                 | cmp                 dword ptr [esi], ebx
            //   75fa                 | jne                 0xfffffffc
            //   6a0c                 | push                0xc
            //   ff5704               | call                dword ptr [edi + 4]
            //   59                   | pop                 ecx
            //   8906                 | mov                 dword ptr [esi], eax
            //   3bc3                 | cmp                 eax, ebx

    condition:
        7 of them and filesize < 73728
}
