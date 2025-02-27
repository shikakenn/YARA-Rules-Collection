rule win_nemim_auto {

    meta:
        id = "77Ym3ZTFZOhW1znb3eDS7L"
        fingerprint = "v1_sha256_a74c5cc417011139586470805b653eee06eb07d9c80d556280876db9d2f1564f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nemim."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemim"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c1f905 8d04c0 be00800000 8b0c8d40604300 }
            // n = 4, score = 200
            //   c1f905               | sar                 ecx, 5
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   be00800000           | mov                 esi, 0x8000
            //   8b0c8d40604300       | mov                 ecx, dword ptr [ecx*4 + 0x436040]

        $sequence_1 = { 6a00 6a00 52 6801000080 ff15???????? 85c0 753f }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   52                   | push                edx
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   753f                 | jne                 0x41

        $sequence_2 = { 743a 8b9c243c010000 8b2d???????? 8d4c2434 53 51 ffd5 }
            // n = 7, score = 200
            //   743a                 | je                  0x3c
            //   8b9c243c010000       | mov                 ebx, dword ptr [esp + 0x13c]
            //   8b2d????????         |                     
            //   8d4c2434             | lea                 ecx, [esp + 0x34]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ffd5                 | call                ebp

        $sequence_3 = { 56 57 55 8b0c8504744300 }
            // n = 4, score = 200
            //   56                   | push                esi
            //   57                   | push                edi
            //   55                   | push                ebp
            //   8b0c8504744300       | mov                 ecx, dword ptr [eax*4 + 0x437404]

        $sequence_4 = { 68???????? 68???????? e8???????? 8bf8 83c408 85ff 0f84a2000000 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   83c408               | add                 esp, 8
            //   85ff                 | test                edi, edi
            //   0f84a2000000         | je                  0xa8

        $sequence_5 = { 8856fd 884eff 8b4c2414 c60600 }
            // n = 4, score = 200
            //   8856fd               | mov                 byte ptr [esi - 3], dl
            //   884eff               | mov                 byte ptr [esi - 1], cl
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   c60600               | mov                 byte ptr [esi], 0

        $sequence_6 = { 57 8b7c2410 b856555555 8d0cbd00000000 f7e9 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   8b7c2410             | mov                 edi, dword ptr [esp + 0x10]
            //   b856555555           | mov                 eax, 0x55555556
            //   8d0cbd00000000       | lea                 ecx, [edi*4]
            //   f7e9                 | imul                ecx

        $sequence_7 = { 8bc5 c1e005 ff90d0a74200 83c414 8bf8 83ff01 754b }
            // n = 7, score = 200
            //   8bc5                 | mov                 eax, ebp
            //   c1e005               | shl                 eax, 5
            //   ff90d0a74200         | call                dword ptr [eax + 0x42a7d0]
            //   83c414               | add                 esp, 0x14
            //   8bf8                 | mov                 edi, eax
            //   83ff01               | cmp                 edi, 1
            //   754b                 | jne                 0x4d

        $sequence_8 = { 8d058c5e4300 83780800 754e b741 }
            // n = 4, score = 200
            //   8d058c5e4300         | lea                 eax, [0x435e8c]
            //   83780800             | cmp                 dword ptr [eax + 8], 0
            //   754e                 | jne                 0x50
            //   b741                 | mov                 bh, 0x41

        $sequence_9 = { 68???????? 53 ff15???????? 6a5c 68???????? }
            // n = 5, score = 200
            //   68????????           |                     
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   6a5c                 | push                0x5c
            //   68????????           |                     

    condition:
        7 of them and filesize < 499712
}
