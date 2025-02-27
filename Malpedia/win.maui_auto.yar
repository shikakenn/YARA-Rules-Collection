rule win_maui_auto {

    meta:
        id = "38wPwPATRcYQBr3uRHFSd"
        fingerprint = "v1_sha256_c832f22e1bbb1398fc1d6a8199e3732cb12b403d9a2eb2103c84e67dba24e6f9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.maui."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maui"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bc8 23c7 f7d1 23cd 8b6c2438 0bc8 8bd6 }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   23c7                 | and                 eax, edi
            //   f7d1                 | not                 ecx
            //   23cd                 | and                 ecx, ebp
            //   8b6c2438             | mov                 ebp, dword ptr [esp + 0x38]
            //   0bc8                 | or                  ecx, eax
            //   8bd6                 | mov                 edx, esi

        $sequence_1 = { e8???????? a1???????? 33c4 898424bc000000 8b8424c4000000 8b8c24d0000000 8b9424d4000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   898424bc000000       | mov                 dword ptr [esp + 0xbc], eax
            //   8b8424c4000000       | mov                 eax, dword ptr [esp + 0xc4]
            //   8b8c24d0000000       | mov                 ecx, dword ptr [esp + 0xd0]
            //   8b9424d4000000       | mov                 edx, dword ptr [esp + 0xd4]

        $sequence_2 = { 309630934b00 46 3bf3 7202 33f6 8d50ff 3bd7 }
            // n = 7, score = 100
            //   309630934b00         | xor                 byte ptr [esi + 0x4b9330], dl
            //   46                   | inc                 esi
            //   3bf3                 | cmp                 esi, ebx
            //   7202                 | jb                  4
            //   33f6                 | xor                 esi, esi
            //   8d50ff               | lea                 edx, [eax - 1]
            //   3bd7                 | cmp                 edx, edi

        $sequence_3 = { 743b 8b4910 85c9 7434 8b9c24ec000000 8bf0 894c2428 }
            // n = 7, score = 100
            //   743b                 | je                  0x3d
            //   8b4910               | mov                 ecx, dword ptr [ecx + 0x10]
            //   85c9                 | test                ecx, ecx
            //   7434                 | je                  0x36
            //   8b9c24ec000000       | mov                 ebx, dword ptr [esp + 0xec]
            //   8bf0                 | mov                 esi, eax
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx

        $sequence_4 = { 0f84c5fdffff 8b4c2440 b801000000 85c9 0f84b8fdffff 8b542418 }
            // n = 6, score = 100
            //   0f84c5fdffff         | je                  0xfffffdcb
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   b801000000           | mov                 eax, 1
            //   85c9                 | test                ecx, ecx
            //   0f84b8fdffff         | je                  0xfffffdbe
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]

        $sequence_5 = { 6814030000 68???????? 6a44 e9???????? 6822030000 68???????? 6a41 }
            // n = 7, score = 100
            //   6814030000           | push                0x314
            //   68????????           |                     
            //   6a44                 | push                0x44
            //   e9????????           |                     
            //   6822030000           | push                0x322
            //   68????????           |                     
            //   6a41                 | push                0x41

        $sequence_6 = { 83c414 5f 5e c3 8b542414 8b460c 52 }
            // n = 7, score = 100
            //   83c414               | add                 esp, 0x14
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   52                   | push                edx

        $sequence_7 = { 89442418 e8???????? 8b4c2418 83c408 c744241001000000 3bc8 7408 }
            // n = 7, score = 100
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   e8????????           |                     
            //   8b4c2418             | mov                 ecx, dword ptr [esp + 0x18]
            //   83c408               | add                 esp, 8
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1
            //   3bc8                 | cmp                 ecx, eax
            //   7408                 | je                  0xa

        $sequence_8 = { 83c414 eb49 8b4714 56 68d0020000 83c008 68???????? }
            // n = 7, score = 100
            //   83c414               | add                 esp, 0x14
            //   eb49                 | jmp                 0x4b
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]
            //   56                   | push                esi
            //   68d0020000           | push                0x2d0
            //   83c008               | add                 eax, 8
            //   68????????           |                     

        $sequence_9 = { 755a 6852010000 68???????? 6a20 6a69 6a21 e8???????? }
            // n = 7, score = 100
            //   755a                 | jne                 0x5c
            //   6852010000           | push                0x152
            //   68????????           |                     
            //   6a20                 | push                0x20
            //   6a69                 | push                0x69
            //   6a21                 | push                0x21
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1616896
}
