rule win_minitypeframe_auto {

    meta:
        id = "6OEZB9pvw1UeEXO1A408jH"
        fingerprint = "v1_sha256_8864a5220eda366ec3f0b791c455ecd5bc17a2ac1068453ffa5046f89df1e064"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.minitypeframe."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.minitypeframe"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85c0 750d c744246c87010000 e9???????? 83fb21 753b 8b44245c }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   c744246c87010000     | mov                 dword ptr [esp + 0x6c], 0x187
            //   e9????????           |                     
            //   83fb21               | cmp                 ebx, 0x21
            //   753b                 | jne                 0x3d
            //   8b44245c             | mov                 eax, dword ptr [esp + 0x5c]

        $sequence_1 = { 50 8d542434 51 52 e8???????? 83c41c 8d44241c }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8d44241c             | lea                 eax, [esp + 0x1c]

        $sequence_2 = { c684248c00000034 c684248d000000a3 c684248e00000038 c684248f00000037 c684249000000008 c68424910000007f c6842492000000c7 }
            // n = 7, score = 100
            //   c684248c00000034     | mov                 byte ptr [esp + 0x8c], 0x34
            //   c684248d000000a3     | mov                 byte ptr [esp + 0x8d], 0xa3
            //   c684248e00000038     | mov                 byte ptr [esp + 0x8e], 0x38
            //   c684248f00000037     | mov                 byte ptr [esp + 0x8f], 0x37
            //   c684249000000008     | mov                 byte ptr [esp + 0x90], 8
            //   c68424910000007f     | mov                 byte ptr [esp + 0x91], 0x7f
            //   c6842492000000c7     | mov                 byte ptr [esp + 0x92], 0xc7

        $sequence_3 = { 8d8c24fc000000 50 51 e8???????? 83c41c 8b86cc000000 85c0 }
            // n = 7, score = 100
            //   8d8c24fc000000       | lea                 ecx, [esp + 0xfc]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8b86cc000000         | mov                 eax, dword ptr [esi + 0xcc]
            //   85c0                 | test                eax, eax

        $sequence_4 = { 7521 6a01 8d442410 6829800000 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   7521                 | jne                 0x23
            //   6a01                 | push                1
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   6829800000           | push                0x8029
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_5 = { 8d049560740a10 50 ff500c 83c40c 5e 83c41c c3 }
            // n = 7, score = 100
            //   8d049560740a10       | lea                 eax, [edx*4 + 0x100a7460]
            //   50                   | push                eax
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   83c40c               | add                 esp, 0xc
            //   5e                   | pop                 esi
            //   83c41c               | add                 esp, 0x1c
            //   c3                   | ret                 

        $sequence_6 = { 51 e8???????? 8d54243c 8d8424a4000000 52 50 }
            // n = 6, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8d54243c             | lea                 edx, [esp + 0x3c]
            //   8d8424a4000000       | lea                 eax, [esp + 0xa4]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_7 = { 895c2434 8b542444 8b44245c 89542464 }
            // n = 4, score = 100
            //   895c2434             | mov                 dword ptr [esp + 0x34], ebx
            //   8b542444             | mov                 edx, dword ptr [esp + 0x44]
            //   8b44245c             | mov                 eax, dword ptr [esp + 0x5c]
            //   89542464             | mov                 dword ptr [esp + 0x64], edx

        $sequence_8 = { 8b542454 894c2434 8b0d???????? 89442430 8b442458 51 57 }
            // n = 7, score = 100
            //   8b542454             | mov                 edx, dword ptr [esp + 0x54]
            //   894c2434             | mov                 dword ptr [esp + 0x34], ecx
            //   8b0d????????         |                     
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   8b442458             | mov                 eax, dword ptr [esp + 0x58]
            //   51                   | push                ecx
            //   57                   | push                edi

        $sequence_9 = { 8d8c24c8000000 85c9 7421 8d9424c8000000 55 52 e8???????? }
            // n = 7, score = 100
            //   8d8c24c8000000       | lea                 ecx, [esp + 0xc8]
            //   85c9                 | test                ecx, ecx
            //   7421                 | je                  0x23
            //   8d9424c8000000       | lea                 edx, [esp + 0xc8]
            //   55                   | push                ebp
            //   52                   | push                edx
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1589248
}
