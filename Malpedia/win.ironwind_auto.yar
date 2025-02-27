rule win_ironwind_auto {

    meta:
        id = "7N4la4SB530K1uAaZIXWSj"
        fingerprint = "v1_sha256_df52b853e06a9bac2fed032f09d4a195b27f234efb72e316b71f02accfc6c4ed"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ironwind."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ironwind"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4d3926 7425 4c396718 751f 4c396720 7519 498b8f90110000 }
            // n = 7, score = 100
            //   4d3926               | lea                 eax, [0x2fb8]
            //   7425                 | dec                 eax
            //   4c396718             | mov                 dword ptr [edi + 0x1f8], ebx
            //   751f                 | dec                 eax
            //   4c396720             | mov                 dword ptr [ebx + 0x1180], eax
            //   7519                 | dec                 eax
            //   498b8f90110000       | mov                 dword ptr [ebx + 0x1188], edi

        $sequence_1 = { c7459401000000 498b5620 e8???????? 4c8d45b8 488bce 488d15fd5c0300 e8???????? }
            // n = 7, score = 100
            //   c7459401000000       | mov                 eax, dword ptr [esp + 0x60]
            //   498b5620             | je                  0x48a
            //   e8????????           |                     
            //   4c8d45b8             | cmp                 ecx, 0x10
            //   488bce               | je                  0x482
            //   488d15fd5c0300       | cmp                 ecx, 0x20
            //   e8????????           |                     

        $sequence_2 = { 498b4c3608 49892c36 ff15???????? 49896c3608 488bb3c80c0000 488bc6 48ffc7 }
            // n = 7, score = 100
            //   498b4c3608           | inc                 ecx
            //   49892c36             | push                edi
            //   ff15????????         |                     
            //   49896c3608           | dec                 eax
            //   488bb3c80c0000       | sub                 esp, 0x60
            //   488bc6               | dec                 esp
            //   48ffc7               | mov                 esp, dword ptr [ecx + 0xdf8]

        $sequence_3 = { 0f8582010000 48837f4800 7568 488b6f08 4885ed 744a 48635f10 }
            // n = 7, score = 100
            //   0f8582010000         | dec                 esp
            //   48837f4800           | mov                 esi, eax
            //   7568                 | dec                 eax
            //   488b6f08             | test                eax, eax
            //   4885ed               | je                  0x123c
            //   744a                 | dec                 eax
            //   48635f10             | mov                 edi, 0xffffffff

        $sequence_4 = { 488bce e8???????? b80f000000 e9???????? 4438a7db020000 418bc4 41b801000000 }
            // n = 7, score = 100
            //   488bce               | je                  0x7f4
            //   e8????????           |                     
            //   b80f000000           | dec                 eax
            //   e9????????           |                     
            //   4438a7db020000       | mov                 ecx, dword ptr [ebx + 0x11e0]
            //   418bc4               | dec                 esp
            //   41b801000000         | mov                 eax, dword ptr [esp + 0x78]

        $sequence_5 = { 488d15613e0500 e8???????? 488bf8 418bde 4885c0 0f84ab050000 440fb6bd08200000 }
            // n = 7, score = 100
            //   488d15613e0500       | inc                 esp
            //   e8????????           |                     
            //   488bf8               | mov                 ecx, dword ptr [ecx + 0x6b4]
            //   418bde               | sete                al
            //   4885c0               | dec                 ebp
            //   0f84ab050000         | cmp                 ebx, ecx
            //   440fb6bd08200000     | dec                 eax

        $sequence_6 = { 488d159df20300 488bcb e8???????? 4885c0 752b 448d4810 488bd6 }
            // n = 7, score = 100
            //   488d159df20300       | dec                 eax
            //   488bcb               | mov                 edx, eax
            //   e8????????           |                     
            //   4885c0               | dec                 eax
            //   752b                 | mov                 ecx, edi
            //   448d4810             | dec                 eax
            //   488bd6               | arpl                word ptr [edi + 0x2fc], ax

        $sequence_7 = { 4c8bc0 488d15ad180200 488bcd e8???????? 899d540d0000 c70637000000 48635720 }
            // n = 7, score = 100
            //   4c8bc0               | arpl                ax, bx
            //   488d15ad180200       | cmp                 ebx, 0x30
            //   488bcd               | ja                  0x123
            //   e8????????           |                     
            //   899d540d0000         | dec                 eax
            //   c70637000000         | mov                 ecx, dword ptr [ebp + 0x58]
            //   48635720             | inc                 esp

        $sequence_8 = { e9???????? 498b00 4885c0 790a b82b000000 e9???????? 48898120030000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   498b00               | mov                 byte ptr [ebx + 0x10a], 1
            //   4885c0               | lea                 eax, [ecx - 5]
            //   790a                 | jmp                 0xf98
            //   b82b000000           | dec                 eax
            //   e9????????           |                     
            //   48898120030000       | lea                 edx, [esp]

        $sequence_9 = { 410f94c7 4489bde0000000 4d8b4cc1f8 e8???????? 8bf8 85c0 0f85fffeffff }
            // n = 7, score = 100
            //   410f94c7             | dec                 eax
            //   4489bde0000000       | mov                 edx, dword ptr [esp + 0x88]
            //   4d8b4cc1f8           | dec                 eax
            //   e8????????           |                     
            //   8bf8                 | lea                 ecx, [0x43eb3]
            //   85c0                 | inc                 esp
            //   0f85fffeffff         | mov                 esi, eax

    condition:
        7 of them and filesize < 995328
}
