rule win_socelars_auto {

    meta:
        id = "4r2MJ6ko2q2qKj6FmVtWwI"
        fingerprint = "v1_sha256_b8094e8a90fbd4b228aeee4fe07a815ac53358ef07b587d100a6e2f0f5e01dbf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.socelars."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socelars"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f20f11542460 81ff5e010000 7e32 8a4c2415 8dbc24d0000000 33c0 888c24d0000000 }
            // n = 7, score = 100
            //   f20f11542460         | movsd               qword ptr [esp + 0x60], xmm2
            //   81ff5e010000         | cmp                 edi, 0x15e
            //   7e32                 | jle                 0x34
            //   8a4c2415             | mov                 cl, byte ptr [esp + 0x15]
            //   8dbc24d0000000       | lea                 edi, [esp + 0xd0]
            //   33c0                 | xor                 eax, eax
            //   888c24d0000000       | mov                 byte ptr [esp + 0xd0], cl

        $sequence_1 = { 8bec 56 8b7508 8b4608 85c0 7410 fe8850814f00 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12
            //   fe8850814f00         | dec                 byte ptr [eax + 0x4f8150]

        $sequence_2 = { f7d1 0b4db0 334dac ba04000000 6bc20d 034c05bc 8b55b4 }
            // n = 7, score = 100
            //   f7d1                 | not                 ecx
            //   0b4db0               | or                  ecx, dword ptr [ebp - 0x50]
            //   334dac               | xor                 ecx, dword ptr [ebp - 0x54]
            //   ba04000000           | mov                 edx, 4
            //   6bc20d               | imul                eax, edx, 0xd
            //   034c05bc             | add                 ecx, dword ptr [ebp + eax - 0x44]
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]

        $sequence_3 = { 8b4508 40 8939 ff463c 894638 8b5324 8b09 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   40                   | inc                 eax
            //   8939                 | mov                 dword ptr [ecx], edi
            //   ff463c               | inc                 dword ptr [esi + 0x3c]
            //   894638               | mov                 dword ptr [esi + 0x38], eax
            //   8b5324               | mov                 edx, dword ptr [ebx + 0x24]
            //   8b09                 | mov                 ecx, dword ptr [ecx]

        $sequence_4 = { e8???????? 807f4900 0f8583030000 837e5c00 750a 837e4c00 0f8473030000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   807f4900             | cmp                 byte ptr [edi + 0x49], 0
            //   0f8583030000         | jne                 0x389
            //   837e5c00             | cmp                 dword ptr [esi + 0x5c], 0
            //   750a                 | jne                 0xc
            //   837e4c00             | cmp                 dword ptr [esi + 0x4c], 0
            //   0f8473030000         | je                  0x379

        $sequence_5 = { eb09 83f9ff 0f84eb040000 8b4e08 8b460c 234f20 234724 }
            // n = 7, score = 100
            //   eb09                 | jmp                 0xb
            //   83f9ff               | cmp                 ecx, -1
            //   0f84eb040000         | je                  0x4f1
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]
            //   234f20               | and                 ecx, dword ptr [edi + 0x20]
            //   234724               | and                 eax, dword ptr [edi + 0x24]

        $sequence_6 = { eb05 e8???????? 8bf0 83c408 85f6 740d ff7508 }
            // n = 7, score = 100
            //   eb05                 | jmp                 7
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c408               | add                 esp, 8
            //   85f6                 | test                esi, esi
            //   740d                 | je                  0xf
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_7 = { e8???????? 8945a8 8b45e8 50 8b4de0 e8???????? 8945a4 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8945a8               | mov                 dword ptr [ebp - 0x58], eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   50                   | push                eax
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   e8????????           |                     
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax

        $sequence_8 = { e8???????? c645fc02 c685fbf8ffff00 68???????? 68???????? e8???????? 83c408 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   c685fbf8ffff00       | mov                 byte ptr [ebp - 0x705], 0
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_9 = { 8bcb e8???????? 8bf0 83fe11 0f85cf000000 8b7c241c e9???????? }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83fe11               | cmp                 esi, 0x11
            //   0f85cf000000         | jne                 0xd5
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   e9????????           |                     

    condition:
        7 of them and filesize < 2151424
}
