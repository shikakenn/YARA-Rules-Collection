rule win_doppeldridex_auto {

    meta:
        id = "7hUeEDlkYxhK6mRwT0iwhF"
        fingerprint = "v1_sha256_f94875582e8b5aa2ebc993fa0b95159a94408b6d25288caadf3c8433582dd0a1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.doppeldridex."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doppeldridex"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 01501c 015020 015024 01500c }
            // n = 4, score = 1200
            //   01501c               | add                 dword ptr [eax + 0x1c], edx
            //   015020               | add                 dword ptr [eax + 0x20], edx
            //   015024               | add                 dword ptr [eax + 0x24], edx
            //   01500c               | add                 dword ptr [eax + 0xc], edx

        $sequence_1 = { 01500c 833920 751c 8bc1 }
            // n = 4, score = 1200
            //   01500c               | add                 dword ptr [eax + 0xc], edx
            //   833920               | cmp                 dword ptr [ecx], 0x20
            //   751c                 | jne                 0x1e
            //   8bc1                 | mov                 eax, ecx

        $sequence_2 = { 011483 40 3b06 7cf8 }
            // n = 4, score = 1200
            //   011483               | add                 dword ptr [ebx + eax*4], edx
            //   40                   | inc                 eax
            //   3b06                 | cmp                 eax, dword ptr [esi]
            //   7cf8                 | jl                  0xfffffffa

        $sequence_3 = { 010c28 8b4e04 42 8d41f8 d1e8 }
            // n = 5, score = 1200
            //   010c28               | add                 dword ptr [eax + ebp], ecx
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   42                   | inc                 edx
            //   8d41f8               | lea                 eax, [ecx - 8]
            //   d1e8                 | shr                 eax, 1

        $sequence_4 = { 017c240c 3b5c2408 0f822affffff ff74240c }
            // n = 4, score = 1200
            //   017c240c             | add                 dword ptr [esp + 0xc], edi
            //   3b5c2408             | cmp                 ebx, dword ptr [esp + 8]
            //   0f822affffff         | jb                  0xffffff30
            //   ff74240c             | push                dword ptr [esp + 0xc]

        $sequence_5 = { 33d2 3b7c2414 0f4cd3 032c24 03ee 2bea }
            // n = 6, score = 1200
            //   33d2                 | xor                 edx, edx
            //   3b7c2414             | cmp                 edi, dword ptr [esp + 0x14]
            //   0f4cd3               | cmovl               edx, ebx
            //   032c24               | add                 ebp, dword ptr [esp]
            //   03ee                 | add                 ebp, esi
            //   2bea                 | sub                 ebp, edx

        $sequence_6 = { 030c24 0fbe01 88442458 85c0 }
            // n = 4, score = 1200
            //   030c24               | add                 ecx, dword ptr [esp]
            //   0fbe01               | movsx               eax, byte ptr [ecx]
            //   88442458             | mov                 byte ptr [esp + 0x58], al
            //   85c0                 | test                eax, eax

        $sequence_7 = { 0306 894218 47 3b7c2408 }
            // n = 4, score = 1200
            //   0306                 | add                 eax, dword ptr [esi]
            //   894218               | mov                 dword ptr [edx + 0x18], eax
            //   47                   | inc                 edi
            //   3b7c2408             | cmp                 edi, dword ptr [esp + 8]

        $sequence_8 = { 897dc4 8955c8 893424 c744240400000000 c744240864000000 898548ffffff }
            // n = 6, score = 100
            //   897dc4               | mov                 dword ptr [ebp - 0x3c], edi
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   893424               | mov                 dword ptr [esp], esi
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   c744240864000000     | mov                 dword ptr [esp + 8], 0x64
            //   898548ffffff         | mov                 dword ptr [ebp - 0xb8], eax

        $sequence_9 = { 8945d4 0f84b3feffff e9???????? 8b45e0 }
            // n = 4, score = 100
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   0f84b3feffff         | je                  0xfffffeb9
            //   e9????????           |                     
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_10 = { eb0c 8b45dc 6683785c03 7414 eb6e 8b45ec }
            // n = 6, score = 100
            //   eb0c                 | jmp                 0xe
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   6683785c03           | cmp                 word ptr [eax + 0x5c], 3
            //   7414                 | je                  0x16
            //   eb6e                 | jmp                 0x70
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]

        $sequence_11 = { 83fa00 89459c 8955e0 7475 e9???????? b801000000 8b4d98 }
            // n = 7, score = 100
            //   83fa00               | cmp                 edx, 0
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   7475                 | je                  0x77
            //   e9????????           |                     
            //   b801000000           | mov                 eax, 1
            //   8b4d98               | mov                 ecx, dword ptr [ebp - 0x68]

        $sequence_12 = { 8b5df0 81f330d7a128 8b4de8 8b541104 39da }
            // n = 5, score = 100
            //   8b5df0               | mov                 ebx, dword ptr [ebp - 0x10]
            //   81f330d7a128         | xor                 ebx, 0x28a1d730
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b541104             | mov                 edx, dword ptr [ecx + edx + 4]
            //   39da                 | cmp                 edx, ebx

        $sequence_13 = { 8955f8 ebe7 55 89e5 50 }
            // n = 5, score = 100
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   ebe7                 | jmp                 0xffffffe9
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   50                   | push                eax

        $sequence_14 = { 8945ec 894de8 897de4 742c eb0c }
            // n = 5, score = 100
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi
            //   742c                 | je                  0x2e
            //   eb0c                 | jmp                 0xe

        $sequence_15 = { 83fa20 0f92c4 8a6db3 20cd 20e5 f6c501 8955b4 }
            // n = 7, score = 100
            //   83fa20               | cmp                 edx, 0x20
            //   0f92c4               | setb                ah
            //   8a6db3               | mov                 ch, byte ptr [ebp - 0x4d]
            //   20cd                 | and                 ch, cl
            //   20e5                 | and                 ch, ah
            //   f6c501               | test                ch, 1
            //   8955b4               | mov                 dword ptr [ebp - 0x4c], edx

    condition:
        7 of them and filesize < 360448
}
