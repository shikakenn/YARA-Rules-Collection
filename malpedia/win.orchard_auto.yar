rule win_orchard_auto {

    meta:
        id = "43GFelBYFxGmbbXxKC9rWH"
        fingerprint = "v1_sha256_138080fd95f8adafa6f2759bdbd81f59c5234a21d6fcbf8907de2c121b106fe9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.orchard."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orchard"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b07 8b4804 8d41e0 894439fc c745fc07000000 }
            // n = 5, score = 200
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   8d41e0               | lea                 eax, [ecx - 0x20]
            //   894439fc             | mov                 dword ptr [ecx + edi - 4], eax
            //   c745fc07000000       | mov                 dword ptr [ebp - 4], 7

        $sequence_1 = { 6a00 83c804 50 e8???????? 8b55e0 8b7de8 }
            // n = 6, score = 200
            //   6a00                 | push                0
            //   83c804               | or                  eax, 4
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b55e0               | mov                 edx, dword ptr [ebp - 0x20]
            //   8b7de8               | mov                 edi, dword ptr [ebp - 0x18]

        $sequence_2 = { 83c404 e8???????? 99 b95b000000 f7f9 }
            // n = 5, score = 200
            //   83c404               | add                 esp, 4
            //   e8????????           |                     
            //   99                   | cdq                 
            //   b95b000000           | mov                 ecx, 0x5b
            //   f7f9                 | idiv                ecx

        $sequence_3 = { 8b7c2424 89542428 8b54240c 83d200 }
            // n = 4, score = 200
            //   8b7c2424             | mov                 edi, dword ptr [esp + 0x24]
            //   89542428             | mov                 dword ptr [esp + 0x28], edx
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   83d200               | adc                 edx, 0

        $sequence_4 = { 83c318 897730 83c404 895f38 }
            // n = 4, score = 200
            //   83c318               | add                 ebx, 0x18
            //   897730               | mov                 dword ptr [edi + 0x30], esi
            //   83c404               | add                 esp, 4
            //   895f38               | mov                 dword ptr [edi + 0x38], ebx

        $sequence_5 = { 8b75a8 46 56 e8???????? }
            // n = 4, score = 200
            //   8b75a8               | mov                 esi, dword ptr [ebp - 0x58]
            //   46                   | inc                 esi
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_6 = { 50 ff15???????? 83f805 7507 }
            // n = 4, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83f805               | cmp                 eax, 5
            //   7507                 | jne                 9

        $sequence_7 = { 56 ff15???????? ff15???????? 50 6a00 68ffff1f00 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   68ffff1f00           | push                0x1fffff

        $sequence_8 = { f7f9 81c2d0070000 52 ffd6 }
            // n = 4, score = 200
            //   f7f9                 | idiv                ecx
            //   81c2d0070000         | add                 edx, 0x7d0
            //   52                   | push                edx
            //   ffd6                 | call                esi

        $sequence_9 = { 83c223 2bc1 83c0fc 83f81f 0f877e030000 }
            // n = 5, score = 200
            //   83c223               | add                 edx, 0x23
            //   2bc1                 | sub                 eax, ecx
            //   83c0fc               | add                 eax, -4
            //   83f81f               | cmp                 eax, 0x1f
            //   0f877e030000         | ja                  0x384

        $sequence_10 = { 8b07 6a08 895de0 8b4004 }
            // n = 4, score = 200
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   6a08                 | push                8
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   8b4004               | mov                 eax, dword ptr [eax + 4]

        $sequence_11 = { 8b8550fdffff 83e001 0f8412000000 83a550fdfffffe }
            // n = 4, score = 200
            //   8b8550fdffff         | mov                 eax, dword ptr [ebp - 0x2b0]
            //   83e001               | and                 eax, 1
            //   0f8412000000         | je                  0x18
            //   83a550fdfffffe       | and                 dword ptr [ebp - 0x2b0], 0xfffffffe

        $sequence_12 = { 83c404 8d4718 897034 8d5804 }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   8d4718               | lea                 eax, [edi + 0x18]
            //   897034               | mov                 dword ptr [eax + 0x34], esi
            //   8d5804               | lea                 ebx, [eax + 4]

        $sequence_13 = { 8d442410 50 ff15???????? 6685c0 }
            // n = 4, score = 200
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6685c0               | test                ax, ax

        $sequence_14 = { 8945e0 c7437000000000 c7839000000000000000 c7839400000000000000 }
            // n = 4, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   c7437000000000       | mov                 dword ptr [ebx + 0x70], 0
            //   c7839000000000000000     | mov    dword ptr [ebx + 0x90], 0
            //   c7839400000000000000     | mov    dword ptr [ebx + 0x94], 0

        $sequence_15 = { 8bc8 83ec1c c645fc3c 8d8500ffffff }
            // n = 4, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83ec1c               | sub                 esp, 0x1c
            //   c645fc3c             | mov                 byte ptr [ebp - 4], 0x3c
            //   8d8500ffffff         | lea                 eax, [ebp - 0x100]

    condition:
        7 of them and filesize < 4716352
}
