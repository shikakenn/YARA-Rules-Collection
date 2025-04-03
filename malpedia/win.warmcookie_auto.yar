rule win_warmcookie_auto {

    meta:
        id = "5aCJdQ2w2DRhFefLo0kjfz"
        fingerprint = "v1_sha256_205c15eced2ed79efcc622047f0495a7c9e5251bb4fd9a4d1e0ae8a704e7e82e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.warmcookie."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.warmcookie"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f85c0000000 4183e801 4489430c 0f1f840000000000 }
            // n = 4, score = 800
            //   0f85c0000000         | cmp                 eax, ebp
            //   4183e801             | dec                 eax
            //   4489430c             | sub                 esp, eax
            //   0f1f840000000000     | dec                 esp

        $sequence_1 = { 4863d3 4801d2 31c9 6641890c14 4883c438 }
            // n = 5, score = 800
            //   4863d3               | add                 eax, 1
            //   4801d2               | mov                 dword ptr [ebx + 0x24], eax
            //   31c9                 | sub                 esi, 1
            //   6641890c14           | jb                  0x41
            //   4883c438             | jne                 0xc6

        $sequence_2 = { 0f8758fcffff e9???????? 448b6b0c 4439e8 }
            // n = 4, score = 800
            //   0f8758fcffff         | mov                 eax, dword ptr [edi]
            //   e9????????           |                     
            //   448b6b0c             | movzx               edx, word ptr [eax]
            //   4439e8               | cmp                 dx, 0x20

        $sequence_3 = { e8???????? 39c3 7f1c 4863d3 4801d2 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   39c3                 | test                edx, edx
            //   7f1c                 | je                  0x201
            //   4863d3               | dec                 eax
            //   4801d2               | mov                 eax, ecx

        $sequence_4 = { 4829c4 4c8d642420 4c89e6 4885d2 0f84f0010000 }
            // n = 5, score = 800
            //   4829c4               | jbe                 0xffffffea
            //   4c8d642420           | inc                 ecx
            //   4c89e6               | mov                 eax, ecx
            //   4885d2               | inc                 ecx
            //   0f84f0010000         | xor                 eax, 1

        $sequence_5 = { f7c700040000 0f8440ffffff 4c39e6 0f877cfdffff }
            // n = 4, score = 800
            //   f7c700040000         | lea                 esp, [esp + 0x20]
            //   0f8440ffffff         | dec                 esp
            //   4c39e6               | mov                 esi, esp
            //   0f877cfdffff         | dec                 eax

        $sequence_6 = { 4889c8 83c001 894324 83ee01 7236 }
            // n = 5, score = 800
            //   4889c8               | mov                 dword ptr [edi], 1
            //   83c001               | ja                  0xfffffc5e
            //   894324               | inc                 esp
            //   83ee01               | mov                 ebp, dword ptr [ebx + 0xc]
            //   7236                 | inc                 esp

        $sequence_7 = { ff15???????? 25ff0f0000 8d88b80b0000 ff15???????? }
            // n = 4, score = 600
            //   ff15????????         |                     
            //   25ff0f0000           | and                 eax, 0xfff
            //   8d88b80b0000         | lea                 ecx, [eax + 0xbb8]
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 3dff2f0000 0f97c0 0fb6c0 }
            // n = 4, score = 500
            //   e8????????           |                     
            //   3dff2f0000           | dec                 eax
            //   0f97c0               | mov                 ecx, dword ptr [esp + 0x38]
            //   0fb6c0               | test                eax, eax

        $sequence_9 = { ba18000000 4889c1 ffd3 85c0 }
            // n = 4, score = 500
            //   ba18000000           | mov                 edx, 0x18
            //   4889c1               | dec                 eax
            //   ffd3                 | mov                 ecx, eax
            //   85c0                 | call                ebx

        $sequence_10 = { 488b01 ff9080000000 85c0 7815 }
            // n = 4, score = 500
            //   488b01               | test                eax, eax
            //   ff9080000000         | dec                 eax
            //   85c0                 | mov                 eax, dword ptr [ecx]
            //   7815                 | call                dword ptr [eax + 0x80]

        $sequence_11 = { ba19000000 488b4c2438 ff15???????? 85c0 }
            // n = 4, score = 500
            //   ba19000000           | test                eax, eax
            //   488b4c2438           | js                  0x19
            //   ff15????????         |                     
            //   85c0                 | mov                 edx, 0x19

        $sequence_12 = { 75e2 488b3d???????? 31ed 8b07 }
            // n = 4, score = 400
            //   75e2                 | movzx               eax, al
            //   488b3d????????       |                     
            //   31ed                 | test                eax, eax
            //   8b07                 | je                  0xb

        $sequence_13 = { 85c0 7409 488b442428 48c1e814 }
            // n = 4, score = 400
            //   85c0                 | dec                 eax
            //   7409                 | sub                 esp, 0x28
            //   488b442428           | cmp                 eax, 0x2fff
            //   48c1e814             | seta                al

        $sequence_14 = { 0fb710 6683fa20 76e4 4189c8 4183f001 }
            // n = 5, score = 400
            //   0fb710               | dec                 eax
            //   6683fa20             | mov                 eax, dword ptr [esp + 0x28]
            //   76e4                 | dec                 eax
            //   4189c8               | shr                 eax, 0x14
            //   4183f001             | jne                 0xffffffe4

        $sequence_15 = { 4885c0 741a 89742428 4183c9ff }
            // n = 4, score = 300
            //   4885c0               | arpl                bx, dx
            //   741a                 | dec                 eax
            //   89742428             | add                 edx, edx
            //   4183c9ff             | xor                 ecx, ecx

        $sequence_16 = { 488b01 ff5018 85c0 0f88b9000000 }
            // n = 4, score = 300
            //   488b01               | inc                 cx
            //   ff5018               | mov                 dword ptr [esp + edx], ecx
            //   85c0                 | dec                 eax
            //   0f88b9000000         | add                 esp, 0x38

        $sequence_17 = { 41be01000000 4489742454 4585e4 0f84aa000000 488d9550010000 b904010000 ff15???????? }
            // n = 7, score = 200
            //   41be01000000         | dec                 ecx
            //   4489742454           | cmp                 ebp, edi
            //   4585e4               | je                  0x1a5
            //   0f84aa000000         | test                esi, esi
            //   488d9550010000       | jle                 0x37
            //   b904010000           | dec                 eax
            //   ff15????????         |                     

        $sequence_18 = { 8b7500 33c0 f04d0fb1bcf1d0300200 488bd8 740e 483bc7 }
            // n = 6, score = 200
            //   8b7500               | inc                 cx
            //   33c0                 | mov                 dword ptr [eax + edx*2], ecx
            //   f04d0fb1bcf1d0300200     | dec    eax
            //   488bd8               | mov                 eax, edx
            //   740e                 | add                 eax, 1
            //   483bc7               | ja                  0xfffffc5e

        $sequence_19 = { 48ffc1 4881f900010000 72f0 4532d2 4c8bc6 }
            // n = 5, score = 200
            //   48ffc1               | inc                 esp
            //   4881f900010000       | mov                 ebp, dword ptr [ebx + 0xc]
            //   72f0                 | inc                 esp
            //   4532d2               | cmp                 eax, ebp
            //   4c8bc6               | dec                 eax

        $sequence_20 = { 488b4da7 ff15???????? 488bc3 488b4d37 4833cc e8???????? 488b9c2418010000 }
            // n = 7, score = 200
            //   488b4da7             | mov                 eax, edi
            //   ff15????????         |                     
            //   488bc3               | dec                 esp
            //   488b4d37             | sub                 eax, ebp
            //   4833cc               | sub                 esi, eax
            //   e8????????           |                     
            //   488b9c2418010000     | mov                 ecx, 0x20

    condition:
        7 of them and filesize < 331776
}
