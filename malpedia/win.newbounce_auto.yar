rule win_newbounce_auto {

    meta:
        id = "A3MeCx2N9yUqhZfdybxax"
        fingerprint = "v1_sha256_1757d742189e1562595d26ebbaf5e74bc5236d74e3305389104993dc5b138ecf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.newbounce."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newbounce"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83e00f 7e05 2bf0 83c610 }
            // n = 4, score = 300
            //   83e00f               | and                 eax, 0xf
            //   7e05                 | jle                 7
            //   2bf0                 | sub                 esi, eax
            //   83c610               | add                 esi, 0x10

        $sequence_1 = { 488bcb 33f6 e8???????? 4889442438 }
            // n = 4, score = 200
            //   488bcb               | mov                 ecx, ebx
            //   33f6                 | xor                 edx, edx
            //   e8????????           |                     
            //   4889442438           | inc                 ebp

        $sequence_2 = { 488bcb 482bd3 480355ef e8???????? }
            // n = 4, score = 200
            //   488bcb               | inc                 ebp
            //   482bd3               | lea                 eax, [ecx + 0x10]
            //   480355ef             | cmp                 esi, edi
            //   e8????????           |                     

        $sequence_3 = { 488bcb 488905???????? ff15???????? 488bc8 488d1526d60200 }
            // n = 5, score = 200
            //   488bcb               | dec                 eax
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488bc8               | mov                 ecx, ebx
            //   488d1526d60200       | inc                 ebp

        $sequence_4 = { 488bcb 418906 e8???????? b001 }
            // n = 4, score = 200
            //   488bcb               | mov                 edx, esi
            //   418906               | dec                 eax
            //   e8????????           |                     
            //   b001                 | mov                 ecx, ebx

        $sequence_5 = { 488bcb 33d2 45895c2404 45892c24 }
            // n = 4, score = 200
            //   488bcb               | dec                 eax
            //   33d2                 | lea                 ecx, [edi + 0x3034]
            //   45895c2404           | dec                 eax
            //   45892c24             | mov                 edx, ebx

        $sequence_6 = { 488bca e8???????? be00100000 483bc6 735d 488d8f34300000 488bd3 }
            // n = 7, score = 200
            //   488bca               | dec                 eax
            //   e8????????           |                     
            //   be00100000           | mov                 ecx, edx
            //   483bc6               | mov                 esi, 0x1000
            //   735d                 | dec                 eax
            //   488d8f34300000       | cmp                 eax, esi
            //   488bd3               | jae                 0x5f

        $sequence_7 = { 488bcb 458d4110 e8???????? 3bf7 }
            // n = 4, score = 200
            //   488bcb               | mov                 dword ptr [esp + 0x38], eax
            //   458d4110             | dec                 eax
            //   e8????????           |                     
            //   3bf7                 | test                eax, eax

        $sequence_8 = { 81e6ff000000 3304b548576300 c1ea08 81e2ff000000 }
            // n = 4, score = 100
            //   81e6ff000000         | mov                 ecx, ebx
            //   3304b548576300       | dec                 eax
            //   c1ea08               | lea                 edx, [0x2d97f]
            //   81e2ff000000         | dec                 eax

        $sequence_9 = { 81e6ff000000 33048d485f6300 8b34b5485b6300 33c6 33442428 89742420 }
            // n = 6, score = 100
            //   81e6ff000000         | dec                 eax
            //   33048d485f6300       | mov                 ecx, eax
            //   8b34b5485b6300       | dec                 eax
            //   33c6                 | mov                 ecx, ebx
            //   33442428             | dec                 eax
            //   89742420             | mov                 ecx, ebx

        $sequence_10 = { 81e6ff000000 8b14b548576300 89542414 8b9424bc000000 }
            // n = 4, score = 100
            //   81e6ff000000         | mov                 ecx, ebx
            //   8b14b548576300       | dec                 eax
            //   89542414             | lea                 edx, [0x2d681]
            //   8b9424bc000000       | dec                 eax

        $sequence_11 = { 81e6ff000000 3344242c 8b34b5485b6300 33442410 }
            // n = 4, score = 100
            //   81e6ff000000         | lea                 edx, [0x2d381]
            //   3344242c             | dec                 eax
            //   8b34b5485b6300       | mov                 ecx, ebx
            //   33442410             | dec                 eax

        $sequence_12 = { 81e6ff000000 3304b548576300 894c2458 33049548536300 }
            // n = 4, score = 100
            //   81e6ff000000         | mov                 ecx, eax
            //   3304b548576300       | dec                 eax
            //   894c2458             | mov                 ecx, ebx
            //   33049548536300       | dec                 eax

        $sequence_13 = { 81e6ff000000 3304b548576300 c1e908 81e1ff000000 }
            // n = 4, score = 100
            //   81e6ff000000         | lea                 edx, [0x2d07b]
            //   3304b548576300       | dec                 eax
            //   c1e908               | mov                 ecx, eax
            //   81e1ff000000         | dec                 eax

        $sequence_14 = { 81e6ff000000 8b34b548536300 81e7ff000000 8b3cbd48576300 }
            // n = 4, score = 100
            //   81e6ff000000         | mov                 ecx, ebx
            //   8b34b548536300       | dec                 eax
            //   81e7ff000000         | mov                 ecx, ebx
            //   8b3cbd48576300       | dec                 eax

    condition:
        7 of them and filesize < 8637440
}
