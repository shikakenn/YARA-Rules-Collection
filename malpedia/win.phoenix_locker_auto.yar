rule win_phoenix_locker_auto {

    meta:
        id = "66l0Bv2FvQCTNZE4XdQgD4"
        fingerprint = "v1_sha256_fc57928d88a0e4a78b2d227bc29cc732b1edff7e878d1ae0306413cb72bae6ed"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.phoenix_locker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phoenix_locker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d4f01 49f7c204600d78 4183c9ff f9 4533c0 e9???????? ff15???????? }
            // n = 7, score = 200
            //   8d4f01               | cmp                 ecx, ebp
            //   49f7c204600d78       | inc                 ebp
            //   4183c9ff             | mov                 dword ptr [ebx - 0x38], ecx
            //   f9                   | inc                 cx
            //   4533c0               | test                ecx, 0x80402545
            //   e9????????           |                     
            //   ff15????????         |                     

        $sequence_1 = { 4c0fbfcb 4903f5 4803e9 4c8bdc 41c0e2f9 4881ec80010000 }
            // n = 6, score = 200
            //   4c0fbfcb             | dec                 eax
            //   4903f5               | mov                 esi, dword ptr [esp + 0x60]
            //   4803e9               | inc                 ebp
            //   4c8bdc               | movsx               ebp, cx
            //   41c0e2f9             | inc                 ecx
            //   4881ec80010000       | shr                 ch, cl

        $sequence_2 = { 0fbfd2 4899 450fb7c4 4c8d4080 480fb7d3 490fbfd6 }
            // n = 6, score = 200
            //   0fbfd2               | xlatb               
            //   4899                 | pop                 ebp
            //   450fb7c4             | cdq                 
            //   4c8d4080             | cld                 
            //   480fb7d3             | xor                 eax, 0xf6f119b1
            //   490fbfd6             | enter               -0x5437, 0x19

        $sequence_3 = { 4d8d8424b602a3ea 660fbeca 488bcb e9???????? e8???????? 8bd5 498d8c1cb602a3ea }
            // n = 7, score = 200
            //   4d8d8424b602a3ea     | cwde                
            //   660fbeca             | inc                 eax
            //   488bcb               | cmp                 dl, dh
            //   e9????????           |                     
            //   e8????????           |                     
            //   8bd5                 | dec                 ecx
            //   498d8c1cb602a3ea     | sub                 edi, ecx

        $sequence_4 = { 48818c24080000008b626a49 68342cb403 81ac2410000000ec5e9720 4881bc2400000000825a821d 68b97f0b55 66819424000000007c2e 680d2ea817 }
            // n = 7, score = 200
            //   48818c24080000008b626a49     | mov    bh, al
            //   68342cb403           | dec                 eax
            //   81ac2410000000ec5e9720     | lea    edi, [esp + 0x30]
            //   4881bc2400000000825a821d     | inc    bp
            //   68b97f0b55           | movzx               eax, dl
            //   66819424000000007c2e     | inc    esp
            //   680d2ea817           | xor                 al, dl

        $sequence_5 = { 488bfb 483bde e9???????? 0f8508feffff 4c8d5c2450 }
            // n = 5, score = 200
            //   488bfb               | mov                 ecx, dword ptr [esi]
            //   483bde               | xor                 ah, 0x4e
            //   e9????????           |                     
            //   0f8508feffff         | inc                 esp
            //   4c8d5c2450           | mov                 dword ptr [esi], ebx

        $sequence_6 = { 0f8441010000 418bbf84000000 41c0f875 40f6c621 458b8788000000 413bfb e9???????? }
            // n = 7, score = 200
            //   0f8441010000         | cmp                 al, 5
            //   418bbf84000000       | jbe                 0x1f9
            //   41c0f875             | dec                 eax
            //   40f6c621             | lea                 edx, [esp + 0x60]
            //   458b8788000000       | inc                 ecx
            //   413bfb               | movzx               ecx, sp
            //   e9????????           |                     

        $sequence_7 = { 0f8579010000 39442460 e9???????? 0f845b010000 488d542460 66410fbecb 660fc9 }
            // n = 7, score = 200
            //   0f8579010000         | inc                 dword ptr [ebp + 0x10]
            //   39442460             | mov                 ecx, 8
            //   e9????????           |                     
            //   0f845b010000         | inc                 ecx
            //   488d542460           | test                dl, 0xef
            //   66410fbecb           | xor                 eax, eax
            //   660fc9               | dec                 dword ptr [ebx + 0x3c]

        $sequence_8 = { 4c8b842428010000 80e5d5 d2c5 894228 6681c1f04d 4963c7 d2d4 }
            // n = 7, score = 200
            //   4c8b842428010000     | movzx               ecx, word ptr [ebp]
            //   80e5d5               | inc                 eax
            //   d2c5                 | cmp                 ch, 0x5b
            //   894228               | inc                 ecx
            //   6681c1f04d           | ror                 bh, 0x6d
            //   4963c7               | inc                 esp
            //   d2d4                 | mov                 edi, eax

        $sequence_9 = { e8???????? 4155 4151 9c 49b98059c32d64378851 e8???????? 4c0fbbea }
            // n = 7, score = 200
            //   e8????????           |                     
            //   4155                 | test                dword ptr [esp + 8], 0x35803afc
            //   4151                 | push                0x25de4436
            //   9c                   | dec                 ecx
            //   49b98059c32d64378851     | ror    ebp, 0x84
            //   e8????????           |                     
            //   4c0fbbea             | inc                 ecx

    condition:
        7 of them and filesize < 3702784
}
