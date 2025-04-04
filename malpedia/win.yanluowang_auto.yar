rule win_yanluowang_auto {

    meta:
        id = "3201KfJQ2YirFTpPxgENMY"
        fingerprint = "v1_sha256_6212a7300d814763a89ad52de44e628c3e76a732777f6c6e8d98550e60e1baf9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.yanluowang."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yanluowang"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7416 8bc2 8bca 83e03f c1f906 6bc030 03048d38034600 }
            // n = 7, score = 100
            //   7416                 | je                  0x18
            //   8bc2                 | mov                 eax, edx
            //   8bca                 | mov                 ecx, edx
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bc030               | imul                eax, eax, 0x30
            //   03048d38034600       | add                 eax, dword ptr [ecx*4 + 0x460338]

        $sequence_1 = { 74da 83e801 74d5 83e801 0f85a5fdffff 0fbe41ff 8d04c560984400 }
            // n = 7, score = 100
            //   74da                 | je                  0xffffffdc
            //   83e801               | sub                 eax, 1
            //   74d5                 | je                  0xffffffd7
            //   83e801               | sub                 eax, 1
            //   0f85a5fdffff         | jne                 0xfffffdab
            //   0fbe41ff             | movsx               eax, byte ptr [ecx - 1]
            //   8d04c560984400       | lea                 eax, [eax*8 + 0x449860]

        $sequence_2 = { 668945e8 8b45d4 886de5 8b148538034600 8a4c1a2d f6c104 7419 }
            // n = 7, score = 100
            //   668945e8             | mov                 word ptr [ebp - 0x18], ax
            //   8b45d4               | mov                 eax, dword ptr [ebp - 0x2c]
            //   886de5               | mov                 byte ptr [ebp - 0x1b], ch
            //   8b148538034600       | mov                 edx, dword ptr [eax*4 + 0x460338]
            //   8a4c1a2d             | mov                 cl, byte ptr [edx + ebx + 0x2d]
            //   f6c104               | test                cl, 4
            //   7419                 | je                  0x1b

        $sequence_3 = { 69f307536554 8b55cc 8d1c0f 8b45b4 c1c208 0fb6c0 }
            // n = 6, score = 100
            //   69f307536554         | imul                esi, ebx, 0x54655307
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   8d1c0f               | lea                 ebx, [edi + ecx]
            //   8b45b4               | mov                 eax, dword ptr [ebp - 0x4c]
            //   c1c208               | rol                 edx, 8
            //   0fb6c0               | movzx               eax, al

        $sequence_4 = { 68???????? 51 50 8d45a4 50 ffb5e4fcffff 8d8d3cffffff }
            // n = 7, score = 100
            //   68????????           |                     
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax
            //   ffb5e4fcffff         | push                dword ptr [ebp - 0x31c]
            //   8d8d3cffffff         | lea                 ecx, [ebp - 0xc4]

        $sequence_5 = { 8d8dc0eeffff e8???????? c645fc18 b8ffffff7f 8b8dd0eeffff 2bc1 83f830 }
            // n = 7, score = 100
            //   8d8dc0eeffff         | lea                 ecx, [ebp - 0x1140]
            //   e8????????           |                     
            //   c645fc18             | mov                 byte ptr [ebp - 4], 0x18
            //   b8ffffff7f           | mov                 eax, 0x7fffffff
            //   8b8dd0eeffff         | mov                 ecx, dword ptr [ebp - 0x1130]
            //   2bc1                 | sub                 eax, ecx
            //   83f830               | cmp                 eax, 0x30

        $sequence_6 = { ff75b8 ff75c8 e8???????? 6a00 6a00 }
            // n = 5, score = 100
            //   ff75b8               | push                dword ptr [ebp - 0x48]
            //   ff75c8               | push                dword ptr [ebp - 0x38]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_7 = { 8ad8 83fa10 722c 8b4ddc 42 8bc1 81fa00100000 }
            // n = 7, score = 100
            //   8ad8                 | mov                 bl, al
            //   83fa10               | cmp                 edx, 0x10
            //   722c                 | jb                  0x2e
            //   8b4ddc               | mov                 ecx, dword ptr [ebp - 0x24]
            //   42                   | inc                 edx
            //   8bc1                 | mov                 eax, ecx
            //   81fa00100000         | cmp                 edx, 0x1000

        $sequence_8 = { 388557f4ffff 7431 8b85c0f5ffff 8d8d98f5ffff 51 3b85c4f5ffff 7410 }
            // n = 7, score = 100
            //   388557f4ffff         | cmp                 byte ptr [ebp - 0xba9], al
            //   7431                 | je                  0x33
            //   8b85c0f5ffff         | mov                 eax, dword ptr [ebp - 0xa40]
            //   8d8d98f5ffff         | lea                 ecx, [ebp - 0xa68]
            //   51                   | push                ecx
            //   3b85c4f5ffff         | cmp                 eax, dword ptr [ebp - 0xa3c]
            //   7410                 | je                  0x12

        $sequence_9 = { 8b4f50 8bf1 8b55ac 8b4754 8b7f58 8b525c 0bca }
            // n = 7, score = 100
            //   8b4f50               | mov                 ecx, dword ptr [edi + 0x50]
            //   8bf1                 | mov                 esi, ecx
            //   8b55ac               | mov                 edx, dword ptr [ebp - 0x54]
            //   8b4754               | mov                 eax, dword ptr [edi + 0x54]
            //   8b7f58               | mov                 edi, dword ptr [edi + 0x58]
            //   8b525c               | mov                 edx, dword ptr [edx + 0x5c]
            //   0bca                 | or                  ecx, edx

    condition:
        7 of them and filesize < 834560
}
