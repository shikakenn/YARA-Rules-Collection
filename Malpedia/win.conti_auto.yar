rule win_conti_auto {

    meta:
        id = "61Rqph4IqYLVcfemt0oyyk"
        fingerprint = "v1_sha256_dcbcb23c478cd81647ea44a976b8893f9822f8475b35052b849cd9e3172bedaa"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.conti."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.conti"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8a06 8d7601 0fb6c0 83e839 }
            // n = 4, score = 600
            //   8a06                 | mov                 al, byte ptr [esi]
            //   8d7601               | lea                 esi, [esi + 1]
            //   0fb6c0               | movzx               eax, al
            //   83e839               | sub                 eax, 0x39

        $sequence_1 = { 57 bf0e000000 8d7101 8d5f71 }
            // n = 4, score = 600
            //   57                   | push                edi
            //   bf0e000000           | mov                 edi, 0xe
            //   8d7101               | lea                 esi, [ecx + 1]
            //   8d5f71               | lea                 ebx, [edi + 0x71]

        $sequence_2 = { 803900 7530 53 56 57 bf0e000000 }
            // n = 6, score = 600
            //   803900               | cmp                 byte ptr [ecx], 0
            //   7530                 | jne                 0x32
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   bf0e000000           | mov                 edi, 0xe

        $sequence_3 = { 0f1f4000 8a07 8d7f01 0fb6c0 b92a000000 2bc8 }
            // n = 6, score = 600
            //   0f1f4000             | nop                 dword ptr [eax]
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8d7f01               | lea                 edi, [edi + 1]
            //   0fb6c0               | movzx               eax, al
            //   b92a000000           | mov                 ecx, 0x2a
            //   2bc8                 | sub                 ecx, eax

        $sequence_4 = { 753f 53 bb0e000000 57 8d7e01 }
            // n = 5, score = 600
            //   753f                 | jne                 0x41
            //   53                   | push                ebx
            //   bb0e000000           | mov                 ebx, 0xe
            //   57                   | push                edi
            //   8d7e01               | lea                 edi, [esi + 1]

        $sequence_5 = { 8975fc 803e00 7541 53 bb0a000000 }
            // n = 5, score = 600
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7541                 | jne                 0x43
            //   53                   | push                ebx
            //   bb0a000000           | mov                 ebx, 0xa

        $sequence_6 = { 6a00 6a00 6800100000 68???????? }
            // n = 4, score = 600
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6800100000           | push                0x1000
            //   68????????           |                     

        $sequence_7 = { 57 bf0a000000 8d7101 8d5f75 }
            // n = 4, score = 600
            //   57                   | push                edi
            //   bf0a000000           | mov                 edi, 0xa
            //   8d7101               | lea                 esi, [ecx + 1]
            //   8d5f75               | lea                 ebx, [edi + 0x75]

        $sequence_8 = { e8???????? 85c0 7508 6a01 ff15???????? }
            // n = 5, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7508                 | jne                 0xa
            //   6a01                 | push                1
            //   ff15????????         |                     

        $sequence_9 = { 50 6a20 ff15???????? 68???????? ff15???????? 68???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   6a20                 | push                0x20
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   68????????           |                     

        $sequence_10 = { 8b4d08 e8???????? 6a00 ff15???????? 33c0 }
            // n = 5, score = 400
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_11 = { 3d00005000 7605 b800005000 6a00 8d4c2418 }
            // n = 5, score = 400
            //   3d00005000           | cmp                 eax, 0x500000
            //   7605                 | jbe                 7
            //   b800005000           | mov                 eax, 0x500000
            //   6a00                 | push                0
            //   8d4c2418             | lea                 ecx, [esp + 0x18]

        $sequence_12 = { 3cff 0f859d000000 807f0125 0f8593000000 }
            // n = 4, score = 400
            //   3cff                 | cmp                 al, 0xff
            //   0f859d000000         | jne                 0xa3
            //   807f0125             | cmp                 byte ptr [edi + 1], 0x25
            //   0f8593000000         | jne                 0x99

        $sequence_13 = { 8bb6007d0000 85f6 75ef 6aff 6a01 }
            // n = 5, score = 400
            //   8bb6007d0000         | mov                 esi, dword ptr [esi + 0x7d00]
            //   85f6                 | test                esi, esi
            //   75ef                 | jne                 0xfffffff1
            //   6aff                 | push                -1
            //   6a01                 | push                1

        $sequence_14 = { ff15???????? 89460c ff15???????? 8bc8 8b460c }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   89460c               | mov                 dword ptr [esi + 0xc], eax
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   8b460c               | mov                 eax, dword ptr [esi + 0xc]

        $sequence_15 = { ffd0 85c0 7519 c705????????0a000000 }
            // n = 4, score = 400
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7519                 | jne                 0x1b
            //   c705????????0a000000     |     

        $sequence_16 = { 6aff 6a01 8d4108 50 }
            // n = 4, score = 400
            //   6aff                 | push                -1
            //   6a01                 | push                1
            //   8d4108               | lea                 eax, [ecx + 8]
            //   50                   | push                eax

        $sequence_17 = { ff15???????? ff75f4 ff15???????? ff75f0 ff15???????? 5e }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff15????????         |                     
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     
            //   5e                   | pop                 esi

        $sequence_18 = { 7519 c705????????0a000000 e9???????? b801000000 }
            // n = 4, score = 400
            //   7519                 | jne                 0x1b
            //   c705????????0a000000     |     
            //   e9????????           |                     
            //   b801000000           | mov                 eax, 1

        $sequence_19 = { 3ce9 7412 3cff 0f859d000000 }
            // n = 4, score = 400
            //   3ce9                 | cmp                 al, 0xe9
            //   7412                 | je                  0x14
            //   3cff                 | cmp                 al, 0xff
            //   0f859d000000         | jne                 0xa3

        $sequence_20 = { 48894e08 4863c8 488d1c4b e8???????? }
            // n = 4, score = 300
            //   48894e08             | push                ebx
            //   4863c8               | mov                 ebx, 0xa
            //   488d1c4b             | mov                 al, byte ptr [edi]
            //   e8????????           |                     

        $sequence_21 = { e8???????? 33c0 e9???????? 488bc8 48899c24a8010000 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   33c0                 | mov                 edi, eax
            //   e9????????           |                     
            //   488bc8               | test                eax, eax
            //   48899c24a8010000     | xor                 eax, eax

        $sequence_22 = { 0f8ef5000000 49895b18 498973d0 be00005000 }
            // n = 4, score = 300
            //   0f8ef5000000         | dec                 eax
            //   49895b18             | mov                 ecx, ebx
            //   498973d0             | call                eax
            //   be00005000           | inc                 esp

        $sequence_23 = { c7442420000000f0 4c8d45a1 33d2 488bcf ffd0 85c0 }
            // n = 6, score = 300
            //   c7442420000000f0     | mov                 dword ptr [esp + 0x20], 0xf0000000
            //   4c8d45a1             | dec                 esp
            //   33d2                 | lea                 eax, [ebp - 0x5f]
            //   488bcf               | xor                 edx, edx
            //   ffd0                 | dec                 eax
            //   85c0                 | mov                 ecx, edi

        $sequence_24 = { e8???????? 33d2 33c9 ffd0 8bf8 }
            // n = 5, score = 300
            //   e8????????           |                     
            //   33d2                 | call                eax
            //   33c9                 | test                eax, eax
            //   ffd0                 | xor                 edx, edx
            //   8bf8                 | xor                 ecx, ecx

        $sequence_25 = { e8???????? 33d2 41b8107d0000 488bc8 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   33d2                 | call                eax
            //   41b8107d0000         | mov                 edi, eax
            //   488bc8               | test                eax, eax

        $sequence_26 = { 42884c0501 49ffc0 4983f80c 72af }
            // n = 4, score = 300
            //   42884c0501           | dec                 eax
            //   49ffc0               | arpl                ax, cx
            //   4983f80c             | dec                 eax
            //   72af                 | lea                 ebx, [ebx + ecx*2]

        $sequence_27 = { 2bc8 884c3c21 48ffc7 4883ff04 }
            // n = 4, score = 300
            //   2bc8                 | mov                 ecx, 0x48
            //   884c3c21             | sub                 ecx, eax
            //   48ffc7               | dec                 eax
            //   4883ff04             | mov                 dword ptr [esi + 8], ecx

    condition:
        7 of them and filesize < 520192
}
