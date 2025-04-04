rule win_dadstache_auto {

    meta:
        id = "6nXZ9YAGmwQ5juuvWabkhx"
        fingerprint = "v1_sha256_25ccaa507f10be35b704008ec9887b279a6b66e6fbc6fcb0d9200b947fa69258"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dadstache."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dadstache"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a3???????? c605????????03 ff15???????? 68c8000000 }
            // n = 4, score = 500
            //   a3????????           |                     
            //   c605????????03       |                     
            //   ff15????????         |                     
            //   68c8000000           | push                0xc8

        $sequence_1 = { e9???????? 80f902 0f85f8000000 8b830c020000 }
            // n = 4, score = 500
            //   e9????????           |                     
            //   80f902               | cmp                 cl, 2
            //   0f85f8000000         | jne                 0xfe
            //   8b830c020000         | mov                 eax, dword ptr [ebx + 0x20c]

        $sequence_2 = { 8bd8 83c408 85db 0f858e000000 6aff ff35???????? }
            // n = 6, score = 500
            //   8bd8                 | mov                 ebx, eax
            //   83c408               | add                 esp, 8
            //   85db                 | test                ebx, ebx
            //   0f858e000000         | jne                 0x94
            //   6aff                 | push                -1
            //   ff35????????         |                     

        $sequence_3 = { 85c0 7409 50 ffd6 8b15???????? 85d2 }
            // n = 6, score = 500
            //   85c0                 | test                eax, eax
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   8b15????????         |                     
            //   85d2                 | test                edx, edx

        $sequence_4 = { 83c710 8b45f0 8b5dec c1e810 0fb6c0 c1e918 8b55e8 }
            // n = 7, score = 500
            //   83c710               | add                 edi, 0x10
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b5dec               | mov                 ebx, dword ptr [ebp - 0x14]
            //   c1e810               | shr                 eax, 0x10
            //   0fb6c0               | movzx               eax, al
            //   c1e918               | shr                 ecx, 0x18
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]

        $sequence_5 = { 68c8000000 ff15???????? 8b45ec 8d5302 46 ebd7 6a64 }
            // n = 7, score = 500
            //   68c8000000           | push                0xc8
            //   ff15????????         |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8d5302               | lea                 edx, [ebx + 2]
            //   46                   | inc                 esi
            //   ebd7                 | jmp                 0xffffffd9
            //   6a64                 | push                0x64

        $sequence_6 = { 6a00 83e103 8d85fcfdffff 6a00 }
            // n = 4, score = 500
            //   6a00                 | push                0
            //   83e103               | and                 ecx, 3
            //   8d85fcfdffff         | lea                 eax, [ebp - 0x204]
            //   6a00                 | push                0

        $sequence_7 = { ff35???????? ff15???????? 85c0 0f8461ffffff 8b45fc 3dc8000000 751c }
            // n = 7, score = 500
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8461ffffff         | je                  0xffffff67
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   3dc8000000           | cmp                 eax, 0xc8
            //   751c                 | jne                 0x1e

        $sequence_8 = { 50 57 c745c075616c41 c745c46c6c6f63 c645c800 ffd3 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   57                   | push                edi
            //   c745c075616c41       | mov                 dword ptr [ebp - 0x40], 0x416c6175
            //   c745c46c6c6f63       | mov                 dword ptr [ebp - 0x3c], 0x636f6c6c
            //   c645c800             | mov                 byte ptr [ebp - 0x38], 0
            //   ffd3                 | call                ebx

        $sequence_9 = { 660f6e8838ffffff 660f76f5 660f62d8 0f28e6 660f62ca }
            // n = 5, score = 200
            //   660f6e8838ffffff     | movd                xmm1, dword ptr [eax - 0xc8]
            //   660f76f5             | pcmpeqd             xmm6, xmm5
            //   660f62d8             | punpckldq           xmm3, xmm0
            //   0f28e6               | movaps              xmm4, xmm6
            //   660f62ca             | punpckldq           xmm1, xmm2

        $sequence_10 = { 0f8409010000 85c0 0f8401010000 6a20 }
            // n = 4, score = 200
            //   0f8409010000         | je                  0x10f
            //   85c0                 | test                eax, eax
            //   0f8401010000         | je                  0x107
            //   6a20                 | push                0x20

        $sequence_11 = { 57 c745e075616c46 c745e472656500 ffd3 837e0400 894610 7438 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   c745e075616c46       | mov                 dword ptr [ebp - 0x20], 0x466c6175
            //   c745e472656500       | mov                 dword ptr [ebp - 0x1c], 0x656572
            //   ffd3                 | call                ebx
            //   837e0400             | cmp                 dword ptr [esi + 4], 0
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   7438                 | je                  0x3a

        $sequence_12 = { 0f28e6 660f6e5084 660fdbfe 660f62d9 0f57f6 }
            // n = 5, score = 200
            //   0f28e6               | movaps              xmm4, xmm6
            //   660f6e5084           | movd                xmm2, dword ptr [eax - 0x7c]
            //   660fdbfe             | pand                xmm7, xmm6
            //   660f62d9             | punpckldq           xmm3, xmm1
            //   0f57f6               | xorps               xmm6, xmm6

        $sequence_13 = { 85f6 7437 837e0c00 7431 85d2 742d }
            // n = 6, score = 200
            //   85f6                 | test                esi, esi
            //   7437                 | je                  0x39
            //   837e0c00             | cmp                 dword ptr [esi + 0xc], 0
            //   7431                 | je                  0x33
            //   85d2                 | test                edx, edx
            //   742d                 | je                  0x2f

        $sequence_14 = { 83c060 660f6e5024 8d8040010000 660f6e80bcfeffff 0f57f6 660f6e8894feffff }
            // n = 6, score = 200
            //   83c060               | add                 eax, 0x60
            //   660f6e5024           | movd                xmm2, dword ptr [eax + 0x24]
            //   8d8040010000         | lea                 eax, [eax + 0x140]
            //   660f6e80bcfeffff     | movd                xmm0, dword ptr [eax - 0x144]
            //   0f57f6               | xorps               xmm6, xmm6
            //   660f6e8894feffff     | movd                xmm1, dword ptr [eax - 0x16c]

        $sequence_15 = { 74d5 ff7654 8b55e8 8bcf e8???????? 8b4dfc }
            // n = 6, score = 200
            //   74d5                 | je                  0xffffffd7
            //   ff7654               | push                dword ptr [esi + 0x54]
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 580608
}
