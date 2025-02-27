rule elf_nosedive_auto {

    meta:
        id = "69tAvAQyB60Efwr1YeN8k1"
        fingerprint = "v1_sha256_437edcb731a71f57346014b7f168c5a7e19b62836d7ab5266e2b058730d6e731"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects elf.nosedive."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.nosedive"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a801 0f84d1000000 48c7c098ffffff 64448b30 64c70000000000 41ffc7 7441 }
            // n = 7, score = 100
            //   a801                 | mov                 ebp, eax
            //   0f84d1000000         | xor                 eax, eax
            //   48c7c098ffffff       | cmp                 ebp, -1
            //   64448b30             | je                  0xd0
            //   64c70000000000       | dec                 esp
            //   41ffc7               | lea                 esp, [esp + 0x10]
            //   7441                 | mov                 edx, 0x10

        $sequence_1 = { eb02 31c9 488b4038 4c89542428 48890c24 4889c7 4889442418 }
            // n = 7, score = 100
            //   eb02                 | mov                 eax, dword ptr [esp + 0xa8]
            //   31c9                 | dec                 esp
            //   488b4038             | mov                 edi, edi
            //   4c89542428           | inc                 ecx
            //   48890c24             | cmp                 ebp, 0x7f
            //   4889c7               | jbe                 0xafc
            //   4889442418           | inc                 ecx

        $sequence_2 = { 895d10 48894508 85db 0f8e81000000 4531ff 0f1f00 4489fe }
            // n = 7, score = 100
            //   895d10               | test                eax, eax
            //   48894508             | je                  0xffffffdd
            //   85db                 | dec                 ecx
            //   0f8e81000000         | mov                 edi, dword ptr [edi + 0x70]
            //   4531ff               | mov                 esi, eax
            //   0f1f00               | test                eax, eax
            //   4489fe               | jne                 0xffffffd8

        $sequence_3 = { 85c0 0f8fb2030000 4c8da3be000000 4c89e7 e8???????? 85c0 0f8f7b030000 }
            // n = 7, score = 100
            //   85c0                 | add                 dword ptr [ebp + 8], 1
            //   0f8fb2030000         | and                 edx, 2
            //   4c8da3be000000       | jne                 0x3bf
            //   4c89e7               | dec                 esp
            //   e8????????           |                     
            //   85c0                 | lea                 eax, [0xf218f]
            //   0f8f7b030000         | dec                 esp

        $sequence_4 = { 894f78 898740010000 f3410f6f01 0f118744010000 f3410f6f4910 0f118f54010000 f3410f6f5120 }
            // n = 7, score = 100
            //   894f78               | movzx               edx, byte ptr [ebp]
            //   898740010000         | or                  ebx, eax
            //   f3410f6f01           | xor                 eax, eax
            //   0f118744010000       | cmp                 ebx, eax
            //   f3410f6f4910         | test                dl, dl
            //   0f118f54010000       | jne                 0xdb
            //   f3410f6f5120         | cmp                 dword ptr [ebp - 0xac], 0

        $sequence_5 = { 4531c0 4c8b4c2418 488b742410 49bfffffffffffff0000 4c89cb 4d89cd 4d21cf }
            // n = 7, score = 100
            //   4531c0               | mov                 eax, dword ptr [eax]
            //   4c8b4c2418           | dec                 eax
            //   488b742410           | mov                 ebp, dword ptr [esp + 0x58]
            //   49bfffffffffffff0000     | dec    eax
            //   4c89cb               | test                ebp, ebp
            //   4d89cd               | je                  0x1144
            //   4d21cf               | mov                 al, byte ptr [ebp + 5]

        $sequence_6 = { e8???????? 4d89e1 4189d8 4c89e2 4889c1 4889ee 4c89f7 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4d89e1               | dec                 eax
            //   4189d8               | mov                 dword ptr [ebx + 0x12c], edx
            //   4c89e2               | mov                 dword ptr [ebx + 0x13a], 0xffffffff
            //   4889c1               | or                  ax, 0x6e08
            //   4889ee               | mov                 word ptr [ebx + 0x14c], ax
            //   4c89f7               | dec                 eax

        $sequence_7 = { 880f c3 8b4c16fc 8b36 894c17fc 8937 c3 }
            // n = 7, score = 100
            //   880f                 | add                 eax, esi
            //   c3                   | jmp                 eax
            //   8b4c16fc             | cmp                 eax, 0x49
            //   8b36                 | je                  0x4ba
            //   894c17fc             | cmp                 eax, 0x11
            //   8937                 | je                  0x509
            //   c3                   | jg                  0x4c8

        $sequence_8 = { a801 7527 488b8790000000 48837f6800 48890424 7415 488b0424 }
            // n = 7, score = 100
            //   a801                 | mov                 eax, 0x35000002
            //   7527                 | or                  byte ptr [eax], cl
            //   488b8790000000       | or                  byte ptr [eax], cl
            //   48837f6800           | mov                 ebp, eax
            //   48890424             | cmp                 eax, -1
            //   7415                 | je                  0x3cb
            //   488b0424             | pxor                xmm0, xmm0

        $sequence_9 = { b902160000 e9???????? 4c8d052df80e00 b9f7150000 be01000000 488d156cf30e00 e8???????? }
            // n = 7, score = 100
            //   b902160000           | mov                 edi, ebp
            //   e9????????           |                     
            //   4c8d052df80e00       | mov                 edi, ebp
            //   b9f7150000           | mov                 edx, 7
            //   be01000000           | mov                 dword ptr [esp + 0x20], eax
            //   488d156cf30e00       | mov                 ecx, 0xffff
            //   e8????????           |                     

    condition:
        7 of them and filesize < 3268608
}
