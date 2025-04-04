rule win_cur1_downloader_auto {

    meta:
        id = "7esmWZ7BaTjf58tFaGDgF"
        fingerprint = "v1_sha256_1c569e94280f8095f5f07b5abf340e9688b7e484a4ea176f880968651b21cc46"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cur1_downloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cur1_downloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c684241204000061 c684241304000070 c684241404000073 c684241504000068 c68424160400006f c684241704000074 }
            // n = 6, score = 100
            //   c684241204000061     | dec                 eax
            //   c684241304000070     | lea                 edx, [esp + 0x38]
            //   c684241404000073     | dec                 eax
            //   c684241504000068     | mov                 ecx, dword ptr [esp + 0xd8]
            //   c68424160400006f     | dec                 eax
            //   c684241704000074     | lea                 eax, [esp + 0xe0]

        $sequence_1 = { 88040a 4863442408 488b4c2430 0fb654240c }
            // n = 4, score = 100
            //   88040a               | dec                 eax
            //   4863442408           | lea                 ecx, [eax + 8]
            //   488b4c2430           | movups              xmmword ptr [edx], xmm0
            //   0fb654240c           | dec                 eax

        $sequence_2 = { 488364243000 4889442428 4c89742420 e8???????? 4c8b442468 4c8d0d5d4effff 498b5008 }
            // n = 7, score = 100
            //   488364243000         | mov                 byte ptr [esp + 0x257], 0x41
            //   4889442428           | mov                 byte ptr [esp + 0x258], 0
            //   4c89742420           | mov                 byte ptr [esp + 0x320], 0x49
            //   e8????????           |                     
            //   4c8b442468           | mov                 byte ptr [esp + 0x321], 0x6e
            //   4c8d0d5d4effff       | mov                 byte ptr [esp + 0x355], 0x73
            //   498b5008             | mov                 byte ptr [esp + 0x356], 0x73

        $sequence_3 = { 4863442430 488bd0 488b4c2478 e8???????? 48634c2420 0fb600 88440c24 }
            // n = 7, score = 100
            //   4863442430           | mov                 byte ptr [esp + 0x33c], 0x75
            //   488bd0               | mov                 byte ptr [esp + 0x33d], 0x72
            //   488b4c2478           | add                 byte ptr [edx - 0x3a], dh
            //   e8????????           |                     
            //   48634c2420           | test                byte ptr [ecx + edi], ah
            //   0fb600               | add                 al, 0
            //   88440c24             | add                 byte ptr [ebp - 0x3a], ah

        $sequence_4 = { 488bcb e8???????? 8bf8 e9???????? 41be00010000 4c8d3d57360100 }
            // n = 6, score = 100
            //   488bcb               | mov                 ebx, dword ptr [esp + 0x50]
            //   e8????????           |                     
            //   8bf8                 | dec                 eax
            //   e9????????           |                     
            //   41be00010000         | mov                 ebp, dword ptr [esp + 0x58]
            //   4c8d3d57360100       | jmp                 0x9ad

        $sequence_5 = { e8???????? 488d1527ff0100 488d4c2420 e8???????? cc 48895c2410 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   488d1527ff0100       | cmp                 dword ptr [esp + 0x60], 0
            //   488d4c2420           | je                  0xdbb
            //   e8????????           |                     
            //   cc                   | dec                 eax
            //   48895c2410           | mov                 ecx, dword ptr [esp + 0x60]

        $sequence_6 = { 8b8c2468010000 e8???????? 4889442430 c744242040000000 488d442420 4889442428 4c8b442428 }
            // n = 7, score = 100
            //   8b8c2468010000       | add                 edi, edx
            //   e8????????           |                     
            //   4889442430           | dec                 eax
            //   c744242040000000     | mov                 edx, edi
            //   488d442420           | dec                 eax
            //   4889442428           | mov                 edi, edx
            //   4c8b442428           | dec                 eax

        $sequence_7 = { c3 e8???????? 90 cc 33c0 4c8d1d7b44ffff 884118 }
            // n = 7, score = 100
            //   c3                   | lea                 esi, [0x17de7]
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   cc                   | mov                 dword ptr [esp + 0x20], ebx
            //   33c0                 | dec                 eax
            //   4c8d1d7b44ffff       | lea                 eax, [0x18c73]
            //   884118               | dec                 eax

        $sequence_8 = { 486bc901 8b0408 39442470 7402 eb37 8b442440 }
            // n = 6, score = 100
            //   486bc901             | mov                 byte ptr [esp + 0x33f], 0x65
            //   8b0408               | mov                 byte ptr [esp + 0x340], 0x6e
            //   39442470             | mov                 byte ptr [esp + 0x341], 0x74
            //   7402                 | mov                 byte ptr [esp + 0x342], 0x50
            //   eb37                 | mov                 byte ptr [esp + 0x343], 0x72
            //   8b442440             | mov                 byte ptr [esp + 0x140], 0x53

        $sequence_9 = { c684245f03000069 c68424600300006f c68424610300006e c684246203000049 c684246303000064 }
            // n = 5, score = 100
            //   c684245f03000069     | movups              xmmword ptr [edx], xmm0
            //   c68424600300006f     | dec                 eax
            //   c68424610300006e     | lea                 eax, [0x12bc8]
            //   c684246203000049     | dec                 eax
            //   c684246303000064     | mov                 dword ptr [ebx], eax

    condition:
        7 of them and filesize < 402432
}
