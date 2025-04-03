rule win_romeos_auto {

    meta:
        id = "6mIXzslClfjxDfXJK9Ak5d"
        fingerprint = "v1_sha256_bf8e366219ae553a8681194274b3fe54bbd7c5cf107fd9635cc89862e4d3fd87"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.romeos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 85c0 0f85ef000000 85db 751d 807c244802 0f85e0000000 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f85ef000000         | jne                 0xf5
            //   85db                 | test                ebx, ebx
            //   751d                 | jne                 0x1f
            //   807c244802           | cmp                 byte ptr [esp + 0x48], 2
            //   0f85e0000000         | jne                 0xe6

        $sequence_1 = { 85c0 0f850d010000 33db 6a16 8d4c244c 6800200000 51 }
            // n = 7, score = 400
            //   85c0                 | test                eax, eax
            //   0f850d010000         | jne                 0x113
            //   33db                 | xor                 ebx, ebx
            //   6a16                 | push                0x16
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   6800200000           | push                0x2000
            //   51                   | push                ecx

        $sequence_2 = { 6a16 8d4c2420 55 51 57 8bce e8???????? }
            // n = 7, score = 400
            //   6a16                 | push                0x16
            //   8d4c2420             | lea                 ecx, [esp + 0x20]
            //   55                   | push                ebp
            //   51                   | push                ecx
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_3 = { 33c0 8d7c2449 c644244800 6a16 }
            // n = 4, score = 400
            //   33c0                 | xor                 eax, eax
            //   8d7c2449             | lea                 edi, [esp + 0x49]
            //   c644244800           | mov                 byte ptr [esp + 0x48], 0
            //   6a16                 | push                0x16

        $sequence_4 = { 3bdd 7cf2 8b542414 6a16 8d44244c }
            // n = 5, score = 400
            //   3bdd                 | cmp                 ebx, ebp
            //   7cf2                 | jl                  0xfffffff4
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   6a16                 | push                0x16
            //   8d44244c             | lea                 eax, [esp + 0x4c]

        $sequence_5 = { 8d542414 8d442448 52 50 e8???????? }
            // n = 5, score = 400
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   8d442448             | lea                 eax, [esp + 0x48]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_6 = { 50 57 e8???????? 85c0 0f850d010000 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   57                   | push                edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f850d010000         | jne                 0x113

        $sequence_7 = { c644241701 50 bd30000000 e8???????? 8bbc2454200000 83c404 }
            // n = 6, score = 400
            //   c644241701           | mov                 byte ptr [esp + 0x17], 1
            //   50                   | push                eax
            //   bd30000000           | mov                 ebp, 0x30
            //   e8????????           |                     
            //   8bbc2454200000       | mov                 edi, dword ptr [esp + 0x2054]
            //   83c404               | add                 esp, 4

        $sequence_8 = { c644245c2e c644245d64 885c245e 885c245f }
            // n = 4, score = 200
            //   c644245c2e           | mov                 byte ptr [esp + 0x5c], 0x2e
            //   c644245d64           | mov                 byte ptr [esp + 0x5d], 0x64
            //   885c245e             | mov                 byte ptr [esp + 0x5e], bl
            //   885c245f             | mov                 byte ptr [esp + 0x5f], bl

        $sequence_9 = { 89442418 e8???????? 6802020000 55 }
            // n = 4, score = 200
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   e8????????           |                     
            //   6802020000           | push                0x202
            //   55                   | push                ebp

        $sequence_10 = { 89442410 8b442414 8d542468 52 50 ff15???????? }
            // n = 6, score = 200
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8d542468             | lea                 edx, [esp + 0x68]
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_11 = { c644247475 c644247574 884c2476 88442477 }
            // n = 4, score = 200
            //   c644247475           | mov                 byte ptr [esp + 0x74], 0x75
            //   c644247574           | mov                 byte ptr [esp + 0x75], 0x74
            //   884c2476             | mov                 byte ptr [esp + 0x76], cl
            //   88442477             | mov                 byte ptr [esp + 0x77], al

        $sequence_12 = { 7508 ff15???????? 8bf0 3b7c2410 7408 }
            // n = 5, score = 200
            //   7508                 | jne                 0xa
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   3b7c2410             | cmp                 edi, dword ptr [esp + 0x10]
            //   7408                 | je                  0xa

        $sequence_13 = { ffd7 8bf0 85f6 7447 8b3d???????? 6820590110 }
            // n = 6, score = 200
            //   ffd7                 | call                edi
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7447                 | je                  0x49
            //   8b3d????????         |                     
            //   6820590110           | push                0x10015920

        $sequence_14 = { 8d94241c010000 68ff000000 8d442414 52 }
            // n = 4, score = 200
            //   8d94241c010000       | lea                 edx, [esp + 0x11c]
            //   68ff000000           | push                0xff
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   52                   | push                edx

        $sequence_15 = { 6a01 51 c744242c0c000000 89742430 895c2434 }
            // n = 5, score = 200
            //   6a01                 | push                1
            //   51                   | push                ecx
            //   c744242c0c000000     | mov                 dword ptr [esp + 0x2c], 0xc
            //   89742430             | mov                 dword ptr [esp + 0x30], esi
            //   895c2434             | mov                 dword ptr [esp + 0x34], ebx

    condition:
        7 of them and filesize < 294912
}
