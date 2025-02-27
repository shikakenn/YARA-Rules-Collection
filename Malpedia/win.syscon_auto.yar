rule win_syscon_auto {

    meta:
        id = "1NbGBJqlxHxCNDHEf3W3K9"
        fingerprint = "v1_sha256_302ef373551197e8ed957c8603c0bcf0757f29f0db7a8e8349d7ddb01c77aa30"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.syscon."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.syscon"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6a00 6a00 6a01 6a00 ff15???????? a3???????? }
            // n = 7, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_1 = { 68???????? 68???????? 8818 ff15???????? 68???????? ffd6 53 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   8818                 | mov                 byte ptr [eax], bl
            //   ff15????????         |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   53                   | push                ebx

        $sequence_2 = { 52 8845ff ffd7 0fb64e02 ba???????? 51 2ac2 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8845ff               | mov                 byte ptr [ebp - 1], al
            //   ffd7                 | call                edi
            //   0fb64e02             | movzx               ecx, byte ptr [esi + 2]
            //   ba????????           |                     
            //   51                   | push                ecx
            //   2ac2                 | sub                 al, dl

        $sequence_3 = { ffd3 83f8ff 74d3 50 ff15???????? 8d442418 }
            // n = 6, score = 200
            //   ffd3                 | call                ebx
            //   83f8ff               | cmp                 eax, -1
            //   74d3                 | je                  0xffffffd5
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d442418             | lea                 eax, [esp + 0x18]

        $sequence_4 = { 898424d80b0000 53 56 57 8b3d???????? }
            // n = 5, score = 200
            //   898424d80b0000       | mov                 dword ptr [esp + 0xbd8], eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b3d????????         |                     

        $sequence_5 = { 68???????? 57 ffd3 8bf0 8bd6 2bd7 42 }
            // n = 7, score = 200
            //   68????????           |                     
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   8bf0                 | mov                 esi, eax
            //   8bd6                 | mov                 edx, esi
            //   2bd7                 | sub                 edx, edi
            //   42                   | inc                 edx

        $sequence_6 = { 55 8bec 8b4508 48 7458 83e803 }
            // n = 6, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   48                   | dec                 eax
            //   7458                 | je                  0x5a
            //   83e803               | sub                 eax, 3

        $sequence_7 = { 53 68???????? 53 53 891d???????? ff15???????? }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   68????????           |                     
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   891d????????         |                     
            //   ff15????????         |                     

        $sequence_8 = { ff15???????? 488d542420 488d0df6500000 448bc0 e8???????? 488d542420 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488d542420           | dec                 eax
            //   488d0df6500000       | mov                 ebx, dword ptr [ebp + 0xfd0]
            //   448bc0               | dec                 eax
            //   e8????????           |                     
            //   488d542420           | lea                 edx, [ebp + 0x360]

        $sequence_9 = { 41be01000000 488b9dd00f0000 488d9560030000 498bcd ff15???????? }
            // n = 5, score = 100
            //   41be01000000         | mov                 dword ptr [esp + 8], ebx
            //   488b9dd00f0000       | dec                 eax
            //   488d9560030000       | mov                 dword ptr [esp + 0x10], esi
            //   498bcd               | movzx               edx, word ptr [esp + 0x66]
            //   ff15????????         |                     

        $sequence_10 = { ff15???????? 488905???????? 4885c0 0f845af5ffff }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488905????????       |                     
            //   4885c0               | inc                 esp
            //   0f845af5ffff         | movzx               ebx, word ptr [esp + 0x6c]

        $sequence_11 = { 4c89742440 4c89742438 c744243000000008 4489742428 4c89742420 ff15???????? 488b8d700c0000 }
            // n = 7, score = 100
            //   4c89742440           | dec                 esp
            //   4c89742438           | mov                 dword ptr [esp + 0x40], esi
            //   c744243000000008     | dec                 esp
            //   4489742428           | mov                 dword ptr [esp + 0x38], esi
            //   4c89742420           | mov                 dword ptr [esp + 0x30], 0x8000000
            //   ff15????????         |                     
            //   488b8d700c0000       | inc                 esp

        $sequence_12 = { ff15???????? 488d9520040000 488d0dd32e0000 448bc0 e8???????? 488d5590 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488d9520040000       | mov                 dword ptr [esp + 0x38], ebx
            //   488d0dd32e0000       | mov                 dword ptr [esp + 0x30], eax
            //   448bc0               | inc                 ecx
            //   e8????????           |                     
            //   488d5590             | mov                 esi, 1

        $sequence_13 = { e8???????? 488d9560010000 488d4c2450 e8???????? e9???????? 48895c2408 4889742410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d9560010000       | mov                 dword ptr [esp + 0x28], esi
            //   488d4c2450           | dec                 esp
            //   e8????????           |                     
            //   e9????????           |                     
            //   48895c2408           | mov                 dword ptr [esp + 0x20], esi
            //   4889742410           | dec                 eax

        $sequence_14 = { 0fb7542466 440fb75c246c 0fb744246a 440fb74c2462 44895c2438 89442430 }
            // n = 6, score = 100
            //   0fb7542466           | mov                 ecx, dword ptr [ebp + 0xc70]
            //   440fb75c246c         | dec                 eax
            //   0fb744246a           | lea                 edx, [ebp + 0x160]
            //   440fb74c2462         | dec                 eax
            //   44895c2438           | lea                 ecx, [esp + 0x50]
            //   89442430             | dec                 eax

        $sequence_15 = { 488d8d10020000 ff15???????? 488d4d90 448bc3 33d2 }
            // n = 5, score = 100
            //   488d8d10020000       | movzx               eax, word ptr [esp + 0x6a]
            //   ff15????????         |                     
            //   488d4d90             | inc                 esp
            //   448bc3               | movzx               ecx, word ptr [esp + 0x62]
            //   33d2                 | inc                 esp

    condition:
        7 of them and filesize < 120832
}
