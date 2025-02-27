rule win_uacme_auto {

    meta:
        id = "GgO52E3Xp3jo3nXubB0Ta"
        fingerprint = "v1_sha256_07027ccb25725e405fe664bc8c5892aae7b19e4bf0683cd3f46495797cb60d93"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.uacme."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.uacme"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 85c0 7515 834dfcff 56 8b7514 85f6 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7515                 | jne                 0x17
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff
            //   56                   | push                esi
            //   8b7514               | mov                 esi, dword ptr [ebp + 0x14]
            //   85f6                 | test                esi, esi

        $sequence_1 = { 8d85fcfeffff 50 ff15???????? 8a85fcfeffff 8d95fcfeffff }
            // n = 5, score = 100
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8a85fcfeffff         | mov                 al, byte ptr [ebp - 0x104]
            //   8d95fcfeffff         | lea                 edx, [ebp - 0x104]

        $sequence_2 = { 8d45a8 50 ff15???????? 8d45f0 50 }
            // n = 5, score = 100
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_3 = { 56 ff15???????? 68???????? 6806600000 56 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   ff15????????         |                     
            //   68????????           |                     
            //   6806600000           | push                0x6006
            //   56                   | push                esi

        $sequence_4 = { 53 c744247030000000 c744247420000000 c744247897344000 895c247c 899c2480000000 89bc2484000000 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   c744247030000000     | mov                 dword ptr [esp + 0x70], 0x30
            //   c744247420000000     | mov                 dword ptr [esp + 0x74], 0x20
            //   c744247897344000     | mov                 dword ptr [esp + 0x78], 0x403497
            //   895c247c             | mov                 dword ptr [esp + 0x7c], ebx
            //   899c2480000000       | mov                 dword ptr [esp + 0x80], ebx
            //   89bc2484000000       | mov                 dword ptr [esp + 0x84], edi

        $sequence_5 = { 50 57 ff15???????? 8d4c2428 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8d4c2428             | lea                 ecx, [esp + 0x28]

        $sequence_6 = { 750d ffd6 3db7000000 0f8567010000 ba???????? 8d8ddcfbffff e8???????? }
            // n = 7, score = 100
            //   750d                 | jne                 0xf
            //   ffd6                 | call                esi
            //   3db7000000           | cmp                 eax, 0xb7
            //   0f8567010000         | jne                 0x16d
            //   ba????????           |                     
            //   8d8ddcfbffff         | lea                 ecx, [ebp - 0x424]
            //   e8????????           |                     

        $sequence_7 = { 52 57 57 53 51 ff500c }
            // n = 6, score = 100
            //   52                   | push                edx
            //   57                   | push                edi
            //   57                   | push                edi
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   ff500c               | call                dword ptr [eax + 0xc]

        $sequence_8 = { 83f915 89742420 0f44c6 895c2414 a3???????? }
            // n = 5, score = 100
            //   83f915               | cmp                 ecx, 0x15
            //   89742420             | mov                 dword ptr [esp + 0x20], esi
            //   0f44c6               | cmove               eax, esi
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   a3????????           |                     

        $sequence_9 = { 75f7 8b4dfc ba???????? 8d4930 e8???????? 8b4dfc ba???????? }
            // n = 7, score = 100
            //   75f7                 | jne                 0xfffffff9
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   ba????????           |                     
            //   8d4930               | lea                 ecx, [ecx + 0x30]
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   ba????????           |                     

    condition:
        7 of them and filesize < 565248
}
