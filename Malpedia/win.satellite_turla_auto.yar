rule win_satellite_turla_auto {

    meta:
        id = "3IwVU5gUXUt4ZEqXVWno5v"
        fingerprint = "v1_sha256_e5dfd974166d3696682fe85d3bf761357a2cf777cf6c86d583494170169c67ee"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.satellite_turla."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satellite_turla"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0105???????? 81c3b0020000 2945e0 75ae 837dd400 }
            // n = 5, score = 200
            //   0105????????         |                     
            //   81c3b0020000         | add                 ebx, 0x2b0
            //   2945e0               | sub                 dword ptr [ebp - 0x20], eax
            //   75ae                 | jne                 0xffffffb0
            //   837dd400             | cmp                 dword ptr [ebp - 0x2c], 0

        $sequence_1 = { 0105???????? 83c410 29442418 75a9 }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442418             | sub                 dword ptr [esp + 0x18], eax
            //   75a9                 | jne                 0xffffffab

        $sequence_2 = { 0105???????? 83c410 29442420 75aa }
            // n = 4, score = 200
            //   0105????????         |                     
            //   83c410               | add                 esp, 0x10
            //   29442420             | sub                 dword ptr [esp + 0x20], eax
            //   75aa                 | jne                 0xffffffac

        $sequence_3 = { 0108 833a00 7c23 8b442428 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833a00               | cmp                 dword ptr [edx], 0
            //   7c23                 | jl                  0x25
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]

        $sequence_4 = { 0108 833e00 7fc7 db46fc }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7fc7                 | jg                  0xffffffc9
            //   db46fc               | fild                dword ptr [esi - 4]

        $sequence_5 = { 0108 833e00 7c1f 8b542410 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7c1f                 | jl                  0x21
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_6 = { 0108 833e00 7cc7 7e39 }
            // n = 4, score = 200
            //   0108                 | add                 dword ptr [eax], ecx
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7cc7                 | jl                  0xffffffc9
            //   7e39                 | jle                 0x3b

        $sequence_7 = { 51 8d9514fbffff 52 a1???????? 50 ff15???????? 3bc3 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   8d9514fbffff         | lea                 edx, [ebp - 0x4ec]
            //   52                   | push                edx
            //   a1????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx

        $sequence_8 = { c6459d1f c6459e19 c6459f02 c645a009 c645a11e c645a21f c645a30e }
            // n = 7, score = 100
            //   c6459d1f             | mov                 byte ptr [ebp - 0x63], 0x1f
            //   c6459e19             | mov                 byte ptr [ebp - 0x62], 0x19
            //   c6459f02             | mov                 byte ptr [ebp - 0x61], 2
            //   c645a009             | mov                 byte ptr [ebp - 0x60], 9
            //   c645a11e             | mov                 byte ptr [ebp - 0x5f], 0x1e
            //   c645a21f             | mov                 byte ptr [ebp - 0x5e], 0x1f
            //   c645a30e             | mov                 byte ptr [ebp - 0x5d], 0xe

        $sequence_9 = { 6a0c 50 c645d036 c645d114 }
            // n = 4, score = 100
            //   6a0c                 | push                0xc
            //   50                   | push                eax
            //   c645d036             | mov                 byte ptr [ebp - 0x30], 0x36
            //   c645d114             | mov                 byte ptr [ebp - 0x2f], 0x14

        $sequence_10 = { ff15???????? 85c0 0f8400010000 895dfc }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8400010000         | je                  0x106
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx

        $sequence_11 = { 8d85f0feffff 6a5c 50 e8???????? 59 885801 }
            // n = 6, score = 100
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   6a5c                 | push                0x5c
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   885801               | mov                 byte ptr [eax + 1], bl

        $sequence_12 = { 57 ff15???????? ff75f8 e8???????? 59 33c0 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 57 ffd6 a3???????? 6a28 8d45dc }
            // n = 5, score = 100
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   a3????????           |                     
            //   6a28                 | push                0x28
            //   8d45dc               | lea                 eax, [ebp - 0x24]

        $sequence_14 = { ffd7 8d85f0feffff 50 56 }
            // n = 4, score = 100
            //   ffd7                 | call                edi
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_15 = { c645b62b c645b72b e8???????? 83c40c 8d45a8 885db7 50 }
            // n = 7, score = 100
            //   c645b62b             | mov                 byte ptr [ebp - 0x4a], 0x2b
            //   c645b72b             | mov                 byte ptr [ebp - 0x49], 0x2b
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   885db7               | mov                 byte ptr [ebp - 0x49], bl
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1040384
}
