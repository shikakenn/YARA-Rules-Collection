rule win_gratem_auto {

    meta:
        id = "1X0gnjjAQX2gfVyaaFVZZv"
        fingerprint = "v1_sha256_b58ab0ade84c3286830362f0f11bfb9519b8733c76dfe4e9cd7ba24746663e50"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.gratem."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gratem"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c744242404000000 ffd5 85c0 0f84b2000000 }
            // n = 4, score = 100
            //   c744242404000000     | mov                 dword ptr [esp + 0x24], 4
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax
            //   0f84b2000000         | je                  0xb8

        $sequence_1 = { 884e13 66a1???????? 33c9 6685c0 741f 0fb7c0 ba000c0000 }
            // n = 7, score = 100
            //   884e13               | mov                 byte ptr [esi + 0x13], cl
            //   66a1????????         |                     
            //   33c9                 | xor                 ecx, ecx
            //   6685c0               | test                ax, ax
            //   741f                 | je                  0x21
            //   0fb7c0               | movzx               eax, ax
            //   ba000c0000           | mov                 edx, 0xc00

        $sequence_2 = { ff15???????? 8b442414 50 ff15???????? 8b5c2410 56 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]
            //   56                   | push                esi

        $sequence_3 = { 85c0 7405 e8???????? 8b8c24d4070000 5e 33cc }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   e8????????           |                     
            //   8b8c24d4070000       | mov                 ecx, dword ptr [esp + 0x7d4]
            //   5e                   | pop                 esi
            //   33cc                 | xor                 ecx, esp

        $sequence_4 = { 663bc2 0f84ac030000 0fb7048d64bc4000 41 }
            // n = 4, score = 100
            //   663bc2               | cmp                 ax, dx
            //   0f84ac030000         | je                  0x3b2
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]
            //   41                   | inc                 ecx

        $sequence_5 = { 8b4c2440 8b542418 894114 895110 }
            // n = 4, score = 100
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   894114               | mov                 dword ptr [ecx + 0x14], eax
            //   895110               | mov                 dword ptr [ecx + 0x10], edx

        $sequence_6 = { 6a00 50 e8???????? 83c40c 6805010000 8d4c2404 51 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6805010000           | push                0x105
            //   8d4c2404             | lea                 ecx, [esp + 4]
            //   51                   | push                ecx

        $sequence_7 = { 53 ff54244c 85c0 8b442414 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   ff54244c             | call                dword ptr [esp + 0x4c]
            //   85c0                 | test                eax, eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_8 = { 0fb7c0 baa8540000 663bc2 0f8420050000 0fb7048d64bc4000 41 }
            // n = 6, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   baa8540000           | mov                 edx, 0x54a8
            //   663bc2               | cmp                 ax, dx
            //   0f8420050000         | je                  0x526
            //   0fb7048d64bc4000     | movzx               eax, word ptr [ecx*4 + 0x40bc64]
            //   41                   | inc                 ecx

        $sequence_9 = { 56 8d34c5c0b84000 833e00 7513 50 e8???????? }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d34c5c0b84000       | lea                 esi, [eax*8 + 0x40b8c0]
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7513                 | jne                 0x15
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 155648
}
