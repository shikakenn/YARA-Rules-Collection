rule win_puzzlemaker_auto {

    meta:
        id = "5JWte2ii7lbYztCIM4JYWx"
        fingerprint = "v1_sha256_59c32899b883bfb9bd7e74e09947139de6a13e19aa30e115675dc0025c3e011c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.puzzlemaker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.puzzlemaker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f830c020000 4c8b7da8 4c8d0529b5ffff 8b4590 }
            // n = 4, score = 100
            //   0f830c020000         | inc                 edx
            //   4c8b7da8             | movzx               ecx, byte ptr [edx + edx]
            //   4c8d0529b5ffff       | nop                 dword ptr [eax]
            //   8b4590               | nop                 word ptr [eax + eax]

        $sequence_1 = { 4c8d0500aaffff 48895108 0fb60a 83e10f 4a0fbe8401b8640100 }
            // n = 5, score = 100
            //   4c8d0500aaffff       | lea                 ecx, [eax + 2]
            //   48895108             | test                eax, eax
            //   0fb60a               | je                  0xb2d
            //   83e10f               | cmp                 eax, 1
            //   4a0fbe8401b8640100     | inc    ecx

        $sequence_2 = { 8bd9 488d15d6060100 33c9 ff15???????? 85c0 }
            // n = 5, score = 100
            //   8bd9                 | lea                 edx, [0x215a6]
            //   488d15d6060100       | dec                 eax
            //   33c9                 | sub                 esp, 0x28
            //   ff15????????         |                     
            //   85c0                 | dec                 eax

        $sequence_3 = { 488b8d00020000 ff15???????? 4585f6 740a 4183ff0f 0f8284fdffff }
            // n = 6, score = 100
            //   488b8d00020000       | dec                 eax
            //   ff15????????         |                     
            //   4585f6               | lea                 edx, [0x88c1]
            //   740a                 | dec                 esp
            //   4183ff0f             | lea                 ecx, [0x2035d]
            //   0f8284fdffff         | dec                 eax

        $sequence_4 = { 498bd8 4c8bd2 0f84ac000000 4c634910 4c8d35c2bbffff 488b7a08 33f6 }
            // n = 7, score = 100
            //   498bd8               | dec                 esp
            //   4c8bd2               | mov                 eax, dword ptr [ebp - 0x70]
            //   0f84ac000000         | dec                 esp
            //   4c634910             | lea                 ecx, [0xffffb13b]
            //   4c8d35c2bbffff       | psrldq              xmm0, 8
            //   488b7a08             | movd                eax, xmm0
            //   33f6                 | cmp                 eax, dword ptr [ebp - 0x40]

        $sequence_5 = { 4883f8ff 74c8 488bd3 4c8d0502f20000 }
            // n = 4, score = 100
            //   4883f8ff             | inc                 esp
            //   74c8                 | mov                 dword ptr [esp + 0x44], ebp
            //   488bd3               | inc                 ecx
            //   4c8d0502f20000       | lea                 eax, [ebp - 1]

        $sequence_6 = { 4883ec58 488b05???????? 4833c4 4889442440 e8???????? 488d05a1fdffff }
            // n = 6, score = 100
            //   4883ec58             | movsx               edx, byte ptr [ecx + esi + 0x164b8]
            //   488b05????????       |                     
            //   4833c4               | inc                 edx
            //   4889442440           | mov                 cl, byte ptr [ecx + esi + 0x164c8]
            //   e8????????           |                     
            //   488d05a1fdffff       | dec                 esp

        $sequence_7 = { 77ae 2bd1 83fa0f 777a 8b8c96101a0100 4803ce }
            // n = 6, score = 100
            //   77ae                 | dec                 eax
            //   2bd1                 | mov                 dword ptr [ebp - 0x80], eax
            //   83fa0f               | dec                 ecx
            //   777a                 | mov                 ecx, edi
            //   8b8c96101a0100       | dec                 eax
            //   4803ce               | mov                 ecx, dword ptr [ebp - 0x21]

        $sequence_8 = { 488b11 ff5210 ff15???????? b801000000 488b4d1f }
            // n = 5, score = 100
            //   488b11               | dec                 eax
            //   ff5210               | lea                 eax, [0x20481]
            //   ff15????????         |                     
            //   b801000000           | ret                 
            //   488b4d1f             | ret                 

        $sequence_9 = { 4181f804010000 72e1 448bc0 4c8d0d1f0e0200 }
            // n = 4, score = 100
            //   4181f804010000       | xor                 ebx, ebx
            //   72e1                 | dec                 esp
            //   448bc0               | lea                 esi, [0xffff16ed]
            //   4c8d0d1f0e0200       | dec                 eax

    condition:
        7 of them and filesize < 331776
}
