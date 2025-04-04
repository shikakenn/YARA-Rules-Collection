rule win_babar_auto {

    meta:
        id = "5XOFjm4DuvXI1m2lNboLLW"
        fingerprint = "v1_sha256_f26db48f4ddda7baab96557200e3865f1c9bdc6e10a7518d2cd23d9a8273c7f2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.babar."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.babar"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 3bd6 0f8c7affffff 8bbc24d0000000 ddd9 }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   0f8c7affffff         | jl                  0xffffff80
            //   8bbc24d0000000       | mov                 edi, dword ptr [esp + 0xd0]
            //   ddd9                 | fstp                st(1)

        $sequence_1 = { 3bd5 7e47 8d0c9500000000 2bd9 83c304 2bd5 }
            // n = 6, score = 400
            //   3bd5                 | cmp                 edx, ebp
            //   7e47                 | jle                 0x49
            //   8d0c9500000000       | lea                 ecx, [edx*4]
            //   2bd9                 | sub                 ebx, ecx
            //   83c304               | add                 ebx, 4
            //   2bd5                 | sub                 edx, ebp

        $sequence_2 = { 3bd6 0f82eefeffff 8b742458 03f5 }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   0f82eefeffff         | jb                  0xfffffef4
            //   8b742458             | mov                 esi, dword ptr [esp + 0x58]
            //   03f5                 | add                 esi, ebp

        $sequence_3 = { 3bd6 7503 8d5014 895010 }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   7503                 | jne                 5
            //   8d5014               | lea                 edx, [eax + 0x14]
            //   895010               | mov                 dword ptr [eax + 0x10], edx

        $sequence_4 = { 3bd6 0f86f9feffff 8b54243c 8b442438 }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   0f86f9feffff         | jbe                 0xfffffeff
            //   8b54243c             | mov                 edx, dword ptr [esp + 0x3c]
            //   8b442438             | mov                 eax, dword ptr [esp + 0x38]

        $sequence_5 = { 3bd6 72d9 33f6 eb08 }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   72d9                 | jb                  0xffffffdb
            //   33f6                 | xor                 esi, esi
            //   eb08                 | jmp                 0xa

        $sequence_6 = { 3bd6 721b 57 8bcb }
            // n = 4, score = 400
            //   3bd6                 | cmp                 edx, esi
            //   721b                 | jb                  0x1d
            //   57                   | push                edi
            //   8bcb                 | mov                 ecx, ebx

        $sequence_7 = { 46 8d44bb08 8d5308 8d0cb7 }
            // n = 4, score = 400
            //   46                   | inc                 esi
            //   8d44bb08             | lea                 eax, [ebx + edi*4 + 8]
            //   8d5308               | lea                 edx, [ebx + 8]
            //   8d0cb7               | lea                 ecx, [edi + esi*4]

        $sequence_8 = { a3???????? 33c0 c3 8bc1 8b4c2404 c700???????? }
            // n = 6, score = 200
            //   a3????????           |                     
            //   33c0                 | xor                 eax, eax
            //   c3                   | ret                 
            //   8bc1                 | mov                 eax, ecx
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]
            //   c700????????         |                     

        $sequence_9 = { 7708 0fb6c9 83e947 eb28 8ad1 80ea30 80fa09 }
            // n = 7, score = 200
            //   7708                 | ja                  0xa
            //   0fb6c9               | movzx               ecx, cl
            //   83e947               | sub                 ecx, 0x47
            //   eb28                 | jmp                 0x2a
            //   8ad1                 | mov                 dl, cl
            //   80ea30               | sub                 dl, 0x30
            //   80fa09               | cmp                 dl, 9

        $sequence_10 = { ffd6 83c001 50 e8???????? 8b15???????? 83c404 }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   83c001               | add                 eax, 1
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b15????????         |                     
            //   83c404               | add                 esp, 4

        $sequence_11 = { c744242c00000000 ffd3 83c410 85ff 0f848d010000 e8???????? }
            // n = 6, score = 200
            //   c744242c00000000     | mov                 dword ptr [esp + 0x2c], 0
            //   ffd3                 | call                ebx
            //   83c410               | add                 esp, 0x10
            //   85ff                 | test                edi, edi
            //   0f848d010000         | je                  0x193
            //   e8????????           |                     

        $sequence_12 = { ff15???????? 8b1424 52 ff15???????? 33c0 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8b1424               | mov                 edx, dword ptr [esp]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_13 = { 8b0d???????? 894f08 8b8c2450010000 8bc7 5f 5e }
            // n = 6, score = 200
            //   8b0d????????         |                     
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   8b8c2450010000       | mov                 ecx, dword ptr [esp + 0x150]
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_14 = { c1c90b 8bfa 03ce f7d7 0bf9 }
            // n = 5, score = 200
            //   c1c90b               | ror                 ecx, 0xb
            //   8bfa                 | mov                 edi, edx
            //   03ce                 | add                 ecx, esi
            //   f7d7                 | not                 edi
            //   0bf9                 | or                  edi, ecx

        $sequence_15 = { e8???????? 8b8c2418010000 83c40c 5f }
            // n = 4, score = 200
            //   e8????????           |                     
            //   8b8c2418010000       | mov                 ecx, dword ptr [esp + 0x118]
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 1294336
}
