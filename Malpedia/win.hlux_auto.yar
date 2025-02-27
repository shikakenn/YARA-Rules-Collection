rule win_hlux_auto {

    meta:
        id = "5y1aTQpJv3oXo7QqPaOdGT"
        fingerprint = "v1_sha256_6289602931f864ef390f887bdc3596feba8613d121e8e169b915693bee14e183"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hlux."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hlux"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0009 1b4e01 e405 9d }
            // n = 4, score = 100
            //   0009                 | add                 byte ptr [ecx], cl
            //   1b4e01               | sbb                 ecx, dword ptr [esi + 1]
            //   e405                 | in                  al, 5
            //   9d                   | popfd               

        $sequence_1 = { 0101 c9 c3 6a10 }
            // n = 4, score = 100
            //   0101                 | add                 dword ptr [ecx], eax
            //   c9                   | leave               
            //   c3                   | ret                 
            //   6a10                 | push                0x10

        $sequence_2 = { 0104bb 8d1447 89542418 e9???????? }
            // n = 4, score = 100
            //   0104bb               | add                 dword ptr [ebx + edi*4], eax
            //   8d1447               | lea                 edx, [edi + eax*2]
            //   89542418             | mov                 dword ptr [esp + 0x18], edx
            //   e9????????           |                     

        $sequence_3 = { 8b8d84feffff 898d84feffff 8b0d???????? 8b1d???????? 899d0cffffff 898d64ffffff }
            // n = 6, score = 100
            //   8b8d84feffff         | mov                 ecx, dword ptr [ebp - 0x17c]
            //   898d84feffff         | mov                 dword ptr [ebp - 0x17c], ecx
            //   8b0d????????         |                     
            //   8b1d????????         |                     
            //   899d0cffffff         | mov                 dword ptr [ebp - 0xf4], ebx
            //   898d64ffffff         | mov                 dword ptr [ebp - 0x9c], ecx

        $sequence_4 = { 0000 008365f0fe8b 4d 0883c108e918 }
            // n = 4, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al
            //   4d                   | dec                 ebp
            //   0883c108e918         | or                  byte ptr [ebx + 0x18e908c1], al

        $sequence_5 = { 0130 8b13 8b08 85d2 }
            // n = 4, score = 100
            //   0130                 | add                 dword ptr [eax], esi
            //   8b13                 | mov                 edx, dword ptr [ebx]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   85d2                 | test                edx, edx

        $sequence_6 = { 8975fc 57 33d2 81fac4f4b942 741d 8d7a6f }
            // n = 6, score = 100
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   57                   | push                edi
            //   33d2                 | xor                 edx, edx
            //   81fac4f4b942         | cmp                 edx, 0x42b9f4c4
            //   741d                 | je                  0x1f
            //   8d7a6f               | lea                 edi, [edx + 0x6f]

        $sequence_7 = { 53 bb36194608 895dcc 56 33d2 33f6 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   bb36194608           | mov                 ebx, 0x8461936
            //   895dcc               | mov                 dword ptr [ebp - 0x34], ebx
            //   56                   | push                esi
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi

        $sequence_8 = { 010f 840f 0000 008365f0fe8b }
            // n = 4, score = 100
            //   010f                 | add                 dword ptr [edi], ecx
            //   840f                 | test                byte ptr [edi], cl
            //   0000                 | add                 byte ptr [eax], al
            //   008365f0fe8b         | add                 byte ptr [ebx - 0x74010f9b], al

        $sequence_9 = { 895584 bb2672b397 83fbab 7406 899d44ffffff 09c9 7506 }
            // n = 7, score = 100
            //   895584               | mov                 dword ptr [ebp - 0x7c], edx
            //   bb2672b397           | mov                 ebx, 0x97b37226
            //   83fbab               | cmp                 ebx, -0x55
            //   7406                 | je                  8
            //   899d44ffffff         | mov                 dword ptr [ebp - 0xbc], ebx
            //   09c9                 | or                  ecx, ecx
            //   7506                 | jne                 8

        $sequence_10 = { 8985f0feffff 33d2 33f6 81fe61979899 7428 81faa5601b7b }
            // n = 6, score = 100
            //   8985f0feffff         | mov                 dword ptr [ebp - 0x110], eax
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi
            //   81fe61979899         | cmp                 esi, 0x99989761
            //   7428                 | je                  0x2a
            //   81faa5601b7b         | cmp                 edx, 0x7b1b60a5

        $sequence_11 = { bf81b805ef 81f876496748 744d 8b15???????? }
            // n = 4, score = 100
            //   bf81b805ef           | mov                 edi, 0xef05b881
            //   81f876496748         | cmp                 eax, 0x48674976
            //   744d                 | je                  0x4f
            //   8b15????????         |                     

        $sequence_12 = { 21f6 7427 83f8af 7422 }
            // n = 4, score = 100
            //   21f6                 | and                 esi, esi
            //   7427                 | je                  0x29
            //   83f8af               | cmp                 eax, -0x51
            //   7422                 | je                  0x24

        $sequence_13 = { 0088aa4b0023 d18a0688078a 46 018847018a46 }
            // n = 4, score = 100
            //   0088aa4b0023         | add                 byte ptr [eax + 0x23004baa], cl
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1
            //   46                   | inc                 esi
            //   018847018a46         | add                 dword ptr [eax + 0x468a0147], ecx

        $sequence_14 = { 7506 89b588feffff 83f922 0f8501010000 8b05???????? 897dc8 }
            // n = 6, score = 100
            //   7506                 | jne                 8
            //   89b588feffff         | mov                 dword ptr [ebp - 0x178], esi
            //   83f922               | cmp                 ecx, 0x22
            //   0f8501010000         | jne                 0x107
            //   8b05????????         |                     
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi

        $sequence_15 = { 0104b9 33c9 83c408 85c0 }
            // n = 4, score = 100
            //   0104b9               | add                 dword ptr [ecx + edi*4], eax
            //   33c9                 | xor                 ecx, ecx
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 3147776
}
