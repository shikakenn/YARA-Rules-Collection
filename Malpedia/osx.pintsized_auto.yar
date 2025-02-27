rule osx_pintsized_auto {

    meta:
        id = "3GzsbOmMIiOnepTflXbTSE"
        fingerprint = "v1_sha256_f6f8451dcaf8a0e8a23839854adf11c3529a096c294f92142eca03394816d8fa"
        version = "1"
        date = "2020-10-14"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.pintsized"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d09 48 39c8 741b 48 8b45d0 48 }
            // n = 7, score = 100
            //   8d09                 | lea                 ecx, [ecx]
            //   48                   | dec                 eax
            //   39c8                 | cmp                 eax, ecx
            //   741b                 | je                  0x1d
            //   48                   | dec                 eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   48                   | dec                 eax

        $sequence_1 = { 48 8b45e8 48 8b80b0000000 48 89c7 e8???????? }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   48                   | dec                 eax
            //   8b80b0000000         | mov                 eax, dword ptr [eax + 0xb0]
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     

        $sequence_2 = { 48 8b45d0 48 89c7 e8???????? c745e400000000 eb2a }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b45d0               | mov                 eax, dword ptr [ebp - 0x30]
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   eb2a                 | jmp                 0x2c

        $sequence_3 = { eb7c c745f008070000 eb73 c745f060090000 eb6a c745f0c0120000 eb61 }
            // n = 7, score = 100
            //   eb7c                 | jmp                 0x7e
            //   c745f008070000       | mov                 dword ptr [ebp - 0x10], 0x708
            //   eb73                 | jmp                 0x75
            //   c745f060090000       | mov                 dword ptr [ebp - 0x10], 0x960
            //   eb6a                 | jmp                 0x6c
            //   c745f0c0120000       | mov                 dword ptr [ebp - 0x10], 0x12c0
            //   eb61                 | jmp                 0x63

        $sequence_4 = { 8b45f8 48 89c7 e8???????? c745e801000000 8b45e8 8945ec }
            // n = 7, score = 100
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   48                   | dec                 eax
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_5 = { 898d00ffffff 48 8995f8feffff 48 89b5f0feffff 0f2985e0feffff 0f298dd0feffff }
            // n = 7, score = 100
            //   898d00ffffff         | mov                 dword ptr [ebp - 0x100], ecx
            //   48                   | dec                 eax
            //   8995f8feffff         | mov                 dword ptr [ebp - 0x108], edx
            //   48                   | dec                 eax
            //   89b5f0feffff         | mov                 dword ptr [ebp - 0x110], esi
            //   0f2985e0feffff       | movaps              xmmword ptr [ebp - 0x120], xmm0
            //   0f298dd0feffff       | movaps              xmmword ptr [ebp - 0x130], xmm1

        $sequence_6 = { 83f900 751d 48 8d0521bb0100 48 8d0d8ebb0100 30d2 }
            // n = 7, score = 100
            //   83f900               | cmp                 ecx, 0
            //   751d                 | jne                 0x1f
            //   48                   | dec                 eax
            //   8d0521bb0100         | lea                 eax, [0x1bb21]
            //   48                   | dec                 eax
            //   8d0d8ebb0100         | lea                 ecx, [0x1bb8e]
            //   30d2                 | xor                 dl, dl

        $sequence_7 = { 48 8945e0 0f878d000000 48 8d05a0000000 48 }
            // n = 6, score = 100
            //   48                   | dec                 eax
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   0f878d000000         | ja                  0x93
            //   48                   | dec                 eax
            //   8d05a0000000         | lea                 eax, [0xa0]
            //   48                   | dec                 eax

        $sequence_8 = { 898dccfbffff 8b8dccfbffff 83f900 7c0d 8b85ccfbffff 3d???????? 7613 }
            // n = 7, score = 100
            //   898dccfbffff         | mov                 dword ptr [ebp - 0x434], ecx
            //   8b8dccfbffff         | mov                 ecx, dword ptr [ebp - 0x434]
            //   83f900               | cmp                 ecx, 0
            //   7c0d                 | jl                  0xf
            //   8b85ccfbffff         | mov                 eax, dword ptr [ebp - 0x434]
            //   3d????????           |                     
            //   7613                 | jbe                 0x15

        $sequence_9 = { 48 8b4db0 48 89ca 48 631490 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   8b4db0               | mov                 ecx, dword ptr [ebp - 0x50]
            //   48                   | dec                 eax
            //   89ca                 | mov                 edx, ecx
            //   48                   | dec                 eax
            //   631490               | arpl                word ptr [eax + edx*4], dx
            //   48                   | dec                 eax

    condition:
        7 of them and filesize < 1390088
}
