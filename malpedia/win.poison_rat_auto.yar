rule win_poison_rat_auto {

    meta:
        id = "6K9xCiVJvLpYnLT3olDHEr"
        fingerprint = "v1_sha256_b960cb72b2615d9b184a9e25264d3c87f1ec796c5d1b6fa8620d3a64be9786ae"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.poison_rat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poison_rat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6880000000 8d85d4fcffff 52 50 e8???????? }
            // n = 5, score = 100
            //   6880000000           | push                0x80
            //   8d85d4fcffff         | lea                 eax, [ebp - 0x32c]
            //   52                   | push                edx
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_1 = { 40 83f810 7cee 83ee10 4f 75ac 33c0 }
            // n = 7, score = 100
            //   40                   | inc                 eax
            //   83f810               | cmp                 eax, 0x10
            //   7cee                 | jl                  0xfffffff0
            //   83ee10               | sub                 esi, 0x10
            //   4f                   | dec                 edi
            //   75ac                 | jne                 0xffffffae
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 81e1ff000000 83c010 331cad30a44000 8b68f8 }
            // n = 4, score = 100
            //   81e1ff000000         | and                 ecx, 0xff
            //   83c010               | add                 eax, 0x10
            //   331cad30a44000       | xor                 ebx, dword ptr [ebp*4 + 0x40a430]
            //   8b68f8               | mov                 ebp, dword ptr [eax - 8]

        $sequence_3 = { e8???????? 8d8560ffffff 68???????? 50 e8???????? ffb6eca94000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   ffb6eca94000         | push                dword ptr [esi + 0x40a9ec]

        $sequence_4 = { 81e5ff000000 333cad30a44000 8b68fc 33fd 8bea }
            // n = 5, score = 100
            //   81e5ff000000         | and                 ebp, 0xff
            //   333cad30a44000       | xor                 edi, dword ptr [ebp*4 + 0x40a430]
            //   8b68fc               | mov                 ebp, dword ptr [eax - 4]
            //   33fd                 | xor                 edi, ebp
            //   8bea                 | mov                 ebp, edx

        $sequence_5 = { f3a5 ff249578334000 8bc7 ba03000000 }
            // n = 4, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   ff249578334000       | jmp                 dword ptr [edx*4 + 0x403378]
            //   8bc7                 | mov                 eax, edi
            //   ba03000000           | mov                 edx, 3

        $sequence_6 = { 33c9 897c2418 8a6e08 8a4e09 }
            // n = 4, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   897c2418             | mov                 dword ptr [esp + 0x18], edi
            //   8a6e08               | mov                 ch, byte ptr [esi + 8]
            //   8a4e09               | mov                 cl, byte ptr [esi + 9]

        $sequence_7 = { c1ea18 81e5ff000000 330c9530984000 8bd7 81e2ff000000 330c9530a44000 8b10 }
            // n = 7, score = 100
            //   c1ea18               | shr                 edx, 0x18
            //   81e5ff000000         | and                 ebp, 0xff
            //   330c9530984000       | xor                 ecx, dword ptr [edx*4 + 0x409830]
            //   8bd7                 | mov                 edx, edi
            //   81e2ff000000         | and                 edx, 0xff
            //   330c9530a44000       | xor                 ecx, dword ptr [edx*4 + 0x40a430]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_8 = { 8b34b530984000 8b1cbd309c4000 c1e908 33f3 81e1ff000000 8b0c8d30804000 }
            // n = 6, score = 100
            //   8b34b530984000       | mov                 esi, dword ptr [esi*4 + 0x409830]
            //   8b1cbd309c4000       | mov                 ebx, dword ptr [edi*4 + 0x409c30]
            //   c1e908               | shr                 ecx, 8
            //   33f3                 | xor                 esi, ebx
            //   81e1ff000000         | and                 ecx, 0xff
            //   8b0c8d30804000       | mov                 ecx, dword ptr [ecx*4 + 0x408030]

        $sequence_9 = { 8bf1 c1f805 83e61f 8d3c8580c54000 c1e603 8b07 }
            // n = 6, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   c1f805               | sar                 eax, 5
            //   83e61f               | and                 esi, 0x1f
            //   8d3c8580c54000       | lea                 edi, [eax*4 + 0x40c580]
            //   c1e603               | shl                 esi, 3
            //   8b07                 | mov                 eax, dword ptr [edi]

    condition:
        7 of them and filesize < 101688
}
