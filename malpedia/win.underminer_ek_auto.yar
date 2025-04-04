rule win_underminer_ek_auto {

    meta:
        id = "4Gc0wSh4acZaJ09DkjZNRs"
        fingerprint = "v1_sha256_2f91a4d4f297062b3d3b07b58a9c1bfef73e9c0060b6e1680dc04cf736854cd4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.underminer_ek."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.underminer_ek"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b9???????? c7431000000000 8d5101 c743140f000000 c60300 0f1f8000000000 }
            // n = 6, score = 100
            //   b9????????           |                     
            //   c7431000000000       | mov                 dword ptr [ebx + 0x10], 0
            //   8d5101               | lea                 edx, [ecx + 1]
            //   c743140f000000       | mov                 dword ptr [ebx + 0x14], 0xf
            //   c60300               | mov                 byte ptr [ebx], 0
            //   0f1f8000000000       | nop                 dword ptr [eax]

        $sequence_1 = { 8d0c76 8b048f 89430c 8b448f08 33db 33c9 33d2 }
            // n = 7, score = 100
            //   8d0c76               | lea                 ecx, [esi + esi*2]
            //   8b048f               | mov                 eax, dword ptr [edi + ecx*4]
            //   89430c               | mov                 dword ptr [ebx + 0xc], eax
            //   8b448f08             | mov                 eax, dword ptr [edi + ecx*4 + 8]
            //   33db                 | xor                 ebx, ebx
            //   33c9                 | xor                 ecx, ecx
            //   33d2                 | xor                 edx, edx

        $sequence_2 = { 8b0485582c4300 8945d0 81f9e9fd0000 0f852d010000 8b55b4 83c02e }
            // n = 6, score = 100
            //   8b0485582c4300       | mov                 eax, dword ptr [eax*4 + 0x432c58]
            //   8945d0               | mov                 dword ptr [ebp - 0x30], eax
            //   81f9e9fd0000         | cmp                 ecx, 0xfde9
            //   0f852d010000         | jne                 0x133
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]
            //   83c02e               | add                 eax, 0x2e

        $sequence_3 = { 7618 8b4dec 50 8b4704 0301 50 8b47fc }
            // n = 7, score = 100
            //   7618                 | jbe                 0x1a
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   8b4704               | mov                 eax, dword ptr [edi + 4]
            //   0301                 | add                 eax, dword ptr [ecx]
            //   50                   | push                eax
            //   8b47fc               | mov                 eax, dword ptr [edi - 4]

        $sequence_4 = { eb1b 8b0c95582c4300 8a443928 a840 7508 0c02 88443928 }
            // n = 7, score = 100
            //   eb1b                 | jmp                 0x1d
            //   8b0c95582c4300       | mov                 ecx, dword ptr [edx*4 + 0x432c58]
            //   8a443928             | mov                 al, byte ptr [ecx + edi + 0x28]
            //   a840                 | test                al, 0x40
            //   7508                 | jne                 0xa
            //   0c02                 | or                  al, 2
            //   88443928             | mov                 byte ptr [ecx + edi + 0x28], al

        $sequence_5 = { 8945fc 8b7dfc 8b470c 3bc3 7437 }
            // n = 5, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]
            //   3bc3                 | cmp                 eax, ebx
            //   7437                 | je                  0x39

        $sequence_6 = { e8???????? 8d4dd0 e8???????? 8bf4 8bf8 83ec18 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     
            //   8bf4                 | mov                 esi, esp
            //   8bf8                 | mov                 edi, eax
            //   83ec18               | sub                 esp, 0x18

        $sequence_7 = { c3 8b442404 8325????????00 a3???????? 8b442408 a3???????? }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   8325????????00       |                     
            //   a3????????           |                     
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   a3????????           |                     

        $sequence_8 = { 25ffff0000 eb07 03c7 6a00 83c002 }
            // n = 5, score = 100
            //   25ffff0000           | and                 eax, 0xffff
            //   eb07                 | jmp                 9
            //   03c7                 | add                 eax, edi
            //   6a00                 | push                0
            //   83c002               | add                 eax, 2

        $sequence_9 = { 7408 3b5d14 7351 8d0c13 51 50 56 }
            // n = 7, score = 100
            //   7408                 | je                  0xa
            //   3b5d14               | cmp                 ebx, dword ptr [ebp + 0x14]
            //   7351                 | jae                 0x53
            //   8d0c13               | lea                 ecx, [ebx + edx]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_10 = { 83f81f 0f8767110000 52 51 }
            // n = 4, score = 100
            //   83f81f               | cmp                 eax, 0x1f
            //   0f8767110000         | ja                  0x116d
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_11 = { 7474 807dfd03 7540 84d2 740c b9da51fa7e }
            // n = 6, score = 100
            //   7474                 | je                  0x76
            //   807dfd03             | cmp                 byte ptr [ebp - 3], 3
            //   7540                 | jne                 0x42
            //   84d2                 | test                dl, dl
            //   740c                 | je                  0xe
            //   b9da51fa7e           | mov                 ecx, 0x7efa51da

        $sequence_12 = { 3cb8 3cc2 3cd3 3cd8 3ce2 3cf3 }
            // n = 6, score = 100
            //   3cb8                 | cmp                 al, 0xb8
            //   3cc2                 | cmp                 al, 0xc2
            //   3cd3                 | cmp                 al, 0xd3
            //   3cd8                 | cmp                 al, 0xd8
            //   3ce2                 | cmp                 al, 0xe2
            //   3cf3                 | cmp                 al, 0xf3

        $sequence_13 = { e8???????? 3bde 7412 0fb603 8bcf }
            // n = 5, score = 100
            //   e8????????           |                     
            //   3bde                 | cmp                 ebx, esi
            //   7412                 | je                  0x14
            //   0fb603               | movzx               eax, byte ptr [ebx]
            //   8bcf                 | mov                 ecx, edi

        $sequence_14 = { 8d7dc2 66895dc0 ff7508 895dec ab ff760c }
            // n = 6, score = 100
            //   8d7dc2               | lea                 edi, [ebp - 0x3e]
            //   66895dc0             | mov                 word ptr [ebp - 0x40], bx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   ff760c               | push                dword ptr [esi + 0xc]

        $sequence_15 = { 0f42c1 a3???????? 8b8584feffff 83f806 7545 }
            // n = 5, score = 100
            //   0f42c1               | cmovb               eax, ecx
            //   a3????????           |                     
            //   8b8584feffff         | mov                 eax, dword ptr [ebp - 0x17c]
            //   83f806               | cmp                 eax, 6
            //   7545                 | jne                 0x47

    condition:
        7 of them and filesize < 466944
}
