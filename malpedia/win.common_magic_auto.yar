rule win_common_magic_auto {

    meta:
        id = "5ASyfPJqgOXRK4KW4vQDNl"
        fingerprint = "v1_sha256_f088c9c6d83029098f6560147761ea146208530ef1a48657d7b10a76113354f7"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.common_magic."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.common_magic"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83e805 7415 83e801 0f8595010000 c745e488424100 e9???????? }
            // n = 6, score = 100
            //   83e805               | sub                 eax, 5
            //   7415                 | je                  0x17
            //   83e801               | sub                 eax, 1
            //   0f8595010000         | jne                 0x19b
            //   c745e488424100       | mov                 dword ptr [ebp - 0x1c], 0x414288
            //   e9????????           |                     

        $sequence_1 = { 83c008 5d c3 8b04c5240e4100 5d c3 8bff }
            // n = 7, score = 100
            //   83c008               | add                 eax, 8
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b04c5240e4100       | mov                 eax, dword ptr [eax*8 + 0x410e24]
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8bff                 | mov                 edi, edi

        $sequence_2 = { 83c408 83f908 7235 8b955cffffff 8d0c4d02000000 8bc2 }
            // n = 6, score = 100
            //   83c408               | add                 esp, 8
            //   83f908               | cmp                 ecx, 8
            //   7235                 | jb                  0x37
            //   8b955cffffff         | mov                 edx, dword ptr [ebp - 0xa4]
            //   8d0c4d02000000       | lea                 ecx, [ecx*2 + 2]
            //   8bc2                 | mov                 eax, edx

        $sequence_3 = { c70000000000 33c9 c7401000000000 c7401400000000 0f1085acfdffff }
            // n = 5, score = 100
            //   c70000000000         | mov                 dword ptr [eax], 0
            //   33c9                 | xor                 ecx, ecx
            //   c7401000000000       | mov                 dword ptr [eax + 0x10], 0
            //   c7401400000000       | mov                 dword ptr [eax + 0x14], 0
            //   0f1085acfdffff       | movups              xmm0, xmmword ptr [ebp - 0x254]

        $sequence_4 = { e8???????? 8b0f 83c408 85c9 7454 8b5704 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   83c408               | add                 esp, 8
            //   85c9                 | test                ecx, ecx
            //   7454                 | je                  0x56
            //   8b5704               | mov                 edx, dword ptr [edi + 4]

        $sequence_5 = { 66891448 53 ff15???????? 8bc6 8b4df4 64890d00000000 59 }
            // n = 7, score = 100
            //   66891448             | mov                 word ptr [eax + ecx*2], dx
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx

        $sequence_6 = { 8934b8 8bc7 83e03f 6bc838 8b049570804100 }
            // n = 5, score = 100
            //   8934b8               | mov                 dword ptr [eax + edi*4], esi
            //   8bc7                 | mov                 eax, edi
            //   83e03f               | and                 eax, 0x3f
            //   6bc838               | imul                ecx, eax, 0x38
            //   8b049570804100       | mov                 eax, dword ptr [edx*4 + 0x418070]

        $sequence_7 = { 8d3400 8985bcfdffff 56 8d85e8fdffff 50 8d85acfdffff 50 }
            // n = 7, score = 100
            //   8d3400               | lea                 esi, [eax + eax]
            //   8985bcfdffff         | mov                 dword ptr [ebp - 0x244], eax
            //   56                   | push                esi
            //   8d85e8fdffff         | lea                 eax, [ebp - 0x218]
            //   50                   | push                eax
            //   8d85acfdffff         | lea                 eax, [ebp - 0x254]
            //   50                   | push                eax

        $sequence_8 = { 660f1f840000000000 83bd40ffffff08 8d8d2cffffff 8bf7 0f438d2cffffff 837f1408 }
            // n = 6, score = 100
            //   660f1f840000000000     | nop    word ptr [eax + eax]
            //   83bd40ffffff08       | cmp                 dword ptr [ebp - 0xc0], 8
            //   8d8d2cffffff         | lea                 ecx, [ebp - 0xd4]
            //   8bf7                 | mov                 esi, edi
            //   0f438d2cffffff       | cmovae              ecx, dword ptr [ebp - 0xd4]
            //   837f1408             | cmp                 dword ptr [edi + 0x14], 8

        $sequence_9 = { 8d45b4 c745b45368656c 50 56 c745b86c457865 c745bc63757465 }
            // n = 6, score = 100
            //   8d45b4               | lea                 eax, [ebp - 0x4c]
            //   c745b45368656c       | mov                 dword ptr [ebp - 0x4c], 0x6c656853
            //   50                   | push                eax
            //   56                   | push                esi
            //   c745b86c457865       | mov                 dword ptr [ebp - 0x48], 0x6578456c
            //   c745bc63757465       | mov                 dword ptr [ebp - 0x44], 0x65747563

    condition:
        7 of them and filesize < 212992
}
