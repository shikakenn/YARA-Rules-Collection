rule win_merdoor_auto {

    meta:
        id = "4pdmUN438TpJl22MHRH6PL"
        fingerprint = "v1_sha256_33a0b0b418ee0e7fb6e555149df68449fe325aead89e3fe3bc9a1904f1b68daf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.merdoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.merdoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d45d4 53 0f4345d4 6a01 }
            // n = 4, score = 100
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   53                   | push                ebx
            //   0f4345d4             | cmovae              eax, dword ptr [ebp - 0x2c]
            //   6a01                 | push                1

        $sequence_1 = { 8bd9 83ff40 7308 5f 33c0 5b 5d }
            // n = 7, score = 100
            //   8bd9                 | mov                 ebx, ecx
            //   83ff40               | cmp                 edi, 0x40
            //   7308                 | jae                 0xa
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp

        $sequence_2 = { 85c0 742e 8d7808 b9a8000000 be???????? f3a5 e8???????? }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   742e                 | je                  0x30
            //   8d7808               | lea                 edi, [eax + 8]
            //   b9a8000000           | mov                 ecx, 0xa8
            //   be????????           |                     
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     

        $sequence_3 = { 83c40c 8934fd78f30110 eb07 56 e8???????? 59 c745fcfeffffff }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   8934fd78f30110       | mov                 dword ptr [edi*8 + 0x1001f378], esi
            //   eb07                 | jmp                 9
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c745fcfeffffff       | mov                 dword ptr [ebp - 4], 0xfffffffe

        $sequence_4 = { 8d8594feffff 50 57 6a00 ff9578fdffff 8bd8 85db }
            // n = 7, score = 100
            //   8d8594feffff         | lea                 eax, [ebp - 0x16c]
            //   50                   | push                eax
            //   57                   | push                edi
            //   6a00                 | push                0
            //   ff9578fdffff         | call                dword ptr [ebp - 0x288]
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx

        $sequence_5 = { 8b4de0 85c9 7449 8b45e8 894dd0 8d4de0 51 }
            // n = 7, score = 100
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   85c9                 | test                ecx, ecx
            //   7449                 | je                  0x4b
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   51                   | push                ecx

        $sequence_6 = { 8981b0020000 ff75e0 ff15???????? 8b45f8 5f 5e 5b }
            // n = 7, score = 100
            //   8981b0020000         | mov                 dword ptr [ecx + 0x2b0], eax
            //   ff75e0               | push                dword ptr [ebp - 0x20]
            //   ff15????????         |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { 0fb7c0 eb0b 8b8d78ffffff 83c102 03c1 50 57 }
            // n = 7, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   eb0b                 | jmp                 0xd
            //   8b8d78ffffff         | mov                 ecx, dword ptr [ebp - 0x88]
            //   83c102               | add                 ecx, 2
            //   03c1                 | add                 eax, ecx
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_8 = { 64a300000000 8bf9 897da8 8b8f50040000 85c9 7405 8b01 }
            // n = 7, score = 100
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf9                 | mov                 edi, ecx
            //   897da8               | mov                 dword ptr [ebp - 0x58], edi
            //   8b8f50040000         | mov                 ecx, dword ptr [edi + 0x450]
            //   85c9                 | test                ecx, ecx
            //   7405                 | je                  7
            //   8b01                 | mov                 eax, dword ptr [ecx]

        $sequence_9 = { b010 2ac1 f6d0 fec1 3084156cfcffff 42 80f910 }
            // n = 7, score = 100
            //   b010                 | mov                 al, 0x10
            //   2ac1                 | sub                 al, cl
            //   f6d0                 | not                 al
            //   fec1                 | inc                 cl
            //   3084156cfcffff       | xor                 byte ptr [ebp + edx - 0x394], al
            //   42                   | inc                 edx
            //   80f910               | cmp                 cl, 0x10

    condition:
        7 of them and filesize < 307200
}
