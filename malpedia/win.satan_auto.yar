rule win_satan_auto {

    meta:
        id = "4w2BYYU2sjux4dVGdoqAN7"
        fingerprint = "v1_sha256_684fd8d03725a857adc2201582faa570633fcd21041d464e35a18c1f078d9ea5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.satan."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.satan"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 57 837d0c00 740c c78560ffffff01000000 eb0a c78560ffffff00000000 8b8560ffffff }
            // n = 7, score = 100
            //   57                   | push                edi
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   740c                 | je                  0xe
            //   c78560ffffff01000000     | mov    dword ptr [ebp - 0xa0], 1
            //   eb0a                 | jmp                 0xc
            //   c78560ffffff00000000     | mov    dword ptr [ebp - 0xa0], 0
            //   8b8560ffffff         | mov                 eax, dword ptr [ebp - 0xa0]

        $sequence_1 = { e8???????? 8d4da4 e8???????? 83ee00 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   e8????????           |                     
            //   83ee00               | sub                 esi, 0

        $sequence_2 = { 8a82c8c64700 884118 ebda c745fc00000000 eb09 8b4dfc 83c101 }
            // n = 7, score = 100
            //   8a82c8c64700         | mov                 al, byte ptr [edx + 0x47c6c8]
            //   884118               | mov                 byte ptr [ecx + 0x18], al
            //   ebda                 | jmp                 0xffffffdc
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c101               | add                 ecx, 1

        $sequence_3 = { 6bd117 8982d0d14700 68???????? 8b45fc 50 ff15???????? 3305???????? }
            // n = 7, score = 100
            //   6bd117               | imul                edx, ecx, 0x17
            //   8982d0d14700         | mov                 dword ptr [edx + 0x47d1d0], eax
            //   68????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3305????????         |                     

        $sequence_4 = { c745e801000000 c745e401000000 c745e0bc070000 8d55f8 52 8d45f4 }
            // n = 6, score = 100
            //   c745e801000000       | mov                 dword ptr [ebp - 0x18], 1
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   c745e0bc070000       | mov                 dword ptr [ebp - 0x20], 0x7bc
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   52                   | push                edx
            //   8d45f4               | lea                 eax, [ebp - 0xc]

        $sequence_5 = { 7409 ff30 8bcf e8???????? 8b45e8 894708 }
            // n = 6, score = 100
            //   7409                 | je                  0xb
            //   ff30                 | push                dword ptr [eax]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   894708               | mov                 dword ptr [edi + 8], eax

        $sequence_6 = { 8b10 52 8d4df8 e8???????? 8d4df8 e8???????? 0fb6c0 }
            // n = 7, score = 100
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   52                   | push                edx
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   e8????????           |                     
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   e8????????           |                     
            //   0fb6c0               | movzx               eax, al

        $sequence_7 = { 50 e8???????? 83c40c b90c000000 8d75cc 8b7d0c f3a5 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   b90c000000           | mov                 ecx, 0xc
            //   8d75cc               | lea                 esi, [ebp - 0x34]
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_8 = { 0f42c8 8b5614 8bc2 f7d0 894dfc 3bc1 0f8607010000 }
            // n = 7, score = 100
            //   0f42c8               | cmovb               ecx, eax
            //   8b5614               | mov                 edx, dword ptr [esi + 0x14]
            //   8bc2                 | mov                 eax, edx
            //   f7d0                 | not                 eax
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   3bc1                 | cmp                 eax, ecx
            //   0f8607010000         | jbe                 0x10d

        $sequence_9 = { e8???????? 8d45b8 c745fc10000000 50 8d45e4 b9???????? 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   c745fc10000000       | mov                 dword ptr [ebp - 4], 0x10
            //   50                   | push                eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]
            //   b9????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1163264
}
