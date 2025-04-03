rule win_decaf_auto {

    meta:
        id = "7I2i2IsIeAsivpfphkn3c1"
        fingerprint = "v1_sha256_7a70ed6fa2a0ce3cf4802d2d0ae4afe2a54da0a94bb0916dbc97593071b29978"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.decaf."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.decaf"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { be02000000 e8???????? 0fb6542459 0fb6742458 29f2 8810 0fb6542457 }
            // n = 7, score = 100
            //   be02000000           | mov                 byte ptr [edi + ebx], 0x8d
            //   e8????????           |                     
            //   0fb6542459           | mov                 ecx, 0xc
            //   0fb6742458           | dec                 ecx
            //   29f2                 | cmp                 eax, 3
            //   8810                 | dec                 eax
            //   0fb6542457           | mov                 edi, eax

        $sequence_1 = { e8???????? 48c7400817000000 488d0dd8a81600 488908 48c7401000000000 4889c3 488d05d7e71300 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48c7400817000000     | mov                 dword ptr [esp + 0x1f48], ecx
            //   488d0dd8a81600       | dec                 eax
            //   488908               | lea                 eax, [0xc2a63]
            //   48c7401000000000     | nop                 dword ptr [eax]
            //   4889c3               | jne                 0xbd6
            //   488d05d7e71300       | dec                 eax

        $sequence_2 = { e9???????? 4c8d4302 4c39c6 7337 4c89442468 488d05d8a30300 4889d9 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4c8d4302             | mov                 eax, dword ptr [esp + 0x40]
            //   4c39c6               | mov                 dword ptr [edi + ebx], 0x31370f06
            //   7337                 | mov                 ecx, 0xe
            //   4c89442468           | dec                 ecx
            //   488d05d8a30300       | cmp                 eax, 0x14
            //   4889d9               | jne                 0xf22

        $sequence_3 = { eb12 4883fa03 750c 488d157e013400 f0480fc102 ba01000000 4c8d059d053400 }
            // n = 7, score = 100
            //   eb12                 | mov                 eax, dword ptr [esp + 0x40]
            //   4883fa03             | mov                 word ptr [edi + ebx], 0xa156
            //   750c                 | dec                 eax
            //   488d157e013400       | mov                 edx, dword ptr [esp + 0x50]
            //   f0480fc102           | dec                 eax
            //   ba01000000           | mov                 ebx, dword ptr [esp + 0x48]
            //   4c8d059d053400       | dec                 esp

        $sequence_4 = { ffd1 488b08 4889c2 b8c7ffffff ffd1 48c744241000000000 488b4c2428 }
            // n = 7, score = 100
            //   ffd1                 | dec                 ecx
            //   488b08               | mov                 ecx, eax
            //   4889c2               | dec                 eax
            //   b8c7ffffff           | mov                 eax, dword ptr [esp + 0x50]
            //   ffd1                 | dec                 eax
            //   48c744241000000000     | mov    ebx, dword ptr [esp + 0x48]
            //   488b4c2428           | xor                 ecx, ecx

        $sequence_5 = { 488b8c24f01c0000 48894818 eb11 488d7818 488b8c24f01c0000 e8???????? 488b8c24100a0000 }
            // n = 7, score = 100
            //   488b8c24f01c0000     | movzx               edx, byte ptr [esp + 0x81]
            //   48894818             | inc                 esp
            //   eb11                 | add                 edx, eax
            //   488d7818             | mov                 byte ptr [eax + 0xf], dl
            //   488b8c24f01c0000     | movzx               edx, byte ptr [esp + 0x50]
            //   e8????????           |                     
            //   488b8c24100a0000     | inc                 esp

        $sequence_6 = { 4983f804 0f8f72010000 90 4983f802 0f8faf000000 4d85c0 755b }
            // n = 7, score = 100
            //   4983f804             | movzx               edx, byte ptr [esp + 0x86]
            //   0f8f72010000         | inc                 esp
            //   90                   | movzx               eax, byte ptr [esp + 0x4d]
            //   4983f802             | inc                 esp
            //   0f8faf000000         | xor                 edx, eax
            //   4d85c0               | mov                 byte ptr [eax + 0xd], dl
            //   755b                 | movzx               edx, byte ptr [esp + 0x4e]

        $sequence_7 = { 488d3dcb351c00 e8???????? e8???????? 48898424e0030000 48899c2408010000 488b0d???????? 48898c24c8050000 }
            // n = 7, score = 100
            //   488d3dcb351c00       | movzx               ebp, byte ptr [esp + 0x73]
            //   e8????????           |                     
            //   e8????????           |                     
            //   48898424e0030000     | inc                 esp
            //   48899c2408010000     | movzx               ebp, byte ptr [esp + 0x78]
            //   488b0d????????       |                     
            //   48898c24c8050000     | inc                 esp

        $sequence_8 = { e8???????? 488b442478 488b4c2470 488b942488000000 ebbd 90 488d05bfff1d00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b442478           | dec                 eax
            //   488b4c2470           | neg                 ecx
            //   488b942488000000     | dec                 eax
            //   ebbd                 | sar                 ecx, 0x3f
            //   90                   | dec                 eax
            //   488d05bfff1d00       | and                 edx, ecx

        $sequence_9 = { eb14 488d7818 488b8c2470220000 0f1f00 e8???????? 488b8c24a8030000 48894808 }
            // n = 7, score = 100
            //   eb14                 | mov                 eax, dword ptr [esp + 0x60]
            //   488d7818             | dec                 eax
            //   488b8c2470220000     | mov                 edi, eax
            //   0f1f00               | dec                 eax
            //   e8????????           |                     
            //   488b8c24a8030000     | mov                 esi, ecx
            //   48894808             | dec                 eax

    condition:
        7 of them and filesize < 7193600
}
