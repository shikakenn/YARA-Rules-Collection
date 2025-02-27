rule win_royal_ransom_auto {

    meta:
        id = "1slpETqhlTu25cAbjnlm3G"
        fingerprint = "v1_sha256_05ad7a29faf1ca692a5b6df2d422be2fdcf12c3fc6c9f7021ff0ef0bb4b8bcb3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.royal_ransom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_ransom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bd0 488d0de62fe4ff 488d05cf33e3ff 488903 e9???????? 428d14cd00000000 498bca }
            // n = 7, score = 100
            //   8bd0                 | dec                 eax
            //   488d0de62fe4ff       | mov                 eax, dword ptr [esp + 0x30]
            //   488d05cf33e3ff       | dec                 esp
            //   488903               | lea                 eax, [0x14b191]
            //   e9????????           |                     
            //   428d14cd00000000     | mov                 edx, 0x4d2
            //   498bca               | dec                 eax

        $sequence_1 = { b820000000 e8???????? 482be0 488bca e8???????? 488bc8 488d15a73d0800 }
            // n = 7, score = 100
            //   b820000000           | mov                 ecx, edi
            //   e8????????           |                     
            //   482be0               | test                eax, eax
            //   488bca               | je                  0xc2c
            //   e8????????           |                     
            //   488bc8               | dec                 eax
            //   488d15a73d0800       | lea                 edx, [0xb5d18]

        $sequence_2 = { 85c0 742c 488b0d???????? 488d15b5220100 e8???????? 85c0 7415 }
            // n = 7, score = 100
            //   85c0                 | dec                 eax
            //   742c                 | mov                 ecx, ebp
            //   488b0d????????       |                     
            //   488d15b5220100       | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, ebp
            //   7415                 | test                eax, eax

        $sequence_3 = { 85c0 7506 448d7001 eb2e e8???????? 4c8d05a59f0d00 bab4010000 }
            // n = 7, score = 100
            //   85c0                 | mov                 edi, eax
            //   7506                 | dec                 eax
            //   448d7001             | test                eax, eax
            //   eb2e                 | je                  0xa8e
            //   e8????????           |                     
            //   4c8d05a59f0d00       | inc                 ecx
            //   bab4010000           | mov                 eax, 0x10

        $sequence_4 = { e8???????? 837f1400 4c8d05cfc01700 488b0f 488b5728 740d 41b9e7000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   837f1400             | inc                 ecx
            //   4c8d05cfc01700       | lea                 ecx, [eax + 0x22]
            //   488b0f               | xor                 edi, edi
            //   488b5728             | dec                 esp
            //   740d                 | lea                 eax, [0x12c5b1]
            //   41b9e7000000         | mov                 edx, 0x23a

        $sequence_5 = { 8d4a8e e8???????? 488b4b20 e8???????? 41b8e1010000 488d155ddf0e00 488bcb }
            // n = 7, score = 100
            //   8d4a8e               | lea                 eax, [0xe1dca]
            //   e8????????           |                     
            //   488b4b20             | mov                 edx, 0x585
            //   e8????????           |                     
            //   41b8e1010000         | dec                 eax
            //   488d155ddf0e00       | lea                 ecx, [0xe0f8e]
            //   488bcb               | inc                 ebp

        $sequence_6 = { eb33 498bc4 eb4f e8???????? 4c8d058fc01400 ba1c010000 488d0d13c01400 }
            // n = 7, score = 100
            //   eb33                 | inc                 edx
            //   498bc4               | mov                 cl, byte ptr [ecx + ebx + 0x2a8c58]
            //   eb4f                 | dec                 eax
            //   e8????????           |                     
            //   4c8d058fc01400       | sub                 edx, eax
            //   ba1c010000           | mov                 eax, dword ptr [edx - 4]
            //   488d0d13c01400       | dec                 esp

        $sequence_7 = { 7525 e8???????? 4c8d0545051600 baa4060000 488bcb e8???????? baab000000 }
            // n = 7, score = 100
            //   7525                 | ret                 
            //   e8????????           |                     
            //   4c8d0545051600       | dec                 eax
            //   baa4060000           | lea                 edx, [0xa0504]
            //   488bcb               | dec                 eax
            //   e8????????           |                     
            //   baab000000           | mov                 ecx, edi

        $sequence_8 = { e8???????? 8b4730 4c8d057fcd1500 448b4b08 8d4eff 89442428 ba0c010800 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b4730               | je                  0xbe4
            //   4c8d057fcd1500       | movups              xmm0, xmmword ptr [ebx]
            //   448b4b08             | inc                 ecx
            //   8d4eff               | mov                 eax, 0x50
            //   89442428             | dec                 eax
            //   ba0c010800           | lea                 edx, [0xf8bc3]

        $sequence_9 = { e8???????? 4c8d05cb5a0f00 baab010000 488d0d2f5a0f00 e8???????? 4533c0 418d4e06 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8d05cb5a0f00       | jmp                 0xdcd
            //   baab010000           | dec                 eax
            //   488d0d2f5a0f00       | mov                 eax, dword ptr [edx]
            //   e8????????           |                     
            //   4533c0               | inc                 ecx
            //   418d4e06             | mov                 ecx, dword ptr [eax + eax*4 + 0x90f60]

    condition:
        7 of them and filesize < 6235136
}
