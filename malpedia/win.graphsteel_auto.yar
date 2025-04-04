rule win_graphsteel_auto {

    meta:
        id = "1d7J09EHHtLtZVtRMO6Pj6"
        fingerprint = "v1_sha256_c16b3aee4470d6b80d6571382358ae60606e1bc85c16a98c39f469be44f26ba8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.graphsteel."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphsteel"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? e9???????? 4c89642420 ba12000000 4531c9 4c89e9 4c8d05e9604900 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e9????????           |                     
            //   4c89642420           | cmp                 word ptr [esp + 0x9a], 0
            //   ba12000000           | je                  0x5bc
            //   4531c9               | jle                 0x12b
            //   4c89e9               | dec                 eax
            //   4c8d05e9604900       | mov                 dword ptr [esp + 0x40], edx

        $sequence_1 = { e8???????? 4889442458 48895c2428 488d0537c74200 e8???????? 48c7400810000000 48c7401010000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889442458           | test                eax, eax
            //   48895c2428           | je                  0xa8
            //   488d0537c74200       | mov                 eax, dword ptr [eax]
            //   e8????????           |                     
            //   48c7400810000000     | dec                 eax
            //   48c7401010000000     | mov                 edx, dword ptr [ebx + 0x18]

        $sequence_2 = { e8???????? 89442458 e9???????? 83c301 4d8d5760 4d8b5f38 4c89f1 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89442458             | pop                 esi
            //   e9????????           |                     
            //   83c301               | js                  0x2e0
            //   4d8d5760             | dec                 eax
            //   4d8b5f38             | mov                 dword ptr [ebx + 0x18], ecx
            //   4c89f1               | dec                 eax

        $sequence_3 = { c784240001000000000000 48895c2438 8b5c2430 4c89e9 448d6301 4489e2 e8???????? }
            // n = 7, score = 100
            //   c784240001000000000000     | cmp    dword ptr [eax], 0x44414548
            //   48895c2438           | je                  0x1f1
            //   8b5c2430             | mov                 ebx, 3
            //   4c89e9               | dec                 eax
            //   448d6301             | lea                 eax, [0x3d9c26]
            //   4489e2               | je                  0x20d
            //   e8????????           |                     

        $sequence_4 = { e9???????? 4889d0 4889d9 e8???????? 4889d0 4889d9 e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   4889d0               | mov                 ecx, dword ptr [ebp + 8]
            //   4889d9               | dec                 ecx
            //   e8????????           |                     
            //   4889d0               | lea                 esi, [esp + 8]
            //   4889d9               | dec                 eax
            //   e8????????           |                     

        $sequence_5 = { e8???????? 488b6c2470 4883c478 c3 488d05d4323a00 488d1dad9f4a00 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b6c2470           | dec                 eax
            //   4883c478             | mov                 ebp, dword ptr [esp + 0x10]
            //   c3                   | jne                 0x4d0
            //   488d05d4323a00       | jmp                 0x4d7
            //   488d1dad9f4a00       | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { e8???????? 488d05fbc53800 488d1db4334900 e8???????? 488d05e8c53800 488d1da1334900 90 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d05fbc53800       | add                 esp, 0x20
            //   488d1db4334900       | jne                 0x1e9
            //   e8????????           |                     
            //   488d05e8c53800       | xor                 eax, eax
            //   488d1da1334900       | dec                 eax
            //   90                   | lea                 ecx, [0x8a87ab]

        $sequence_7 = { e8???????? 89442444 4189c1 85c0 0f8423020000 488b442448 4885c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89442444             | dec                 esp
            //   4189c1               | cmp                 edx, ecx
            //   85c0                 | jne                 0x11f
            //   0f8423020000         | js                  0x154
            //   488b442448           | dec                 esp
            //   4885c0               | mov                 ecx, esp

        $sequence_8 = { e8???????? 48ffc2 4839d3 7e14 761a 0fb63410 6690 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   48ffc2               | jne                 0x3f0
            //   4839d3               | inc                 ecx
            //   7e14                 | cmp                 ebp, 1
            //   761a                 | inc                 ebp
            //   0fb63410             | mov                 edi, ebp
            //   6690                 | sete                al

        $sequence_9 = { bf01000000 4889d6 e8???????? 488b4c2470 488b742450 488b542448 eb39 }
            // n = 7, score = 100
            //   bf01000000           | mov                 dword ptr [esp + 0x70], ebx
            //   4889d6               | dec                 eax
            //   e8????????           |                     
            //   488b4c2470           | mov                 edx, dword ptr [eax + 0x28]
            //   488b742450           | dec                 eax
            //   488b542448           | mov                 edi, dword ptr [eax + 0x30]
            //   eb39                 | dec                 eax

    condition:
        7 of them and filesize < 19812352
}
