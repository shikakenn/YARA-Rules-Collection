rule win_anatova_ransom_auto {

    meta:
        id = "45DOAiWXPkjQycrEqQz2It"
        fingerprint = "v1_sha256_48354275540a19e149a3ec749fb4eeaa508568399fc971259b74ddc21d53a5fe"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.anatova_ransom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anatova_ransom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8b4d8c 4863c9 4839c1 0f832a000000 e9???????? 8b458c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8b4d8c               | mov                 eax, 0x441
            //   4863c9               | mov                 dword ptr [ebp - 0x34], eax
            //   4839c1               | mov                 eax, 0x442
            //   0f832a000000         | mov                 dword ptr [ebp - 0x30], eax
            //   e9????????           |                     
            //   8b458c               | mov                 eax, 0x816

        $sequence_1 = { 0f8521000000 488b4598 4989c2 4c89d1 }
            // n = 4, score = 200
            //   0f8521000000         | and                 eax, 1
            //   488b4598             | cmp                 eax, 0
            //   4989c2               | je                  0x2f8
            //   4c89d1               | mov                 eax, dword ptr [ebp - 0x24]

        $sequence_2 = { 48898510ffffff 488d051f580000 48898518ffffff 488d051b580000 }
            // n = 4, score = 200
            //   48898510ffffff       | je                  0xa22
            //   488d051f580000       | add                 eax, 0x200
            //   48898518ffffff       | dec                 eax
            //   488d051b580000       | cmp                 eax, 0

        $sequence_3 = { e9???????? 48b80000100000000000 e9???????? 488b45e8 4889442428 }
            // n = 5, score = 200
            //   e9????????           |                     
            //   48b80000100000000000     | dec    ecx
            //   e9????????           |                     
            //   488b45e8             | mov                 ebx, eax
            //   4889442428           | dec                 eax

        $sequence_4 = { 0f8dd3fcffff 83f808 0f845bfcffff 83f809 0f8477fcffff 83f80a 0f8493fcffff }
            // n = 7, score = 200
            //   0f8dd3fcffff         | mov                 edx, eax
            //   83f808               | dec                 eax
            //   0f845bfcffff         | add                 eax, 0x3c
            //   83f809               | dec                 eax
            //   0f8477fcffff         | mov                 ecx, dword ptr [ebp + 0x10]
            //   83f80a               | dec                 eax
            //   0f8493fcffff         | add                 ecx, 0xc

        $sequence_5 = { 488b4d10 488b5528 488945c8 488b4520 48894dc0 }
            // n = 5, score = 200
            //   488b4d10             | mov                 eax, dword ptr [ebp + 0x10]
            //   488b5528             | shl                 edx, 0x10
            //   488945c8             | add                 ecx, edx
            //   488b4520             | dec                 eax
            //   48894dc0             | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_6 = { 0fb68597fdffff 83f800 0f8405000000 e9???????? 488b8598fdffff 4989c2 }
            // n = 6, score = 200
            //   0fb68597fdffff       | dec                 eax
            //   83f800               | lea                 eax, [0x5717]
            //   0f8405000000         | dec                 eax
            //   e9????????           |                     
            //   488b8598fdffff       | mov                 dword ptr [ebp - 0x20], eax
            //   4989c2               | dec                 eax

        $sequence_7 = { 488945f0 488b45f0 4883f8ff 0f84aa080000 48b80000000000000000 4989c3 488b45f0 }
            // n = 7, score = 200
            //   488945f0             | dec                 eax
            //   488b45f0             | mov                 dword ptr [esp + 0x28], eax
            //   4883f8ff             | dec                 eax
            //   0f84aa080000         | mov                 ecx, eax
            //   48b80000000000000000     | add    eax, 1
            //   4989c3               | mov                 dword ptr [ebp - 0x28], eax
            //   488b45f0             | jmp                 0x323

        $sequence_8 = { 4889e5 4881ec70000000 b800000000 8845ff 488b05???????? 4883f800 }
            // n = 6, score = 200
            //   4889e5               | mov                 edx, eax
            //   4881ec70000000       | dec                 esp
            //   b800000000           | mov                 ecx, edx
            //   8845ff               | dec                 esp
            //   488b05????????       |                     
            //   4883f800             | mov                 edx, ebx

        $sequence_9 = { 488d05d6390000 488985f8feffff 488d05d5390000 48898500ffffff 488d05d3390000 48898508ffffff }
            // n = 6, score = 200
            //   488d05d6390000       | mov                 eax, 4
            //   488985f8feffff       | dec                 ecx
            //   488d05d5390000       | mov                 ebx, eax
            //   48898500ffffff       | dec                 eax
            //   488d05d3390000       | mov                 eax, 0x2000
            //   48898508ffffff       | add                 byte ptr [eax], al

    condition:
        7 of them and filesize < 671744
}
