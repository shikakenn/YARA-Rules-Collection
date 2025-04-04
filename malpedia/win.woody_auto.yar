rule win_woody_auto {

    meta:
        id = "yQxXoQUG2eVQiCGs2e2L3"
        fingerprint = "v1_sha256_9fa53ff2aea1026050fd9bf490e4459858b6e425e2d1081bd2beeba1427b1834"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.woody."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woody"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6881010100 50 e8???????? 83c414 8d8c2414010000 68b4000000 50 }
            // n = 7, score = 100
            //   6881010100           | push                0x10181
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   8d8c2414010000       | lea                 ecx, [esp + 0x114]
            //   68b4000000           | push                0xb4
            //   50                   | push                eax

        $sequence_1 = { f3a5 8bca 8b542420 83e103 8d442414 f3a4 8d4c242c }
            // n = 7, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bca                 | mov                 ecx, edx
            //   8b542420             | mov                 edx, dword ptr [esp + 0x20]
            //   83e103               | and                 ecx, 3
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d4c242c             | lea                 ecx, [esp + 0x2c]

        $sequence_2 = { 23c7 8bce f7d1 23ca 0bc8 8d9c1956b7c7e8 035dc4 }
            // n = 7, score = 100
            //   23c7                 | and                 eax, edi
            //   8bce                 | mov                 ecx, esi
            //   f7d1                 | not                 ecx
            //   23ca                 | and                 ecx, edx
            //   0bc8                 | or                  ecx, eax
            //   8d9c1956b7c7e8       | lea                 ebx, [ecx + ebx - 0x173848aa]
            //   035dc4               | add                 ebx, dword ptr [ebp - 0x3c]

        $sequence_3 = { 56 8903 ffd7 5f 5e 894304 5d }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8903                 | mov                 dword ptr [ebx], eax
            //   ffd7                 | call                edi
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   894304               | mov                 dword ptr [ebx + 4], eax
            //   5d                   | pop                 ebp

        $sequence_4 = { 8d7c2428 8d54241c f3ab 8d442414 8d4c2428 50 8b442414 }
            // n = 7, score = 100
            //   8d7c2428             | lea                 edi, [esp + 0x28]
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   50                   | push                eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]

        $sequence_5 = { e8???????? 8b35???????? 8d8530fdffff 6a5c 50 ffd6 83c410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b35????????         |                     
            //   8d8530fdffff         | lea                 eax, [ebp - 0x2d0]
            //   6a5c                 | push                0x5c
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83c410               | add                 esp, 0x10

        $sequence_6 = { 50 e8???????? 8d85b4feffff 83c40c 8945c8 8d45b8 50 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85b4feffff         | lea                 eax, [ebp - 0x14c]
            //   83c40c               | add                 esp, 0xc
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   50                   | push                eax

        $sequence_7 = { 56 85ed 57 0f843a020000 8b9424c40b0000 85d2 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   85ed                 | test                ebp, ebp
            //   57                   | push                edi
            //   0f843a020000         | je                  0x240
            //   8b9424c40b0000       | mov                 edx, dword ptr [esp + 0xbc4]
            //   85d2                 | test                edx, edx

        $sequence_8 = { 8b5604 85d2 740b 8bc1 2bc2 c1f803 3bf8 }
            // n = 7, score = 100
            //   8b5604               | mov                 edx, dword ptr [esi + 4]
            //   85d2                 | test                edx, edx
            //   740b                 | je                  0xd
            //   8bc1                 | mov                 eax, ecx
            //   2bc2                 | sub                 eax, edx
            //   c1f803               | sar                 eax, 3
            //   3bf8                 | cmp                 edi, eax

        $sequence_9 = { 83c408 85c0 7505 bf01000000 85f6 7404 85ff }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   bf01000000           | mov                 edi, 1
            //   85f6                 | test                esi, esi
            //   7404                 | je                  6
            //   85ff                 | test                edi, edi

    condition:
        7 of them and filesize < 409600
}
