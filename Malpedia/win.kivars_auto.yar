rule win_kivars_auto {

    meta:
        id = "41IJkYdIMGdRQKYPuNTB5I"
        fingerprint = "v1_sha256_0b4c416b9816d7bbf517a345e2ad0668f53e6096c3605ae9037473d6b0f26452"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kivars."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kivars"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b1d???????? 83c414 33f6 68e8030000 ffd7 }
            // n = 5, score = 200
            //   8b1d????????         |                     
            //   83c414               | dec                 eax
            //   33f6                 | mov                 dword ptr [esp], eax
            //   68e8030000           | dec                 eax
            //   ffd7                 | mov                 eax, dword ptr [esp]

        $sequence_1 = { c68424fa160000eb c68424fb160000cb c68424fc16000074 c68424fd1600005a }
            // n = 4, score = 200
            //   c68424fa160000eb     | mov                 ecx, dword ptr [esp + 0x180]
            //   c68424fb160000cb     | mov                 edx, dword ptr [esp + 0x30]
            //   c68424fc16000074     | mov                 byte ptr [esp + 0x16fa], 0xeb
            //   c68424fd1600005a     | mov                 byte ptr [esp + 0x16fb], 0xcb

        $sequence_2 = { 4863403c 488b4c2408 4803c8 488bc1 48890424 488b0424 }
            // n = 6, score = 200
            //   4863403c             | mov                 edx, 0x10
            //   488b4c2408           | dec                 eax
            //   4803c8               | mov                 ecx, eax
            //   488bc1               | mov                 eax, 1
            //   48890424             | dec                 eax
            //   488b0424             | mov                 ecx, dword ptr [esp + 0x1e8]

        $sequence_3 = { e9???????? 488d0d84c10000 ff15???????? 8b842454020000 }
            // n = 4, score = 200
            //   e9????????           |                     
            //   488d0d84c10000       | dec                 eax
            //   ff15????????         |                     
            //   8b842454020000       | lea                 ecx, [0xc184]

        $sequence_4 = { 742b 8b542414 8b442418 8bce 8d742430 8d3c10 }
            // n = 6, score = 200
            //   742b                 | mov                 eax, ecx
            //   8b542414             | mov                 dword ptr [esp + 0x38], eax
            //   8b442418             | dec                 eax
            //   8bce                 | mov                 eax, dword ptr [esp + 0x28]
            //   8d742430             | dec                 eax
            //   8d3c10               | lea                 eax, [esp + 0x1a0]

        $sequence_5 = { 2bc8 8bc1 89442438 488b442428 }
            // n = 4, score = 200
            //   2bc8                 | mov                 byte ptr [esp + 0x16fc], 0x74
            //   8bc1                 | mov                 byte ptr [esp + 0x16fd], 0x5a
            //   89442438             | sub                 ecx, eax
            //   488b442428           | mov                 eax, ecx

        $sequence_6 = { 8bf0 83c609 33ff 6a74 897c2414 e8???????? }
            // n = 6, score = 200
            //   8bf0                 | lea                 ecx, [esp + 0x130]
            //   83c609               | dec                 eax
            //   33ff                 | mov                 dword ptr [esp + 0x350], eax
            //   6a74                 | dec                 eax
            //   897c2414             | lea                 edx, [0x64a3]
            //   e8????????           |                     

        $sequence_7 = { 56 8bf1 8b4650 c706???????? 85c0 }
            // n = 5, score = 200
            //   56                   | lea                 eax, [0x7711]
            //   8bf1                 | dec                 eax
            //   8b4650               | lea                 edx, [esp + 0x240]
            //   c706????????         |                     
            //   85c0                 | dec                 eax

        $sequence_8 = { 8b4d14 51 e8???????? 83c40c 8945d8 8b55d8 52 }
            // n = 7, score = 200
            //   8b4d14               | dec                 eax
            //   51                   | mov                 ecx, dword ptr [esp + 8]
            //   e8????????           |                     
            //   83c40c               | dec                 eax
            //   8945d8               | add                 ecx, eax
            //   8b55d8               | dec                 eax
            //   52                   | mov                 eax, ecx

        $sequence_9 = { 51 896c2420 ffd0 8be8 }
            // n = 4, score = 200
            //   51                   | mov                 edx, 0x10
            //   896c2420             | dec                 eax
            //   ffd0                 | mov                 ecx, eax
            //   8be8                 | mov                 eax, 1

        $sequence_10 = { 88442437 c644243800 c644243900 ff15???????? }
            // n = 4, score = 200
            //   88442437             | dec                 esp
            //   c644243800           | lea                 ecx, [0x7608]
            //   c644243900           | dec                 esp
            //   ff15????????         |                     

        $sequence_11 = { 4c8d0d08760000 4c8d0511770000 488d942440020000 488d8c2430010000 e8???????? 4889842450030000 }
            // n = 6, score = 200
            //   4c8d0d08760000       | dec                 eax
            //   4c8d0511770000       | arpl                word ptr [eax + 0x3c], ax
            //   488d942440020000     | dec                 eax
            //   488d8c2430010000     | mov                 ecx, dword ptr [esp + 8]
            //   e8????????           |                     
            //   4889842450030000     | dec                 eax

        $sequence_12 = { 488b0d???????? 8b4401fc 39842468100000 743b }
            // n = 4, score = 200
            //   488b0d????????       |                     
            //   8b4401fc             | mov                 eax, dword ptr [esp + 0x254]
            //   39842468100000       | mov                 eax, dword ptr [ecx + eax - 4]
            //   743b                 | cmp                 dword ptr [esp + 0x1068], eax

        $sequence_13 = { 33c9 89442420 894c2410 89442424 }
            // n = 4, score = 200
            //   33c9                 | dec                 eax
            //   89442420             | mov                 ecx, dword ptr [esp + 0x1e8]
            //   894c2410             | dec                 eax
            //   89442424             | arpl                word ptr [eax + 0x3c], ax

        $sequence_14 = { 7538 8b442420 488b8c2480010000 8b542430 }
            // n = 4, score = 200
            //   7538                 | je                  0x3d
            //   8b442420             | jne                 0x3a
            //   488b8c2480010000     | mov                 eax, dword ptr [esp + 0x20]
            //   8b542430             | dec                 eax

        $sequence_15 = { 488d8424a0010000 ba10000000 488bc8 e8???????? b801000000 488b8c24e8010000 }
            // n = 6, score = 200
            //   488d8424a0010000     | mov                 dword ptr [esp + 0x38], eax
            //   ba10000000           | dec                 eax
            //   488bc8               | mov                 eax, dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   b801000000           | dec                 eax
            //   488b8c24e8010000     | lea                 eax, [esp + 0x1a0]

    condition:
        7 of them and filesize < 196608
}
