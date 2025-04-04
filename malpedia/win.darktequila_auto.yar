rule win_darktequila_auto {

    meta:
        id = "70osjPJfX5bVqaxjyWxsdC"
        fingerprint = "v1_sha256_7a615b9f83311311d3befdcf3fa9a13c4c4dc7e52e3af67816a4aeaa810facc1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.darktequila."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darktequila"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b803000000 e8???????? 6a0b 50 e8???????? 8b4310 }
            // n = 6, score = 200
            //   b803000000           | mov                 eax, 3
            //   e8????????           |                     
            //   6a0b                 | push                0xb
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]

        $sequence_1 = { ff15???????? 85c0 740a c705????????01000000 b80b000000 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   740a                 | je                  0xc
            //   c705????????01000000     |     
            //   b80b000000           | mov                 eax, 0xb

        $sequence_2 = { 85c0 7423 8b4b10 803c085c 7404 c604085c }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   7423                 | je                  0x25
            //   8b4b10               | mov                 ecx, dword ptr [ebx + 0x10]
            //   803c085c             | cmp                 byte ptr [eax + ecx], 0x5c
            //   7404                 | je                  6
            //   c604085c             | mov                 byte ptr [eax + ecx], 0x5c

        $sequence_3 = { 8945f8 85c0 7467 8b4b0c }
            // n = 4, score = 200
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   85c0                 | test                eax, eax
            //   7467                 | je                  0x69
            //   8b4b0c               | mov                 ecx, dword ptr [ebx + 0xc]

        $sequence_4 = { 85c0 740d 8d9b00000000 c60300 43 }
            // n = 5, score = 200
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   8d9b00000000         | lea                 ebx, [ebx]
            //   c60300               | mov                 byte ptr [ebx], 0
            //   43                   | inc                 ebx

        $sequence_5 = { 8b4d08 8b15???????? 8901 8913 }
            // n = 4, score = 200
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b15????????         |                     
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8913                 | mov                 dword ptr [ebx], edx

        $sequence_6 = { 85c0 740d 894610 b801000000 }
            // n = 4, score = 200
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   b801000000           | mov                 eax, 1

        $sequence_7 = { 895e0c 5b c3 8b5610 }
            // n = 4, score = 200
            //   895e0c               | mov                 dword ptr [esi + 0xc], ebx
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8b5610               | mov                 edx, dword ptr [esi + 0x10]

        $sequence_8 = { 8bc1 894308 8b45d8 8b4dfc 33cd }
            // n = 5, score = 200
            //   8bc1                 | mov                 eax, ecx
            //   894308               | mov                 dword ptr [ebx + 8], eax
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cd                 | xor                 ecx, ebp

        $sequence_9 = { 85db 0f84c2000000 56 57 8d4102 e8???????? }
            // n = 6, score = 200
            //   85db                 | test                ebx, ebx
            //   0f84c2000000         | je                  0xc8
            //   56                   | push                esi
            //   57                   | push                edi
            //   8d4102               | lea                 eax, [ecx + 2]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1827840
}
