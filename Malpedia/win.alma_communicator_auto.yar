rule win_alma_communicator_auto {

    meta:
        id = "4qtNfC4TgcnEEFxgkopHso"
        fingerprint = "v1_sha256_904bfc03a43918532b57223d9b7b36661a7e5069ea789e70ed097e9455614910"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.alma_communicator."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_communicator"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f802 7509 80bdfdfdffff3a 7429 }
            // n = 4, score = 200
            //   83f802               | cmp                 eax, 2
            //   7509                 | jne                 0xb
            //   80bdfdfdffff3a       | cmp                 byte ptr [ebp - 0x203], 0x3a
            //   7429                 | je                  0x2b

        $sequence_1 = { 89442414 8bf1 8b4c2424 85c9 }
            // n = 4, score = 200
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8bf1                 | mov                 esi, ecx
            //   8b4c2424             | mov                 ecx, dword ptr [esp + 0x24]
            //   85c9                 | test                ecx, ecx

        $sequence_2 = { 8bca 8d542424 83e103 f3a4 8b4c2414 6a01 }
            // n = 6, score = 200
            //   8bca                 | mov                 ecx, edx
            //   8d542424             | lea                 edx, [esp + 0x24]
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   6a01                 | push                1

        $sequence_3 = { 8b4508 dd00 ebc6 c745e018514100 e9???????? c745e020514100 }
            // n = 6, score = 200
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   dd00                 | fld                 qword ptr [eax]
            //   ebc6                 | jmp                 0xffffffc8
            //   c745e018514100       | mov                 dword ptr [ebp - 0x20], 0x415118
            //   e9????????           |                     
            //   c745e020514100       | mov                 dword ptr [ebp - 0x20], 0x415120

        $sequence_4 = { 59 59 eb14 6a10 68???????? }
            // n = 5, score = 200
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   eb14                 | jmp                 0x16
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_5 = { 47 84c0 75f8 be???????? 8d85fcfbffff 68ff010000 50 }
            // n = 7, score = 200
            //   47                   | inc                 edi
            //   84c0                 | test                al, al
            //   75f8                 | jne                 0xfffffffa
            //   be????????           |                     
            //   8d85fcfbffff         | lea                 eax, [ebp - 0x404]
            //   68ff010000           | push                0x1ff
            //   50                   | push                eax

        $sequence_6 = { ba???????? 8901 66a1???????? 51 66894104 }
            // n = 5, score = 200
            //   ba????????           |                     
            //   8901                 | mov                 dword ptr [ecx], eax
            //   66a1????????         |                     
            //   51                   | push                ecx
            //   66894104             | mov                 word ptr [ecx + 4], ax

        $sequence_7 = { 0f4ecb 8bd9 7fe6 8bfe 8d4f01 }
            // n = 5, score = 200
            //   0f4ecb               | cmovle              ecx, ebx
            //   8bd9                 | mov                 ebx, ecx
            //   7fe6                 | jg                  0xffffffe8
            //   8bfe                 | mov                 edi, esi
            //   8d4f01               | lea                 ecx, [edi + 1]

        $sequence_8 = { c6840508faffff00 33c9 8a840d08faffff 88840d20f6ffff }
            // n = 4, score = 200
            //   c6840508faffff00     | mov                 byte ptr [ebp + eax - 0x5f8], 0
            //   33c9                 | xor                 ecx, ecx
            //   8a840d08faffff       | mov                 al, byte ptr [ebp + ecx - 0x5f8]
            //   88840d20f6ffff       | mov                 byte ptr [ebp + ecx - 0x9e0], al

        $sequence_9 = { 53 56 33f6 8955f8 8bd9 57 }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   8bd9                 | mov                 ebx, ecx
            //   57                   | push                edi

    condition:
        7 of them and filesize < 245760
}
