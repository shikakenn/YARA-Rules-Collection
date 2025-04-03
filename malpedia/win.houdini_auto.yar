rule win_houdini_auto {

    meta:
        id = "6Nc5zJJx6HvYufxQmO8sx7"
        fingerprint = "v1_sha256_47f96c22958c442ee3f5f1c730331cf3d789500b5a9f241f822746dd06969064"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.houdini"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b45bc e8???????? 50 8d45b8 8b5508 b900000000 }
            // n = 6, score = 100
            //   8b45bc               | mov                 eax, dword ptr [ebp - 0x44]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d45b8               | lea                 eax, [ebp - 0x48]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   b900000000           | mov                 ecx, 0

        $sequence_1 = { 8bfa 8bd8 8b4604 50 8b0e 8bd7 8bc3 }
            // n = 7, score = 100
            //   8bfa                 | mov                 edi, edx
            //   8bd8                 | mov                 ebx, eax
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   50                   | push                eax
            //   8b0e                 | mov                 ecx, dword ptr [esi]
            //   8bd7                 | mov                 edx, edi
            //   8bc3                 | mov                 eax, ebx

        $sequence_2 = { f6d8 1bc0 c3 83780403 0f94c0 f6d8 1bc0 }
            // n = 7, score = 100
            //   f6d8                 | neg                 al
            //   1bc0                 | sbb                 eax, eax
            //   c3                   | ret                 
            //   83780403             | cmp                 dword ptr [eax + 4], 3
            //   0f94c0               | sete                al
            //   f6d8                 | neg                 al
            //   1bc0                 | sbb                 eax, eax

        $sequence_3 = { 51 8bd8 33f6 54 8b4304 50 e8???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8bd8                 | mov                 ebx, eax
            //   33f6                 | xor                 esi, esi
            //   54                   | push                esp
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { 5b c3 8d4604 50 8b4304 50 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   8d4604               | lea                 eax, [esi + 4]
            //   50                   | push                eax
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   50                   | push                eax

        $sequence_5 = { 00745b5b 00745b5b 007c5b5b 007c5b5b 00845b5b00845b 5b 008c5b5b008c5b }
            // n = 7, score = 100
            //   00745b5b             | add                 byte ptr [ebx + ebx*2 + 0x5b], dh
            //   00745b5b             | add                 byte ptr [ebx + ebx*2 + 0x5b], dh
            //   007c5b5b             | add                 byte ptr [ebx + ebx*2 + 0x5b], bh
            //   007c5b5b             | add                 byte ptr [ebx + ebx*2 + 0x5b], bh
            //   00845b5b00845b       | add                 byte ptr [ebx + ebx*2 + 0x5b84005b], al
            //   5b                   | pop                 ebx
            //   008c5b5b008c5b       | add                 byte ptr [ebx + ebx*2 + 0x5b8c005b], cl

        $sequence_6 = { 896b08 85ed 750e ba03000000 8bc7 e8???????? eb44 }
            // n = 7, score = 100
            //   896b08               | mov                 dword ptr [ebx + 8], ebp
            //   85ed                 | test                ebp, ebp
            //   750e                 | jne                 0x10
            //   ba03000000           | mov                 edx, 3
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   eb44                 | jmp                 0x46

        $sequence_7 = { 8bf2 8bd8 54 56 8b4304 50 e8???????? }
            // n = 7, score = 100
            //   8bf2                 | mov                 esi, edx
            //   8bd8                 | mov                 ebx, eax
            //   54                   | push                esp
            //   56                   | push                esi
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_8 = { 83780403 0f93c0 f6d8 1bc0 c3 83780404 }
            // n = 6, score = 100
            //   83780403             | cmp                 dword ptr [eax + 4], 3
            //   0f93c0               | setae               al
            //   f6d8                 | neg                 al
            //   1bc0                 | sbb                 eax, eax
            //   c3                   | ret                 
            //   83780404             | cmp                 dword ptr [eax + 4], 4

        $sequence_9 = { 8b45fc b901000000 8b55f8 e8???????? ff4df8 837df800 75b6 }
            // n = 7, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   b901000000           | mov                 ecx, 1
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   e8????????           |                     
            //   ff4df8               | dec                 dword ptr [ebp - 8]
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   75b6                 | jne                 0xffffffb8

    condition:
        7 of them and filesize < 6307840
}
