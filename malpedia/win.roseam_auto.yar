rule win_roseam_auto {

    meta:
        id = "26GxqDCrR7fls05DTGuRAq"
        fingerprint = "v1_sha256_6405b276e56fbb6391489a72f41f1ba4fb7da1db3c06ee822f393f99823911b5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.roseam."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.roseam"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0f8512010000 33f6 b963000000 8dbd76ecffff 6689b574ecffff f3ab }
            // n = 6, score = 100
            //   0f8512010000         | jne                 0x118
            //   33f6                 | xor                 esi, esi
            //   b963000000           | mov                 ecx, 0x63
            //   8dbd76ecffff         | lea                 edi, [ebp - 0x138a]
            //   6689b574ecffff       | mov                 word ptr [ebp - 0x138c], si
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_1 = { 681de40a18 56 e8???????? 83c408 a3???????? 50 }
            // n = 6, score = 100
            //   681de40a18           | push                0x180ae41d
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   a3????????           |                     
            //   50                   | push                eax

        $sequence_2 = { 3bda 895df0 895508 8955f8 aa 0f8e8a040000 8b4510 }
            // n = 7, score = 100
            //   3bda                 | cmp                 ebx, edx
            //   895df0               | mov                 dword ptr [ebp - 0x10], ebx
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   aa                   | stosb               byte ptr es:[edi], al
            //   0f8e8a040000         | jle                 0x490
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_3 = { 9d 5d 58 33c0 668945fd 8845ff }
            // n = 6, score = 100
            //   9d                   | popfd               
            //   5d                   | pop                 ebp
            //   58                   | pop                 eax
            //   33c0                 | xor                 eax, eax
            //   668945fd             | mov                 word ptr [ebp - 3], ax
            //   8845ff               | mov                 byte ptr [ebp - 1], al

        $sequence_4 = { 50 51 52 c745fc00000000 ff15???????? 85c0 0f8504020000 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8504020000         | jne                 0x20a

        $sequence_5 = { 80c241 8855ff 68???????? 55 }
            // n = 4, score = 100
            //   80c241               | add                 dl, 0x41
            //   8855ff               | mov                 byte ptr [ebp - 1], dl
            //   68????????           |                     
            //   55                   | push                ebp

        $sequence_6 = { 894df8 8b4d10 2bc8 8d5004 894d10 8b4dfc 89550c }
            // n = 7, score = 100
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   2bc8                 | sub                 ecx, eax
            //   8d5004               | lea                 edx, [eax + 4]
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx

        $sequence_7 = { 53 56 57 8b02 8945f8 50 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   50                   | push                eax

        $sequence_8 = { 58 8bc2 5f 5e }
            // n = 4, score = 100
            //   58                   | pop                 eax
            //   8bc2                 | mov                 eax, edx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 668901 0fbe560c 89550c 68???????? }
            // n = 4, score = 100
            //   668901               | mov                 word ptr [ecx], ax
            //   0fbe560c             | movsx               edx, byte ptr [esi + 0xc]
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   68????????           |                     

    condition:
        7 of them and filesize < 221184
}
