rule win_rorschach_auto {

    meta:
        id = "64ux2YlcPGjK9xZGf8oJ1S"
        fingerprint = "v1_sha256_3819d2826273a95ad95ce552fb76b197f4eb30ddd0b4d089208f0442591f4b17"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rorschach."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rorschach"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f30f6f440420 f30f6f0c28 660fefc8 f30f7f0c30 418d40f0 f30f6f440420 f30f6f0c28 }
            // n = 7, score = 100
            //   f30f6f440420         | lea                 ecx, [ebp + 0x570]
            //   f30f6f0c28           | mov                 byte ptr [ebp + 0x739], al
            //   660fefc8             | xor                 edx, edx
            //   f30f7f0c30           | dec                 eax
            //   418d40f0             | lea                 ecx, [ebp + 0x6d0]
            //   f30f6f440420         | mov                 byte ptr [ebp + 0x73a], al
            //   f30f6f0c28           | mov                 dl, 0x68

        $sequence_1 = { e8???????? 8885f6050000 b261 488d8d70050000 e8???????? 8885f7050000 33d2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8885f6050000         | lea                 ecx, [ebp + 0x150]
            //   b261                 | mov                 byte ptr [ebp + 0x306], al
            //   488d8d70050000       | mov                 dl, 0x2d
            //   e8????????           |                     
            //   8885f7050000         | dec                 eax
            //   33d2                 | lea                 ecx, [ebp + 0x150]

        $sequence_2 = { ff15???????? 85c0 7414 488b4c2438 4c8d442444 488d5570 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   85c0                 | mov                 byte ptr [ebp + 0xb60], al
            //   7414                 | mov                 dl, 0x66
            //   488b4c2438           | dec                 eax
            //   4c8d442444           | lea                 ecx, [ebp + 0xb30]
            //   488d5570             | mov                 byte ptr [ebp + 0xc5f], al
            //   ff15????????         |                     

        $sequence_3 = { eb04 33c0 8bd8 b978110000 e8???????? 488bf8 48894540 }
            // n = 7, score = 100
            //   eb04                 | mov                 byte ptr [ebp + 0xc30], al
            //   33c0                 | mov                 dl, 0x6f
            //   8bd8                 | dec                 eax
            //   b978110000           | lea                 ecx, [ebp + 0xb30]
            //   e8????????           |                     
            //   488bf8               | mov                 byte ptr [ebp + 0xc31], al
            //   48894540             | xor                 edx, edx

        $sequence_4 = { 488d4d28 e8???????? 884529 33d2 488d4d28 e8???????? 88452a }
            // n = 7, score = 100
            //   488d4d28             | mov                 byte ptr [ebp - 0x42], al
            //   e8????????           |                     
            //   884529               | xor                 eax, eax
            //   33d2                 | mov                 word ptr [ebp - 0x41], ax
            //   488d4d28             | dec                 esp
            //   e8????????           |                     
            //   88452a               | mov                 esi, ebx

        $sequence_5 = { 488d8d00010000 e8???????? 88850f010000 33d2 488d8d00010000 e8???????? 888510010000 }
            // n = 7, score = 100
            //   488d8d00010000       | dec                 eax
            //   e8????????           |                     
            //   88850f010000         | lea                 ecx, [ebp + 0x260]
            //   33d2                 | mov                 byte ptr [ebp + 0x272], al
            //   488d8d00010000       | mov                 dl, 0x3e
            //   e8????????           |                     
            //   888510010000         | dec                 eax

        $sequence_6 = { e8???????? 488d8598070000 488985b80c0000 c6454069 b273 488d4d40 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d8598070000       | mov                 esp, ebx
            //   488985b80c0000       | inc                 ecx
            //   c6454069             | pop                 edi
            //   b273                 | inc                 ecx
            //   488d4d40             | pop                 esi
            //   e8????????           |                     

        $sequence_7 = { 48897820 488b05???????? 4833c4 488985f0020000 bae9030000 ff15???????? 488bf0 }
            // n = 7, score = 100
            //   48897820             | dec                 eax
            //   488b05????????       |                     
            //   4833c4               | lea                 eax, [esp + 0x39]
            //   488985f0020000       | dec                 ecx
            //   bae9030000           | mov                 eax, 0xffffffff
            //   ff15????????         |                     
            //   488bf0               | dec                 ecx

        $sequence_8 = { e8???????? 8885d7060000 33d2 488d8dd0060000 e8???????? 8885d8060000 b26b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8885d7060000         | xor                 dl, al
            //   33d2                 | mov                 byte ptr [ebp - 0x1d], dl
            //   488d8dd0060000       | inc                 ebp
            //   e8????????           |                     
            //   8885d8060000         | xor                 al, al
            //   b26b                 | inc                 esp

        $sequence_9 = { 8885f60b0000 b23c 488d8d300b0000 e8???????? 8885f70b0000 33d2 488d8d300b0000 }
            // n = 7, score = 100
            //   8885f60b0000         | lea                 ecx, [ebp + 0x150]
            //   b23c                 | mov                 byte ptr [ebp + 0x30d], al
            //   488d8d300b0000       | dec                 eax
            //   e8????????           |                     
            //   8885f70b0000         | lea                 ecx, [ebp + 0x150]
            //   33d2                 | mov                 byte ptr [ebp + 0x20d], al
            //   488d8d300b0000       | xor                 edx, edx

    condition:
        7 of them and filesize < 3921930
}
