rule win_nitrogen_auto {

    meta:
        id = "6I5WaBoEY8uQzivygrApVT"
        fingerprint = "v1_sha256_7fc10887629eb8cbe7591a0bc8e19e89881d6b530c9068ab47e88598472a7314"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nitrogen."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitrogen"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb0b c784246805000000000000 8b05???????? 0faf842468050000 8bc0 0fb74c2444 0fbfc9 }
            // n = 7, score = 100
            //   eb0b                 | add                 eax, 0x42
            //   c784246805000000000000     | jmp    0x813
            //   8b05????????         |                     
            //   0faf842468050000     | mov                 eax, dword ptr [esp + 0x30]
            //   8bc0                 | mov                 dword ptr [esp + 0x330], eax
            //   0fb74c2444           | mov                 eax, dword ptr [esp + 0x330]
            //   0fbfc9               | jmp                 0x88a

        $sequence_1 = { 7416 eb25 0fb6442434 0fbec0 c1e007 4898 4889442468 }
            // n = 7, score = 100
            //   7416                 | mov                 byte ptr [esp + 0x26], al
            //   eb25                 | mov                 eax, 0xffffd51a
            //   0fb6442434           | mov                 word ptr [esp + 0x18], ax
            //   0fbec0               | dec                 eax
            //   c1e007               | mov                 dword ptr [esp + 0x48], 0xbf87
            //   4898                 | mov                 eax, 0xffffeb3f
            //   4889442468           | mov                 word ptr [esp + 0x14], ax

        $sequence_2 = { b8b37e0000 6689442438 0fb605???????? 480fbec0 4889842490000000 488b05???????? 48898424a8010000 }
            // n = 7, score = 100
            //   b8b37e0000           | movsx               eax, ax
            //   6689442438           | dec                 eax
            //   0fb605????????       |                     
            //   480fbec0             | mov                 dword ptr [esp + 0x90], eax
            //   4889842490000000     | mov                 eax, 0xf920d7cf
            //   488b05????????       |                     
            //   48898424a8010000     | mov                 eax, 0x2c58

        $sequence_3 = { c644245d01 eb05 c644245d00 0fb644245d 8805???????? 0fb7442430 0fb7c0 }
            // n = 7, score = 100
            //   c644245d01           | mov                 esi, ecx
            //   eb05                 | movzx               eax, al
            //   c644245d00           | mov                 ecx, dword ptr [esp + 0x5c]
            //   0fb644245d           | inc                 ecx
            //   8805????????         |                     
            //   0fb7442430           | cmp                 eax, ecx
            //   0fb7c0               | jne                 0x5b6

        $sequence_4 = { eb0b c78424dc02000000000000 8b8424dc020000 398424e0020000 7e02 eb17 0fbf05???????? }
            // n = 7, score = 100
            //   eb0b                 | mov                 dword ptr [esp + 0x278], 0
            //   c78424dc02000000000000     | mov    eax, dword ptr [esp + 0x278]
            //   8b8424dc020000       | cmp                 dword ptr [esp + 0x27c], eax
            //   398424e0020000       | jl                  0x76d
            //   7e02                 | jmp                 0x77c
            //   eb17                 | mov                 eax, dword ptr [esp + 0x6c]
            //   0fbf05????????       |                     

        $sequence_5 = { b83f670000 668944243c 0fb6442431 0fbec0 05c222fae3 8bc0 4889842498000000 }
            // n = 7, score = 100
            //   b83f670000           | dec                 eax
            //   668944243c           | imul                eax, eax, 0x3f
            //   0fb6442431           | dec                 eax
            //   0fbec0               | lea                 ecx, [0x9d8aef]
            //   05c222fae3           | movzx               edx, word ptr [esp + 0x2c]
            //   8bc0                 | dec                 eax
            //   4889842498000000     | movsx               edx, dx

        $sequence_6 = { c744247404000000 488b842440010000 488905???????? 0fb7442428 98 0fbf4c2434 33c1 }
            // n = 7, score = 100
            //   c744247404000000     | mov                 byte ptr [esp + 0x5c], 0x3d
            //   488b842440010000     | mov                 byte ptr [esp + 0x5d], 0xae
            //   488905????????       |                     
            //   0fb7442428           | mov                 byte ptr [esp + 0x57], 0xf6
            //   98                   | mov                 byte ptr [esp + 0x68], 0x3c
            //   0fbf4c2434           | mov                 byte ptr [esp + 0x58], al
            //   33c1                 | dec                 eax

        $sequence_7 = { e8???????? 4989c3 b9508cf2a7 e8???????? 4883c428 488b4c2408 488b542410 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4989c3               | mov                 dword ptr [esp + 0x48], eax
            //   b9508cf2a7           | jmp                 0xf9b
            //   e8????????           |                     
            //   4883c428             | dec                 eax
            //   488b4c2408           | mov                 eax, dword ptr [esp + 0x50]
            //   488b542410           | dec                 eax

        $sequence_8 = { c644240b35 488b05???????? 4889842498000000 0fb605???????? 0fb6c0 8944246c 0fb6442408 }
            // n = 7, score = 100
            //   c644240b35           | mov                 ecx, dword ptr [esp + 8]
            //   488b05????????       |                     
            //   4889842498000000     | dec                 eax
            //   0fb605????????       |                     
            //   0fb6c0               | mov                 edx, dword ptr [esp + 0x10]
            //   8944246c             | dec                 esp
            //   0fb6442408           | mov                 eax, dword ptr [esp + 0x18]

        $sequence_9 = { e8???????? 898424f8020000 0fbe442441 b904000000 4869c98f020000 488d157f9e3b00 89040a }
            // n = 7, score = 100
            //   e8????????           |                     
            //   898424f8020000       | dec                 eax
            //   0fbe442441           | add                 esp, 0x28
            //   b904000000           | dec                 eax
            //   4869c98f020000       | mov                 ecx, dword ptr [esp + 8]
            //   488d157f9e3b00       | dec                 eax
            //   89040a               | mov                 edx, dword ptr [esp + 0x10]

    condition:
        7 of them and filesize < 65433600
}
