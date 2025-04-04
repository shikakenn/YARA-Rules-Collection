rule win_darkmegi_auto {

    meta:
        id = "6mlQ30fV4GkNsw9CfbTcpP"
        fingerprint = "v1_sha256_cbefd542cb2be5b91d54762f56be197fb7c2a5e2f979e1fe8e05b6ab3d5c06b3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.darkmegi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { bf???????? 83c9ff 33c0 33d2 f2ae 8b6c2418 f7d1 }
            // n = 7, score = 100
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   33d2                 | xor                 edx, edx
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   8b6c2418             | mov                 ebp, dword ptr [esp + 0x18]
            //   f7d1                 | not                 ecx

        $sequence_1 = { 50 687e660480 57 c744241c00000000 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   687e660480           | push                0x8004667e
            //   57                   | push                edi
            //   c744241c00000000     | mov                 dword ptr [esp + 0x1c], 0

        $sequence_2 = { 8bc1 8bf7 8bbc24ac020000 c1e902 f3a5 }
            // n = 5, score = 100
            //   8bc1                 | mov                 eax, ecx
            //   8bf7                 | mov                 esi, edi
            //   8bbc24ac020000       | mov                 edi, dword ptr [esp + 0x2ac]
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_3 = { 49 3bd9 7cd2 8806 5f 5e }
            // n = 6, score = 100
            //   49                   | dec                 ecx
            //   3bd9                 | cmp                 ebx, ecx
            //   7cd2                 | jl                  0xffffffd4
            //   8806                 | mov                 byte ptr [esi], al
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { 83d8ff 85c0 0f8420010000 8d842468010000 }
            // n = 4, score = 100
            //   83d8ff               | sbb                 eax, -1
            //   85c0                 | test                eax, eax
            //   0f8420010000         | je                  0x126
            //   8d842468010000       | lea                 eax, [esp + 0x168]

        $sequence_5 = { 53 ffd5 56 ffd5 57 ff15???????? 5f }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ffd5                 | call                ebp
            //   56                   | push                esi
            //   ffd5                 | call                ebp
            //   57                   | push                edi
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_6 = { 8b8c8424010000 668b5108 52 ffd5 }
            // n = 4, score = 100
            //   8b8c8424010000       | mov                 ecx, dword ptr [esp + eax*4 + 0x124]
            //   668b5108             | mov                 dx, word ptr [ecx + 8]
            //   52                   | push                edx
            //   ffd5                 | call                ebp

        $sequence_7 = { 83c408 85ff 0f84a8000000 47 68???????? }
            // n = 5, score = 100
            //   83c408               | add                 esp, 8
            //   85ff                 | test                edi, edi
            //   0f84a8000000         | je                  0xae
            //   47                   | inc                 edi
            //   68????????           |                     

        $sequence_8 = { 8b2d???????? f2ae 8b84249e030000 33db f7d1 }
            // n = 5, score = 100
            //   8b2d????????         |                     
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   8b84249e030000       | mov                 eax, dword ptr [esp + 0x39e]
            //   33db                 | xor                 ebx, ebx
            //   f7d1                 | not                 ecx

        $sequence_9 = { c3 e8???????? 8b0cf59c8cb402 5e }
            // n = 4, score = 100
            //   c3                   | ret                 
            //   e8????????           |                     
            //   8b0cf59c8cb402       | mov                 ecx, dword ptr [esi*8 + 0x2b48c9c]
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 90304
}
