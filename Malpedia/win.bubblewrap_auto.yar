rule win_bubblewrap_auto {

    meta:
        id = "55iRXJj22P35y1Zc0jkwGU"
        fingerprint = "v1_sha256_0ab9a85f4803bb9809d1835ce4819efcd3e97bce18ea2653e803520f80f6784f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bubblewrap."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bubblewrap"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bc8 83e103 f3a4 8d4c2418 51 55 e8???????? }
            // n = 7, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   e8????????           |                     

        $sequence_1 = { a1???????? 8b15???????? 83c404 f3a5 8b0d???????? a3???????? }
            // n = 6, score = 100
            //   a1????????           |                     
            //   8b15????????         |                     
            //   83c404               | add                 esp, 4
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b0d????????         |                     
            //   a3????????           |                     

        $sequence_2 = { c3 b940000000 33c0 8dbc24a9000000 c68424a800000000 }
            // n = 5, score = 100
            //   c3                   | ret                 
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8dbc24a9000000       | lea                 edi, [esp + 0xa9]
            //   c68424a800000000     | mov                 byte ptr [esp + 0xa8], 0

        $sequence_3 = { 750b 5f 5e 5d 5b 81c4a0ba0400 c3 }
            // n = 7, score = 100
            //   750b                 | jne                 0xd
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c4a0ba0400         | add                 esp, 0x4baa0
            //   c3                   | ret                 

        $sequence_4 = { 0bc2 49 79f0 89442458 33c0 }
            // n = 5, score = 100
            //   0bc2                 | or                  eax, edx
            //   49                   | dec                 ecx
            //   79f0                 | jns                 0xfffffff2
            //   89442458             | mov                 dword ptr [esp + 0x58], eax
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 83c408 50 57 8b3d???????? ffd7 68???????? }
            // n = 6, score = 100
            //   83c408               | add                 esp, 8
            //   50                   | push                eax
            //   57                   | push                edi
            //   8b3d????????         |                     
            //   ffd7                 | call                edi
            //   68????????           |                     

        $sequence_6 = { 5d 5b 81c4a0ba0400 c3 8b442410 8d4c2464 898424a4000000 }
            // n = 7, score = 100
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c4a0ba0400         | add                 esp, 0x4baa0
            //   c3                   | ret                 
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8d4c2464             | lea                 ecx, [esp + 0x64]
            //   898424a4000000       | mov                 dword ptr [esp + 0xa4], eax

        $sequence_7 = { 83c404 eb37 a1???????? 8b35???????? 50 ffd6 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   eb37                 | jmp                 0x39
            //   a1????????           |                     
            //   8b35????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi

        $sequence_8 = { 0f8feffeffff 5b 8d4d02 b856555555 f7e9 8bc2 5f }
            // n = 7, score = 100
            //   0f8feffeffff         | jg                  0xfffffef5
            //   5b                   | pop                 ebx
            //   8d4d02               | lea                 ecx, [ebp + 2]
            //   b856555555           | mov                 eax, 0x55555556
            //   f7e9                 | imul                ecx
            //   8bc2                 | mov                 eax, edx
            //   5f                   | pop                 edi

        $sequence_9 = { 33d2 89742414 8d6ced00 89542418 }
            // n = 4, score = 100
            //   33d2                 | xor                 edx, edx
            //   89742414             | mov                 dword ptr [esp + 0x14], esi
            //   8d6ced00             | lea                 ebp, [ebp + ebp*8]
            //   89542418             | mov                 dword ptr [esp + 0x18], edx

    condition:
        7 of them and filesize < 57136
}
