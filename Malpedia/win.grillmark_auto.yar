rule win_grillmark_auto {

    meta:
        id = "6RIShJpErlc4ZHaz9YAi2p"
        fingerprint = "v1_sha256_3b34499d4c29c52da57dd97a7dde84f3954319d72fae7b0456cb1c1378f5429f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.grillmark."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grillmark"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 53 50 68???????? ff35???????? 56 e8???????? 68???????? }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   50                   | push                eax
            //   68????????           |                     
            //   ff35????????         |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   68????????           |                     

        $sequence_1 = { 40 83c104 ebf5 5d c3 55 8bec }
            // n = 7, score = 300
            //   40                   | inc                 eax
            //   83c104               | add                 ecx, 4
            //   ebf5                 | jmp                 0xfffffff7
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_2 = { e8???????? a3???????? ff35???????? 8d85e4fdffff 68???????? 50 e8???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   a3????????           |                     
            //   ff35????????         |                     
            //   8d85e4fdffff         | lea                 eax, [ebp - 0x21c]
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_3 = { 50 ffb604010000 56 e8???????? }
            // n = 4, score = 300
            //   50                   | push                eax
            //   ffb604010000         | push                dword ptr [esi + 0x104]
            //   56                   | push                esi
            //   e8????????           |                     

        $sequence_4 = { e8???????? 59 85c0 59 0f85a4000000 682c020000 6a40 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   0f85a4000000         | jne                 0xaa
            //   682c020000           | push                0x22c
            //   6a40                 | push                0x40

        $sequence_5 = { 56 ff750c e8???????? 83c40c 6a01 5b }
            // n = 6, score = 300
            //   56                   | push                esi
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   6a01                 | push                1
            //   5b                   | pop                 ebx

        $sequence_6 = { 59 75f2 ff7508 eb03 ff75f4 e8???????? 59 }
            // n = 7, score = 300
            //   59                   | pop                 ecx
            //   75f2                 | jne                 0xfffffff4
            //   ff7508               | push                dword ptr [ebp + 8]
            //   eb03                 | jmp                 5
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_7 = { 7439 48 7579 68???????? }
            // n = 4, score = 300
            //   7439                 | je                  0x3b
            //   48                   | dec                 eax
            //   7579                 | jne                 0x7b
            //   68????????           |                     

        $sequence_8 = { 7405 83f86f 7532 ff75fc e8???????? 8bf0 59 }
            // n = 7, score = 300
            //   7405                 | je                  7
            //   83f86f               | cmp                 eax, 0x6f
            //   7532                 | jne                 0x34
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx

        $sequence_9 = { 802600 5f 8908 8b45f8 5e }
            // n = 5, score = 300
            //   802600               | and                 byte ptr [esi], 0
            //   5f                   | pop                 edi
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   5e                   | pop                 esi

    condition:
        7 of them and filesize < 212992
}
