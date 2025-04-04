rule win_rtm_auto {

    meta:
        id = "1xV6brV5kfEPezt1fiHCAY"
        fingerprint = "v1_sha256_f9f968bd72b07daecebbe59f710503eb3e7e66a7761ea2777fb33c14c58163c2"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rtm"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { b805000000 e8???????? 84c0 740f be02000000 e8???????? }
            // n = 6, score = 500
            //   b805000000           | mov                 eax, 5
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   740f                 | je                  0x11
            //   be02000000           | mov                 esi, 2
            //   e8????????           |                     

        $sequence_1 = { 85f6 7416 8bd6 8bc3 e8???????? 8bf8 }
            // n = 6, score = 500
            //   85f6                 | test                esi, esi
            //   7416                 | je                  0x18
            //   8bd6                 | mov                 edx, esi
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { eb1e 8bc6 e8???????? 33c0 eb13 6a00 e8???????? }
            // n = 7, score = 500
            //   eb1e                 | jmp                 0x20
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   eb13                 | jmp                 0x15
            //   6a00                 | push                0
            //   e8????????           |                     

        $sequence_3 = { 8b06 e8???????? 50 8bc6 e8???????? 5a e8???????? }
            // n = 7, score = 500
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   5a                   | pop                 edx
            //   e8????????           |                     

        $sequence_4 = { 50 8b45f4 50 a1???????? 50 8b45e8 }
            // n = 6, score = 500
            //   50                   | push                eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   50                   | push                eax
            //   a1????????           |                     
            //   50                   | push                eax
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_5 = { 8b55e4 a1???????? 8b00 33c9 e8???????? 8b45f4 33d2 }
            // n = 7, score = 500
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   a1????????           |                     
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   33c9                 | xor                 ecx, ecx
            //   e8????????           |                     
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   33d2                 | xor                 edx, edx

        $sequence_6 = { 8bc3 e8???????? 84c0 7430 8b55f8 d1ea 8bc7 }
            // n = 7, score = 500
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7430                 | je                  0x32
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   d1ea                 | shr                 edx, 1
            //   8bc7                 | mov                 eax, edi

        $sequence_7 = { 837dfc00 7444 8d55f8 8b45fc e8???????? 8b45f8 }
            // n = 6, score = 500
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   7444                 | je                  0x46
            //   8d55f8               | lea                 edx, [ebp - 8]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_8 = { 47 8d85a8fdffff 50 53 e8???????? 85c0 }
            // n = 6, score = 500
            //   47                   | inc                 edi
            //   8d85a8fdffff         | lea                 eax, [ebp - 0x258]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_9 = { 8bf8 85ff 7441 6a02 8bc6 e8???????? 50 }
            // n = 7, score = 500
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7441                 | je                  0x43
            //   6a02                 | push                2
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 471040
}
