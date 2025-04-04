rule osx_bella_auto {

    meta:
        id = "54P8Tj9dRwmHylokBZMQMx"
        fingerprint = "v1_sha256_aaa2ed27d317fb2b216e41ca548e81d6f344680df2c55d4fb31df320a3554050"
        version = "1"
        date = "2020-08-17"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.bella"
        malpedia_rule_date = "20200817"
        malpedia_hash = "8c895fd01eccb47a6225bcb1a3ba53cbb98644c5"
        malpedia_version = "20200817"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffe0 48 89d1 48 89c3 83f901 0f8580010000 }
            // n = 7, score = 100
            //   ffe0                 | jmp                 eax
            //   48                   | dec                 eax
            //   89d1                 | mov                 ecx, edx
            //   48                   | dec                 eax
            //   89c3                 | mov                 ebx, eax
            //   83f901               | cmp                 ecx, 1
            //   0f8580010000         | jne                 0x186

        $sequence_1 = { 89c7 48 8b3d???????? 48 8b05???????? 49 }
            // n = 6, score = 100
            //   89c7                 | mov                 edi, eax
            //   48                   | dec                 eax
            //   8b3d????????         |                     
            //   48                   | dec                 eax
            //   8b05????????         |                     
            //   49                   | dec                 ecx

        $sequence_2 = { 897dc0 48 8b3d???????? 48 8b35???????? 4c }
            // n = 6, score = 100
            //   897dc0               | mov                 dword ptr [ebp - 0x40], edi
            //   48                   | dec                 eax
            //   8b3d????????         |                     
            //   48                   | dec                 eax
            //   8b35????????         |                     
            //   4c                   | dec                 esp

        $sequence_3 = { c745cc00000000 31c0 48 89df 41 ffd4 48 }
            // n = 7, score = 100
            //   c745cc00000000       | mov                 dword ptr [ebp - 0x34], 0
            //   31c0                 | xor                 eax, eax
            //   48                   | dec                 eax
            //   89df                 | mov                 edi, ebx
            //   41                   | inc                 ecx
            //   ffd4                 | call                esp
            //   48                   | dec                 eax

        $sequence_4 = { 8b15???????? 4c 8d059c270000 4c 8d0d40140000 31c0 }
            // n = 6, score = 100
            //   8b15????????         |                     
            //   4c                   | dec                 esp
            //   8d059c270000         | lea                 eax, [0x279c]
            //   4c                   | dec                 esp
            //   8d0d40140000         | lea                 ecx, [0x1440]
            //   31c0                 | xor                 eax, eax

        $sequence_5 = { 89ff 48 89c6 4c 89e1 4d 89e8 }
            // n = 7, score = 100
            //   89ff                 | mov                 edi, edi
            //   48                   | dec                 eax
            //   89c6                 | mov                 esi, eax
            //   4c                   | dec                 esp
            //   89e1                 | mov                 ecx, esp
            //   4d                   | dec                 ebp
            //   89e8                 | mov                 eax, ebp

        $sequence_6 = { 89c5 4c 8965d0 48 8b35???????? }
            // n = 5, score = 100
            //   89c5                 | mov                 ebp, eax
            //   4c                   | dec                 esp
            //   8965d0               | mov                 dword ptr [ebp - 0x30], esp
            //   48                   | dec                 eax
            //   8b35????????         |                     

        $sequence_7 = { 53 48 83ec28 48 897dc8 48 8b3d???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   48                   | dec                 eax
            //   83ec28               | sub                 esp, 0x28
            //   48                   | dec                 eax
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   48                   | dec                 eax
            //   8b3d????????         |                     

        $sequence_8 = { 8b35???????? 48 8d15cf260000 31c0 41 ffd4 48 }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   48                   | dec                 eax
            //   8d15cf260000         | lea                 edx, [0x26cf]
            //   31c0                 | xor                 eax, eax
            //   41                   | inc                 ecx
            //   ffd4                 | call                esp
            //   48                   | dec                 eax

        $sequence_9 = { 8b0d???????? 48 8b15???????? 4c 8d2deb2c0000 }
            // n = 5, score = 100
            //   8b0d????????         |                     
            //   48                   | dec                 eax
            //   8b15????????         |                     
            //   4c                   | dec                 esp
            //   8d2deb2c0000         | lea                 ebp, [0x2ceb]

    condition:
        7 of them and filesize < 380864
}
