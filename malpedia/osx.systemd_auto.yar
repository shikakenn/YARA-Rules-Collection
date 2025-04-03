rule osx_systemd_auto {

    meta:
        id = "4yU4Il5Aw6YQZGYBPalzA5"
        fingerprint = "v1_sha256_db75faf3db0bba23e839a9106222d2da5e9549d4daefbfc95826c10e024becd7"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/osx.systemd"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 49 8b0424 49 8b4c2408 49 894d28 }
            // n = 6, score = 100
            //   49                   | dec                 ecx
            //   8b0424               | mov                 eax, dword ptr [esp]
            //   49                   | dec                 ecx
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   49                   | dec                 ecx
            //   894d28               | mov                 dword ptr [ebp + 0x28], ecx

        $sequence_1 = { 41 01f2 41 ffc5 41 89f8 }
            // n = 6, score = 100
            //   41                   | inc                 ecx
            //   01f2                 | add                 edx, esi
            //   41                   | inc                 ecx
            //   ffc5                 | inc                 ebp
            //   41                   | inc                 ecx
            //   89f8                 | mov                 eax, edi

        $sequence_2 = { f00fc148f8 85c9 7fa6 48 8d75b8 e8???????? }
            // n = 6, score = 100
            //   f00fc148f8           | lock xadd           dword ptr [eax - 8], ecx
            //   85c9                 | test                ecx, ecx
            //   7fa6                 | jg                  0xffffffa8
            //   48                   | dec                 eax
            //   8d75b8               | lea                 esi, [ebp - 0x48]
            //   e8????????           |                     

        $sequence_3 = { 49 3314c1 48 89f8 48 c1e80d 48 }
            // n = 7, score = 100
            //   49                   | dec                 ecx
            //   3314c1               | xor                 edx, dword ptr [ecx + eax*8]
            //   48                   | dec                 eax
            //   89f8                 | mov                 eax, edi
            //   48                   | dec                 eax
            //   c1e80d               | shr                 eax, 0xd
            //   48                   | dec                 eax

        $sequence_4 = { 48 898578ffffff 48 8d7d88 48 8d7580 48 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   898578ffffff         | mov                 dword ptr [ebp - 0x88], eax
            //   48                   | dec                 eax
            //   8d7d88               | lea                 edi, [ebp - 0x78]
            //   48                   | dec                 eax
            //   8d7580               | lea                 esi, [ebp - 0x80]
            //   48                   | dec                 eax

        $sequence_5 = { c1e01c 48 09c8 48 338678010000 48 89c1 }
            // n = 7, score = 100
            //   c1e01c               | shl                 eax, 0x1c
            //   48                   | dec                 eax
            //   09c8                 | or                  eax, ecx
            //   48                   | dec                 eax
            //   338678010000         | xor                 eax, dword ptr [esi + 0x178]
            //   48                   | dec                 eax
            //   89c1                 | mov                 ecx, eax

        $sequence_6 = { 89f2 e8???????? 31c9 b8???????? 0f1f840000000000 4c }
            // n = 6, score = 100
            //   89f2                 | mov                 edx, esi
            //   e8????????           |                     
            //   31c9                 | xor                 ecx, ecx
            //   b8????????           |                     
            //   0f1f840000000000     | nop                 dword ptr [eax + eax]
            //   4c                   | dec                 esp

        $sequence_7 = { 89f5 49 89fe 49 8b4e08 49 3b4e10 }
            // n = 7, score = 100
            //   89f5                 | mov                 ebp, esi
            //   49                   | dec                 ecx
            //   89fe                 | mov                 esi, edi
            //   49                   | dec                 ecx
            //   8b4e08               | mov                 ecx, dword ptr [esi + 8]
            //   49                   | dec                 ecx
            //   3b4e10               | cmp                 ecx, dword ptr [esi + 0x10]

        $sequence_8 = { e8???????? c7833c04000000000000 4c 89f7 48 83c408 5b }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c7833c04000000000000     | mov    dword ptr [ebx + 0x43c], 0
            //   4c                   | dec                 esp
            //   89f7                 | mov                 edi, esi
            //   48                   | dec                 eax
            //   83c408               | add                 esp, 8
            //   5b                   | pop                 ebx

        $sequence_9 = { 48 31f8 48 01d0 be81e6a1d8 48 01c6 }
            // n = 7, score = 100
            //   48                   | dec                 eax
            //   31f8                 | xor                 eax, edi
            //   48                   | dec                 eax
            //   01d0                 | add                 eax, edx
            //   be81e6a1d8           | mov                 esi, 0xd8a1e681
            //   48                   | dec                 eax
            //   01c6                 | add                 esi, eax

    condition:
        7 of them and filesize < 381108
}
