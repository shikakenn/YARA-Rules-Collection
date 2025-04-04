rule win_wormhole_auto {

    meta:
        id = "2RS3reGnvKp5jlIhG4s4Bn"
        fingerprint = "v1_sha256_98b6efb48ef674cd1e4efeda549804876add0f8847a14dfa9ff2b839bd666e8b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.wormhole."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wormhole"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a00 6a00 6a00 6808000100 51 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6808000100           | push                0x10008
            //   51                   | push                ecx

        $sequence_1 = { 48 83c880 40 83c040 }
            // n = 4, score = 200
            //   48                   | dec                 eax
            //   83c880               | or                  eax, 0xffffff80
            //   40                   | inc                 eax
            //   83c040               | add                 eax, 0x40

        $sequence_2 = { 85c0 7e0f 2bf0 03f8 85f6 7fc8 5f }
            // n = 7, score = 200
            //   85c0                 | test                eax, eax
            //   7e0f                 | jle                 0x11
            //   2bf0                 | sub                 esi, eax
            //   03f8                 | add                 edi, eax
            //   85f6                 | test                esi, esi
            //   7fc8                 | jg                  0xffffffca
            //   5f                   | pop                 edi

        $sequence_3 = { 83c880 40 83c040 89442418 50 }
            // n = 5, score = 200
            //   83c880               | or                  eax, 0xffffff80
            //   40                   | inc                 eax
            //   83c040               | add                 eax, 0x40
            //   89442418             | mov                 dword ptr [esp + 0x18], eax
            //   50                   | push                eax

        $sequence_4 = { 8b6c2420 8b5c2414 8b7c2418 6a00 }
            // n = 4, score = 200
            //   8b6c2420             | mov                 ebp, dword ptr [esp + 0x20]
            //   8b5c2414             | mov                 ebx, dword ptr [esp + 0x14]
            //   8b7c2418             | mov                 edi, dword ptr [esp + 0x18]
            //   6a00                 | push                0

        $sequence_5 = { ffd3 8b35???????? 8d44240c 8b4c2410 50 51 ffd6 }
            // n = 7, score = 200
            //   ffd3                 | call                ebx
            //   8b35????????         |                     
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   ffd6                 | call                esi

        $sequence_6 = { 6a78 8d542410 50 52 57 e8???????? }
            // n = 6, score = 200
            //   6a78                 | push                0x78
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   50                   | push                eax
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_7 = { 52 57 e8???????? 83c410 85c0 748f }
            // n = 6, score = 200
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   85c0                 | test                eax, eax
            //   748f                 | je                  0xffffff91

        $sequence_8 = { 52 ffd6 8b44240c 8b4c2414 50 }
            // n = 5, score = 200
            //   52                   | push                edx
            //   ffd6                 | call                esi
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8b4c2414             | mov                 ecx, dword ptr [esp + 0x14]
            //   50                   | push                eax

        $sequence_9 = { 6a00 51 6a02 89442424 ffd3 }
            // n = 5, score = 200
            //   6a00                 | push                0
            //   51                   | push                ecx
            //   6a02                 | push                2
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   ffd3                 | call                ebx

    condition:
        7 of them and filesize < 99576
}
