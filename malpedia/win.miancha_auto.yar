rule win_miancha_auto {

    meta:
        id = "45F39i4sWMahaCS9jOkREi"
        fingerprint = "v1_sha256_265db074bcd13da1887f66f32f80a00bfe9fccbd1f685bc2e9a0d53a7fe9cd80"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.miancha."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miancha"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8910 8b15???????? 894804 8b0d???????? 895008 8a15???????? 89480c }
            // n = 7, score = 200
            //   8910                 | mov                 dword ptr [eax], edx
            //   8b15????????         |                     
            //   894804               | mov                 dword ptr [eax + 4], ecx
            //   8b0d????????         |                     
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8a15????????         |                     
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx

        $sequence_1 = { 6a02 6a00 68???????? 52 ffd6 }
            // n = 5, score = 200
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   68????????           |                     
            //   52                   | push                edx
            //   ffd6                 | call                esi

        $sequence_2 = { 52 ff15???????? 50 ffd6 85c0 741a 837c241800 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   741a                 | je                  0x1c
            //   837c241800           | cmp                 dword ptr [esp + 0x18], 0

        $sequence_3 = { 50 8d4e01 51 68???????? e8???????? }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8d4e01               | lea                 ecx, [esi + 1]
            //   51                   | push                ecx
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_4 = { 56 8b35???????? 6a02 6a00 68???????? }
            // n = 5, score = 200
            //   56                   | push                esi
            //   8b35????????         |                     
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_5 = { 68???????? 68???????? c744242000000000 ff15???????? 50 ff15???????? 8bf0 }
            // n = 7, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { 6a01 6a00 68???????? 51 ffd6 85c0 }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax

        $sequence_7 = { 68???????? 68???????? c744242000000000 ff15???????? 50 ff15???????? }
            // n = 6, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_8 = { 85f6 7412 8d542418 52 }
            // n = 4, score = 200
            //   85f6                 | test                esi, esi
            //   7412                 | je                  0x14
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx

        $sequence_9 = { 7412 8d542418 52 ff15???????? 50 ffd6 }
            // n = 6, score = 200
            //   7412                 | je                  0x14
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi

    condition:
        7 of them and filesize < 376832
}
