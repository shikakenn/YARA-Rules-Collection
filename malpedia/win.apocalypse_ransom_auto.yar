rule win_apocalypse_ransom_auto {

    meta:
        id = "3bv0xdSpt5kspAXZns8gZU"
        fingerprint = "v1_sha256_18df20f7eebe1c78a082ce30f5a4491f9ac67772b997a33222fc4d85121626f7"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.apocalypse_ransom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.apocalypse_ransom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 57 8bf8 6a3d 893d???????? ffd3 8bf0 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   8bf8                 | mov                 edi, eax
            //   6a3d                 | push                0x3d
            //   893d????????         |                     
            //   ffd3                 | call                ebx
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { 50 8d8c2410040000 51 ff15???????? 8d442408 e8???????? }
            // n = 6, score = 200
            //   50                   | push                eax
            //   8d8c2410040000       | lea                 ecx, [esp + 0x410]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d442408             | lea                 eax, [esp + 8]
            //   e8????????           |                     

        $sequence_2 = { 0bd7 7479 56 8d44241c 68???????? 50 }
            // n = 6, score = 200
            //   0bd7                 | or                  edx, edi
            //   7479                 | je                  0x7b
            //   56                   | push                esi
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_3 = { 89442424 8b44241c 6a6d 50 c744243006000000 c74424346d000000 }
            // n = 6, score = 200
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   6a6d                 | push                0x6d
            //   50                   | push                eax
            //   c744243006000000     | mov                 dword ptr [esp + 0x30], 6
            //   c74424346d000000     | mov                 dword ptr [esp + 0x34], 0x6d

        $sequence_4 = { ff15???????? 68???????? 8d84240c040000 50 ff15???????? 85c0 742f }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   68????????           |                     
            //   8d84240c040000       | lea                 eax, [esp + 0x40c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   742f                 | je                  0x31

        $sequence_5 = { e8???????? 6a6d 56 ff15???????? 8b3d???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   6a6d                 | push                0x6d
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b3d????????         |                     

        $sequence_6 = { 68???????? ff15???????? 8d542408 52 ff15???????? 83f8ff }
            // n = 6, score = 200
            //   68????????           |                     
            //   ff15????????         |                     
            //   8d542408             | lea                 edx, [esp + 8]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1

        $sequence_7 = { 0bd7 7479 56 8d44241c 68???????? 50 ffd5 }
            // n = 7, score = 200
            //   0bd7                 | or                  edx, edi
            //   7479                 | je                  0x7b
            //   56                   | push                esi
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd5                 | call                ebp

        $sequence_8 = { 8d442410 50 68???????? 6802000080 ffd6 8d4c2414 }
            // n = 6, score = 200
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   ffd6                 | call                esi
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_9 = { 6a01 6800000080 8d4c2440 51 ffd6 8bf8 }
            // n = 6, score = 200
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   8d4c2440             | lea                 ecx, [esp + 0x40]
            //   51                   | push                ecx
            //   ffd6                 | call                esi
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 40960
}
