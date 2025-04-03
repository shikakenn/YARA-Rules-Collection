rule win_cueisfry_auto {

    meta:
        id = "4xhp9fHGYPtDW0YrfVKsnQ"
        fingerprint = "v1_sha256_fe662cbb30073bd6bd4ed92effaa065add48a5ad78c3a6b1fdab8c2e82a82aba"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cueisfry."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cueisfry"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b44241c c1e308 0bdf 8b542438 }
            // n = 4, score = 100
            //   8b44241c             | mov                 eax, dword ptr [esp + 0x1c]
            //   c1e308               | shl                 ebx, 8
            //   0bdf                 | or                  ebx, edi
            //   8b542438             | mov                 edx, dword ptr [esp + 0x38]

        $sequence_1 = { 897dfc 57 897dd8 c645fc01 ff15???????? 8d4dec }
            // n = 6, score = 100
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   57                   | push                edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   ff15????????         |                     
            //   8d4dec               | lea                 ecx, [ebp - 0x14]

        $sequence_2 = { 6803400080 e8???????? 8b45ec 8b08 50 ff5108 897dec }
            // n = 7, score = 100
            //   6803400080           | push                0x80004003
            //   e8????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   50                   | push                eax
            //   ff5108               | call                dword ptr [ecx + 8]
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi

        $sequence_3 = { 0f95c0 84c0 7508 83c8ff e9???????? 8b2d???????? 33f6 }
            // n = 7, score = 100
            //   0f95c0               | setne               al
            //   84c0                 | test                al, al
            //   7508                 | jne                 0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     
            //   8b2d????????         |                     
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { f3a5 50 e8???????? 8d4c2424 51 e8???????? }
            // n = 6, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_5 = { ff15???????? 8bcf 8be8 8bd1 33c0 8bfd }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   8bcf                 | mov                 ecx, edi
            //   8be8                 | mov                 ebp, eax
            //   8bd1                 | mov                 edx, ecx
            //   33c0                 | xor                 eax, eax
            //   8bfd                 | mov                 edi, ebp

        $sequence_6 = { b910000000 8d7c241c f3a5 8d4c241c 68???????? }
            // n = 5, score = 100
            //   b910000000           | mov                 ecx, 0x10
            //   8d7c241c             | lea                 edi, [esp + 0x1c]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   68????????           |                     

        $sequence_7 = { 50 8d442434 6a01 50 ffd7 56 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   56                   | push                esi

        $sequence_8 = { 85c0 0f95c0 be???????? 8dbc24b0010000 84c0 f3a5 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   be????????           |                     
            //   8dbc24b0010000       | lea                 edi, [esp + 0x1b0]
            //   84c0                 | test                al, al
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]

        $sequence_9 = { 83c40c 53 ff15???????? 68???????? e8???????? 83c404 }
            // n = 6, score = 100
            //   83c40c               | add                 esp, 0xc
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

    condition:
        7 of them and filesize < 81920
}
