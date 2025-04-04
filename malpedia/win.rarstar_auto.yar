rule win_rarstar_auto {

    meta:
        id = "68uVTWKY0McDBm9Acx0auI"
        fingerprint = "v1_sha256_731c9230a2c0993fe7a5be5efd272fc408168bba25b13288ff7847590ce53fc3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rarstar."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rarstar"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8dbc2424020000 f3ab bf???????? 83c9ff }
            // n = 4, score = 100
            //   8dbc2424020000       | lea                 edi, [esp + 0x224]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_1 = { f2ae f7d1 49 8d44240c 2bca 51 50 }
            // n = 7, score = 100
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   2bca                 | sub                 ecx, edx
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_2 = { 50 ffd5 85c0 0f8445010000 8b442420 85c0 742f }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   85c0                 | test                eax, eax
            //   0f8445010000         | je                  0x14b
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   85c0                 | test                eax, eax
            //   742f                 | je                  0x31

        $sequence_3 = { 8bc6 5e c20400 81ec24030000 53 }
            // n = 5, score = 100
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   81ec24030000         | sub                 esp, 0x324
            //   53                   | push                ebx

        $sequence_4 = { 33db 8a940c24010000 8a5c0c24 03c2 03c3 25ff000080 }
            // n = 6, score = 100
            //   33db                 | xor                 ebx, ebx
            //   8a940c24010000       | mov                 dl, byte ptr [esp + ecx + 0x124]
            //   8a5c0c24             | mov                 bl, byte ptr [esp + ecx + 0x24]
            //   03c2                 | add                 eax, edx
            //   03c3                 | add                 eax, ebx
            //   25ff000080           | and                 eax, 0x800000ff

        $sequence_5 = { 33db 8a940c20010000 8a5c0c20 03c2 03c3 25ff000080 7907 }
            // n = 7, score = 100
            //   33db                 | xor                 ebx, ebx
            //   8a940c20010000       | mov                 dl, byte ptr [esp + ecx + 0x120]
            //   8a5c0c20             | mov                 bl, byte ptr [esp + ecx + 0x20]
            //   03c2                 | add                 eax, edx
            //   03c3                 | add                 eax, ebx
            //   25ff000080           | and                 eax, 0x800000ff
            //   7907                 | jns                 9

        $sequence_6 = { 7605 2bc1 83c003 8d14c500000000 b8abaaaaaa }
            // n = 5, score = 100
            //   7605                 | jbe                 7
            //   2bc1                 | sub                 eax, ecx
            //   83c003               | add                 eax, 3
            //   8d14c500000000       | lea                 edx, [eax*8]
            //   b8abaaaaaa           | mov                 eax, 0xaaaaaaab

        $sequence_7 = { f3ab bf???????? 83c9ff 33db 8d942424020000 f2ae f7d1 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33db                 | xor                 ebx, ebx
            //   8d942424020000       | lea                 edx, [esp + 0x224]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_8 = { 33db 8a940c24010000 8a5c0c24 03c2 03c3 }
            // n = 5, score = 100
            //   33db                 | xor                 ebx, ebx
            //   8a940c24010000       | mov                 dl, byte ptr [esp + ecx + 0x124]
            //   8a5c0c24             | mov                 bl, byte ptr [esp + ecx + 0x24]
            //   03c2                 | add                 eax, edx
            //   03c3                 | add                 eax, ebx

        $sequence_9 = { 52 50 68???????? 57 895c241c c744243802000000 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi
            //   895c241c             | mov                 dword ptr [esp + 0x1c], ebx
            //   c744243802000000     | mov                 dword ptr [esp + 0x38], 2

    condition:
        7 of them and filesize < 122880
}
