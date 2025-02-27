rule win_duqu_auto {

    meta:
        id = "S7idYpAOnUfEKllAz6mHB"
        fingerprint = "v1_sha256_c898aec26da15be1184cad51dbcbbea7d5de6c2fe0a6afa2af1a2af031fa3007"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.duqu."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duqu"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 8bd8 895c2414 85db 755b }
            // n = 5, score = 400
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   895c2414             | mov                 dword ptr [esp + 0x14], ebx
            //   85db                 | test                ebx, ebx
            //   755b                 | jne                 0x5d

        $sequence_1 = { 8bd7 84c0 74c7 33c9 3c2e }
            // n = 5, score = 400
            //   8bd7                 | mov                 edx, edi
            //   84c0                 | test                al, al
            //   74c7                 | je                  0xffffffc9
            //   33c9                 | xor                 ecx, ecx
            //   3c2e                 | cmp                 al, 0x2e

        $sequence_2 = { e8???????? 894624 85c0 0f8474020000 baf71ad500 8bcf }
            // n = 6, score = 400
            //   e8????????           |                     
            //   894624               | mov                 dword ptr [esi + 0x24], eax
            //   85c0                 | test                eax, eax
            //   0f8474020000         | je                  0x27a
            //   baf71ad500           | mov                 edx, 0xd51af7
            //   8bcf                 | mov                 ecx, edi

        $sequence_3 = { e8???????? ba2760f046 89463c 8bcf e8???????? 894640 85c0 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   ba2760f046           | mov                 edx, 0x46f06027
            //   89463c               | mov                 dword ptr [esi + 0x3c], eax
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   894640               | mov                 dword ptr [esi + 0x40], eax
            //   85c0                 | test                eax, eax

        $sequence_4 = { b9c64ff867 894c2424 8b07 03c6 c7442414ffff3f00 89442420 894c2418 }
            // n = 7, score = 400
            //   b9c64ff867           | mov                 ecx, 0x67f84fc6
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   03c6                 | add                 eax, esi
            //   c7442414ffff3f00     | mov                 dword ptr [esp + 0x14], 0x3fffff
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx

        $sequence_5 = { 56 51 8bf2 e8???????? }
            // n = 4, score = 400
            //   56                   | push                esi
            //   51                   | push                ecx
            //   8bf2                 | mov                 esi, edx
            //   e8????????           |                     

        $sequence_6 = { ba19729c9f 89461c 8bcb e8???????? ba4c1241f2 894630 }
            // n = 6, score = 400
            //   ba19729c9f           | mov                 edx, 0x9f9c7219
            //   89461c               | mov                 dword ptr [esi + 0x1c], eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   ba4c1241f2           | mov                 edx, 0xf241124c
            //   894630               | mov                 dword ptr [esi + 0x30], eax

        $sequence_7 = { e8???????? ba56f0665d 894674 8bcb e8???????? ba244135d1 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   ba56f0665d           | mov                 edx, 0x5d66f056
            //   894674               | mov                 dword ptr [esi + 0x74], eax
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   ba244135d1           | mov                 edx, 0xd1354124

        $sequence_8 = { ba0ded3515 8bcb e8???????? ba0b7bb6ba }
            // n = 4, score = 400
            //   ba0ded3515           | mov                 edx, 0x1535ed0d
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   ba0b7bb6ba           | mov                 edx, 0xbab67b0b

        $sequence_9 = { 85c0 7465 e8???????? 85c0 }
            // n = 4, score = 400
            //   85c0                 | test                eax, eax
            //   7465                 | je                  0x67
            //   e8????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_10 = { 8bec 51 57 33ff b9???????? }
            // n = 5, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   b9????????           |                     

        $sequence_11 = { 8bec 51 66833d????????00 7429 }
            // n = 4, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   66833d????????00     |                     
            //   7429                 | je                  0x2b

        $sequence_12 = { 8bec 51 a1???????? 56 57 6a28 }
            // n = 6, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   a1????????           |                     
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a28                 | push                0x28

        $sequence_13 = { 8bec 51 53 56 be???????? 57 33db }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   be????????           |                     
            //   57                   | push                edi
            //   33db                 | xor                 ebx, ebx

        $sequence_14 = { 8bec 51 6a00 8d45fc 50 6a04 }
            // n = 6, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   6a04                 | push                4

        $sequence_15 = { 8bec 51 56 57 894dfc 8bfa b22e }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8bfa                 | mov                 edi, edx
            //   b22e                 | mov                 dl, 0x2e

    condition:
        7 of them and filesize < 18759680
}
