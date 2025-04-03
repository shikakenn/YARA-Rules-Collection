rule win_sienna_purple_auto {

    meta:
        id = "6eTtz8TXBmYdqZtvbnyhvQ"
        fingerprint = "v1_sha256_7480d66d62837df5528ba634142a2c05768c45916ca5058033314d20ebc94573"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sienna_purple."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sienna_purple"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c7460404000000 8b4604 bb04000000 03c1 c745fc00000000 33c9 f7e3 }
            // n = 7, score = 100
            //   c7460404000000       | mov                 dword ptr [esi + 4], 4
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   bb04000000           | mov                 ebx, 4
            //   03c1                 | add                 eax, ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   33c9                 | xor                 ecx, ecx
            //   f7e3                 | mul                 ebx

        $sequence_1 = { 81fe04020000 0f8321010000 888435ecfdffff 8d4601 3d04020000 0f830c010000 c68405ecfdffff00 }
            // n = 7, score = 100
            //   81fe04020000         | cmp                 esi, 0x204
            //   0f8321010000         | jae                 0x127
            //   888435ecfdffff       | mov                 byte ptr [ebp + esi - 0x214], al
            //   8d4601               | lea                 eax, [esi + 1]
            //   3d04020000           | cmp                 eax, 0x204
            //   0f830c010000         | jae                 0x112
            //   c68405ecfdffff00     | mov                 byte ptr [ebp + eax - 0x214], 0

        $sequence_2 = { e8???????? 84c0 0f8481000000 8d8d1cffffff e8???????? 6a3a 50 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f8481000000         | je                  0x87
            //   8d8d1cffffff         | lea                 ecx, [ebp - 0xe4]
            //   e8????????           |                     
            //   6a3a                 | push                0x3a
            //   50                   | push                eax

        $sequence_3 = { e8???????? 837e0c00 7427 807e1000 7421 6a28 8bcb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   837e0c00             | cmp                 dword ptr [esi + 0xc], 0
            //   7427                 | je                  0x29
            //   807e1000             | cmp                 byte ptr [esi + 0x10], 0
            //   7421                 | je                  0x23
            //   6a28                 | push                0x28
            //   8bcb                 | mov                 ecx, ebx

        $sequence_4 = { e8???????? 85c0 0f84ff010000 6a00 8bc8 e8???????? 8bf8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f84ff010000         | je                  0x205
            //   6a00                 | push                0
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_5 = { d1ff 8bc7 897584 89bd6cffffff c7459c00000000 c7458c70105000 251f000080 }
            // n = 7, score = 100
            //   d1ff                 | sar                 edi, 1
            //   8bc7                 | mov                 eax, edi
            //   897584               | mov                 dword ptr [ebp - 0x7c], esi
            //   89bd6cffffff         | mov                 dword ptr [ebp - 0x94], edi
            //   c7459c00000000       | mov                 dword ptr [ebp - 0x64], 0
            //   c7458c70105000       | mov                 dword ptr [ebp - 0x74], 0x501070
            //   251f000080           | and                 eax, 0x8000001f

        $sequence_6 = { e8???????? 8bb570ffffff 8a03 03f7 ff8578ffffff 8807 803e00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bb570ffffff         | mov                 esi, dword ptr [ebp - 0x90]
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   03f7                 | add                 esi, edi
            //   ff8578ffffff         | inc                 dword ptr [ebp - 0x88]
            //   8807                 | mov                 byte ptr [edi], al
            //   803e00               | cmp                 byte ptr [esi], 0

        $sequence_7 = { 8d4e10 e8???????? 83f803 0f86f3000000 0f57c0 c745ec00000000 8d4dd4 }
            // n = 7, score = 100
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   e8????????           |                     
            //   83f803               | cmp                 eax, 3
            //   0f86f3000000         | jbe                 0xf9
            //   0f57c0               | xorps               xmm0, xmm0
            //   c745ec00000000       | mov                 dword ptr [ebp - 0x14], 0
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]

        $sequence_8 = { e9???????? 3c13 7516 6893000000 68ce000000 8bce e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   3c13                 | cmp                 al, 0x13
            //   7516                 | jne                 0x18
            //   6893000000           | push                0x93
            //   68ce000000           | push                0xce
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_9 = { 8bec 57 8b7d08 8b4708 85c0 7503 5f }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   85c0                 | test                eax, eax
            //   7503                 | jne                 5
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 2930688
}
