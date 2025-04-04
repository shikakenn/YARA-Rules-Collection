rule win_crypmic_auto {

    meta:
        id = "6npsnDCYfjCPH0T8xyKNHh"
        fingerprint = "v1_sha256_bac6071bafa0b8d2c9908dd1914b7cdff1ecb7962c586174feb22c09b0eeeac5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.crypmic."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypmic"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0fb7d2 41 66891406 8d3409 }
            // n = 4, score = 300
            //   0fb7d2               | movzx               edx, dx
            //   41                   | inc                 ecx
            //   66891406             | mov                 word ptr [esi + eax], dx
            //   8d3409               | lea                 esi, [ecx + ecx]

        $sequence_1 = { 66833800 75f6 8d3c72 33c0 }
            // n = 4, score = 300
            //   66833800             | cmp                 word ptr [eax], 0
            //   75f6                 | jne                 0xfffffff8
            //   8d3c72               | lea                 edi, [edx + esi*2]
            //   33c0                 | xor                 eax, eax

        $sequence_2 = { 8bec 83ec10 837d0800 8bc2 }
            // n = 4, score = 300
            //   8bec                 | mov                 ebp, esp
            //   83ec10               | sub                 esp, 0x10
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   8bc2                 | mov                 eax, edx

        $sequence_3 = { ffd0 85c0 7e0e 8b4dfc 03c8 894dfc 2bf0 }
            // n = 7, score = 300
            //   ffd0                 | call                eax
            //   85c0                 | test                eax, eax
            //   7e0e                 | jle                 0x10
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   03c8                 | add                 ecx, eax
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   2bf0                 | sub                 esi, eax

        $sequence_4 = { 8b550c 53 2bc2 56 8945f0 }
            // n = 5, score = 300
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   53                   | push                ebx
            //   2bc2                 | sub                 eax, edx
            //   56                   | push                esi
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_5 = { 894f04 8b4de8 894f08 668b4df0 66894f0c 668b45f2 6689470e }
            // n = 7, score = 300
            //   894f04               | mov                 dword ptr [edi + 4], ecx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   894f08               | mov                 dword ptr [edi + 8], ecx
            //   668b4df0             | mov                 cx, word ptr [ebp - 0x10]
            //   66894f0c             | mov                 word ptr [edi + 0xc], cx
            //   668b45f2             | mov                 ax, word ptr [ebp - 0xe]
            //   6689470e             | mov                 word ptr [edi + 0xe], ax

        $sequence_6 = { 8b7df0 b90e000000 f3a4 8b7dfc 6a00 }
            // n = 5, score = 300
            //   8b7df0               | mov                 edi, dword ptr [ebp - 0x10]
            //   b90e000000           | mov                 ecx, 0xe
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b7dfc               | mov                 edi, dword ptr [ebp - 4]
            //   6a00                 | push                0

        $sequence_7 = { 5d c3 8b55fc 5f 8b4224 5e }
            // n = 6, score = 300
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   5f                   | pop                 edi
            //   8b4224               | mov                 eax, dword ptr [edx + 0x24]
            //   5e                   | pop                 esi

        $sequence_8 = { ff4d08 89550c 7582 5f }
            // n = 4, score = 300
            //   ff4d08               | dec                 dword ptr [ebp + 8]
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   7582                 | jne                 0xffffff84
            //   5f                   | pop                 edi

        $sequence_9 = { 57 ffd1 8bc3 5f 5e 5b }
            // n = 6, score = 300
            //   57                   | push                edi
            //   ffd1                 | call                ecx
            //   8bc3                 | mov                 eax, ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 81920
}
