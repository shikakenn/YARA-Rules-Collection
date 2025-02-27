rule win_ratankbapos_auto {

    meta:
        id = "3NbLNiuzTie1kBbQtwT2ak"
        fingerprint = "v1_sha256_17591f183be92d031983360942e373f37d5a48aae82c019ca5afd1168616aff1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ratankbapos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankbapos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d0cfd484a0110 8b11 3b55e0 7408 48 83e908 }
            // n = 6, score = 300
            //   8d0cfd484a0110       | lea                 ecx, [edi*8 + 0x10014a48]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   3b55e0               | cmp                 edx, dword ptr [ebp - 0x20]
            //   7408                 | je                  0xa
            //   48                   | dec                 eax
            //   83e908               | sub                 ecx, 8

        $sequence_1 = { 83c40c 6800100000 53 56 }
            // n = 4, score = 300
            //   83c40c               | add                 esp, 0xc
            //   6800100000           | push                0x1000
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_2 = { 8b0c8de04d0110 c1e006 0fbe440104 83e040 5d c3 a1???????? }
            // n = 7, score = 300
            //   8b0c8de04d0110       | mov                 ecx, dword ptr [ecx*4 + 0x10014de0]
            //   c1e006               | shl                 eax, 6
            //   0fbe440104           | movsx               eax, byte ptr [ecx + eax + 4]
            //   83e040               | and                 eax, 0x40
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   a1????????           |                     

        $sequence_3 = { 83e01f c1f905 8b0c8de04d0110 c1e006 8d440104 800820 8b4df4 }
            // n = 7, score = 300
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8de04d0110       | mov                 ecx, dword ptr [ecx*4 + 0x10014de0]
            //   c1e006               | shl                 eax, 6
            //   8d440104             | lea                 eax, [ecx + eax + 4]
            //   800820               | or                  byte ptr [eax], 0x20
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_4 = { c6040800 8b55a0 52 8945c4 e8???????? 8b4da4 8945c8 }
            // n = 7, score = 300
            //   c6040800             | mov                 byte ptr [eax + ecx], 0
            //   8b55a0               | mov                 edx, dword ptr [ebp - 0x60]
            //   52                   | push                edx
            //   8945c4               | mov                 dword ptr [ebp - 0x3c], eax
            //   e8????????           |                     
            //   8b4da4               | mov                 ecx, dword ptr [ebp - 0x5c]
            //   8945c8               | mov                 dword ptr [ebp - 0x38], eax

        $sequence_5 = { ff15???????? 8b55c4 52 894314 }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   8b55c4               | mov                 edx, dword ptr [ebp - 0x3c]
            //   52                   | push                edx
            //   894314               | mov                 dword ptr [ebx + 0x14], eax

        $sequence_6 = { 4f 8a4f01 47 84c9 75f8 8b95f4dfffff 8bc8 }
            // n = 7, score = 300
            //   4f                   | dec                 edi
            //   8a4f01               | mov                 cl, byte ptr [edi + 1]
            //   47                   | inc                 edi
            //   84c9                 | test                cl, cl
            //   75f8                 | jne                 0xfffffffa
            //   8b95f4dfffff         | mov                 edx, dword ptr [ebp - 0x200c]
            //   8bc8                 | mov                 ecx, eax

        $sequence_7 = { e8???????? 59 59 8b7508 8d34f5303c0110 391e }
            // n = 6, score = 300
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8d34f5303c0110       | lea                 esi, [esi*8 + 0x10013c30]
            //   391e                 | cmp                 dword ptr [esi], ebx

        $sequence_8 = { 56 e8???????? 8d0445c4420110 8bc8 }
            // n = 4, score = 300
            //   56                   | push                esi
            //   e8????????           |                     
            //   8d0445c4420110       | lea                 eax, [eax*2 + 0x100142c4]
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 8bc1 8da42400000000 8a10 3a11 751a 84d2 7412 }
            // n = 7, score = 300
            //   8bc1                 | mov                 eax, ecx
            //   8da42400000000       | lea                 esp, [esp]
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   3a11                 | cmp                 dl, byte ptr [ecx]
            //   751a                 | jne                 0x1c
            //   84d2                 | test                dl, dl
            //   7412                 | je                  0x14

    condition:
        7 of them and filesize < 327680
}
