rule win_deltastealer_auto {

    meta:
        id = "6Bh71cSP3MeYzVtg1Tc1Nf"
        fingerprint = "v1_sha256_7a995bc7de4a09d620f7c56a219adce0b4fee73dcf5dde633c44a4fcc3f98e63"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.deltastealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deltastealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7317 eb5f 660f6f07 660fd7c0 f7d0 4881c600fdffff 4883c710 }
            // n = 7, score = 200
            //   7317                 | jae                 0x32f
            //   eb5f                 | xor                 eax, 1
            //   660f6f07             | add                 eax, 0x76e
            //   660fd7c0             | mov                 ecx, eax
            //   f7d0                 | lea                 eax, [esi - 0x291]
            //   4881c600fdffff       | cmp                 eax, 0xe
            //   4883c710             | jae                 0x344

        $sequence_1 = { 488d442438 488910 4c8d4c2440 498901 4d897108 488b4e38 488b5650 }
            // n = 7, score = 200
            //   488d442438           | xor                 eax, eax
            //   488910               | cmp                 edx, ecx
            //   4c8d4c2440           | inc                 ecx
            //   498901               | cmove               eax, eax
            //   4d897108             | dec                 eax
            //   488b4e38             | lea                 edx, [0x14839a]
            //   488b5650             | dec                 eax

        $sequence_2 = { 89d5 4889ce 488b09 488b4608 ba27000000 ff5020 40b701 }
            // n = 7, score = 200
            //   89d5                 | inc                 ebp
            //   4889ce               | dec                 ecx
            //   488b09               | not                 esi
            //   488b4608             | mov                 edx, ecx
            //   ba27000000           | and                 edx, 0x7f
            //   ff5020               | shl                 edx, 7
            //   40b701               | movzx               esi, si

        $sequence_3 = { 5e 415c 415e 415f c3 0fb611 4883fa05 }
            // n = 7, score = 200
            //   5e                   | inc                 ecx
            //   415c                 | pop                 esi
            //   415e                 | inc                 ecx
            //   415f                 | pop                 edi
            //   c3                   | ret                 
            //   0fb611               | dec                 eax
            //   4883fa05             | lea                 ecx, [0x4695f]

        $sequence_4 = { 4989d8 e8???????? 4801df 4929dd 4939dd 73e6 eb82 }
            // n = 7, score = 200
            //   4989d8               | dec                 eax
            //   e8????????           |                     
            //   4801df               | test                edx, edx
            //   4929dd               | je                  0x113c
            //   4939dd               | xor                 esi, esi
            //   73e6                 | dec                 eax
            //   eb82                 | lea                 edi, [esp + 0xa8]

        $sequence_5 = { e9???????? 488b442420 48c70002000000 eb33 488b442420 48c70001000000 }
            // n = 6, score = 200
            //   e9????????           |                     
            //   488b442420           | test                cl, cl
            //   48c70002000000       | setne               dl
            //   eb33                 | movups              xmm0, xmmword ptr [esi]
            //   488b442420           | dec                 eax
            //   48c70001000000       | lea                 edi, [esi + 8]

        $sequence_6 = { 488d42f0 482301 4c8b4118 45880c10 46884c0010 48ff4110 c3 }
            // n = 7, score = 200
            //   488d42f0             | dec                 eax
            //   482301               | lea                 edx, [0x99c75]
            //   4c8b4118             | movzx               esi, byte ptr [ecx + edx]
            //   45880c10             | dec                 eax
            //   46884c0010           | mov                 dword ptr [esp + 0x70], esi
            //   48ff4110             | inc                 eax
            //   c3                   | cmp                 al, dh

        $sequence_7 = { 4181fe00001100 b903000000 0f43c8 bb01001100 ba5c000000 488d05c7020000 48630c88 }
            // n = 7, score = 200
            //   4181fe00001100       | inc                 ecx
            //   b903000000           | xor                 bh, 1
            //   0f43c8               | jmp                 0x15b
            //   bb01001100           | xor                 eax, eax
            //   ba5c000000           | inc                 ebp
            //   488d05c7020000       | xor                 edi, edi
            //   48630c88             | movzx               eax, byte ptr [ebp + 0x18]

        $sequence_8 = { 48c1ef39 488d43f0 4821c5 41883c1e 42887c3510 eb25 }
            // n = 6, score = 200
            //   48c1ef39             | mov                 ecx, ebx
            //   488d43f0             | dec                 eax
            //   4821c5               | mov                 edx, edi
            //   41883c1e             | dec                 eax
            //   42887c3510           | shl                 ebx, 5
            //   eb25                 | inc                 eax

        $sequence_9 = { 4885c0 748a 8a1406 8a1c01 881c06 881401 48ffc0 }
            // n = 7, score = 200
            //   4885c0               | mov                 eax, dword ptr [esi + 0x18]
            //   748a                 | dec                 eax
            //   8a1406               | sub                 eax, edi
            //   8a1c01               | mov                 ecx, 0x18
            //   881c06               | dec                 eax
            //   881401               | cdq                 
            //   48ffc0               | dec                 eax

    condition:
        7 of them and filesize < 3532800
}
