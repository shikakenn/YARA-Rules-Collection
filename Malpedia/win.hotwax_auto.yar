rule win_hotwax_auto {

    meta:
        id = "5Ak8HjT93WqO8hORwZemnF"
        fingerprint = "v1_sha256_fe64f11364e8e368736d318c239a3692d708ee4c24b150c29655e2d18f1cd86c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hotwax."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hotwax"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4883ec20 488bd9 488d0de0b60000 483bd9 }
            // n = 4, score = 100
            //   4883ec20             | dec                 esp
            //   488bd9               | mov                 dword ptr [ebp + 4], ebx
            //   488d0de0b60000       | rep stosd           dword ptr es:[edi], eax
            //   483bd9               | dec                 eax

        $sequence_1 = { 33c9 33d2 41ff5500 448bd8 85c0 0f85ef020000 8b4500 }
            // n = 7, score = 100
            //   33c9                 | xor                 eax, eax
            //   33d2                 | dec                 eax
            //   41ff5500             | mov                 ecx, eax
            //   448bd8               | test                eax, eax
            //   85c0                 | jne                 0x28f
            //   0f85ef020000         | dec                 eax
            //   8b4500               | arpl                word ptr [ebx], cx

        $sequence_2 = { 8945a0 496344243c 33d2 428b4c2050 41b900300000 c744242040000000 }
            // n = 6, score = 100
            //   8945a0               | mov                 edi, dword ptr [edi + 0x88]
            //   496344243c           | dec                 eax
            //   33d2                 | add                 edi, ebp
            //   428b4c2050           | je                  0x662
            //   41b900300000         | inc                 esp
            //   c744242040000000     | cmp                 dword ptr [edi + 0x14], esi

        $sequence_3 = { 4885c0 7467 33d2 488bc8 }
            // n = 4, score = 100
            //   4885c0               | mov                 ecx, esi
            //   7467                 | inc                 esp
            //   33d2                 | lea                 eax, [edx + 1]
            //   488bc8               | dec                 esp

        $sequence_4 = { 85c0 0f8596000000 397ddc 0f848d000000 4c8d05247bffff }
            // n = 5, score = 100
            //   85c0                 | dec                 eax
            //   0f8596000000         | lea                 edx, [0xcf5a]
            //   397ddc               | dec                 eax
            //   0f848d000000         | mov                 ecx, ebx
            //   4c8d05247bffff       | dec                 eax

        $sequence_5 = { 4885c8 7507 8b0b 4803ca eb11 483bca 7245 }
            // n = 7, score = 100
            //   4885c8               | lea                 edx, [0xd79f]
            //   7507                 | dec                 eax
            //   8b0b                 | mov                 ecx, ebx
            //   4803ca               | dec                 eax
            //   eb11                 | lea                 edx, [0xd778]
            //   483bca               | dec                 eax
            //   7245                 | mov                 ecx, ebx

        $sequence_6 = { c6850205000000 c785e004000043726561 c785e404000074655468 c785e804000072656164 c685ec04000000 }
            // n = 5, score = 100
            //   c6850205000000       | dec                 eax
            //   c785e004000043726561     | sub    esp, 0x20
            //   c785e404000074655468     | dec    eax
            //   c785e804000072656164     | lea    ebx, [0x738f]
            //   c685ec04000000       | dec                 eax

        $sequence_7 = { 7343 8b471c 458b4d44 4d8b4530 4803c5 }
            // n = 5, score = 100
            //   7343                 | mov                 ebx, eax
            //   8b471c               | jne                 0x6b8
            //   458b4d44             | dec                 eax
            //   4d8b4530             | lea                 edx, [0xd31d]
            //   4803c5               | dec                 eax

        $sequence_8 = { ff15???????? 488d4c2468 33d2 41b868050000 83cbff }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488d4c2468           | dec                 eax
            //   33d2                 | mov                 ecx, ebx
            //   41b868050000         | dec                 eax
            //   83cbff               | mov                 ecx, ebx

        $sequence_9 = { 4c8d0dac7fffff 4c8bd8 4b8b84f9a04b0100 4c895c3040 4b8b84f9a04b0100 498bd6 }
            // n = 6, score = 100
            //   4c8d0dac7fffff       | lea                 esp, [0x8385]
            //   4c8bd8               | jmp                 0x1467
            //   4b8b84f9a04b0100     | dec                 eax
            //   4c895c3040           | mov                 ecx, ebx
            //   4b8b84f9a04b0100     | dec                 eax
            //   498bd6               | mov                 eax, ebx

    condition:
        7 of them and filesize < 198656
}
