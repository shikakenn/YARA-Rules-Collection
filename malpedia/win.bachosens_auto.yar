rule win_bachosens_auto {

    meta:
        id = "5mExsLczPtwrB6BIbZGLfO"
        fingerprint = "v1_sha256_0a45763c922e1378fcd981d3ff76c84b7a49bb1ac5b3430f86089ebe86f29abf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bachosens."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bachosens"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 48895c2408 57 4883ec20 65488b042560000000 488bf9 }
            // n = 5, score = 200
            //   48895c2408           | or                  ecx, 0xffffffff
            //   57                   | inc                 ecx
            //   4883ec20             | sub                 edx, edx
            //   65488b042560000000     | inc    ecx
            //   488bf9               | sub                 ecx, edx

        $sequence_1 = { 75f5 33c9 41380a 7417 498bc2 660f1f840000000000 }
            // n = 6, score = 200
            //   75f5                 | mov                 dword ptr [ebx + ebp], esi
            //   33c9                 | dec                 eax
            //   41380a               | sub                 ebx, 4
            //   7417                 | mov                 dword ptr [esp + 0x30], esi
            //   498bc2               | inc                 ecx
            //   660f1f840000000000     | call    eax

        $sequence_2 = { 488d4002 66443908 75f3 418bc9 66390a }
            // n = 5, score = 200
            //   488d4002             | inc                 esp
            //   66443908             | lea                 eax, [edi + edi]
            //   75f3                 | dec                 eax
            //   418bc9               | mov                 edx, ebx
            //   66390a               | mov                 ecx, 0x28

        $sequence_3 = { 80c1e0 3ad1 7513 49ffc0 }
            // n = 4, score = 200
            //   80c1e0               | mov                 dword ptr [ebp + 0x138], ecx
            //   3ad1                 | dec                 eax
            //   7513                 | lea                 ecx, [eax + 0x314]
            //   49ffc0               | dec                 eax

        $sequence_4 = { 7416 488b1b 488b1b 488bd7 488b4b50 e8???????? }
            // n = 6, score = 200
            //   7416                 | movzx               edx, al
            //   488b1b               | inc                 ecx
            //   488b1b               | mov                 byte ptr [ebp + 4], al
            //   488bd7               | dec                 eax
            //   488b4b50             | mov                 eax, ebx
            //   e8????????           |                     

        $sequence_5 = { ffc2 488d4001 803800 75f5 33c9 41380a 7417 }
            // n = 7, score = 200
            //   ffc2                 | mov                 eax, dword ptr [ebp + 0x2c0]
            //   488d4001             | dec                 ecx
            //   803800               | mov                 edx, ebp
            //   75f5                 | dec                 ecx
            //   33c9                 | shl                 eax, 2
            //   41380a               | xor                 edx, edx
            //   7417                 | dec                 ecx

        $sequence_6 = { e8???????? 85c0 7416 488b1b 488b1b }
            // n = 5, score = 200
            //   e8????????           |                     
            //   85c0                 | lea                 edx, [ebp + 0x310]
            //   7416                 | mov                 dword ptr [ebp + 0x310], edi
            //   488b1b               | dec                 ecx
            //   488b1b               | mov                 ecx, esi

        $sequence_7 = { 33c9 41380a 7417 498bc2 660f1f840000000000 ffc1 488d4001 }
            // n = 7, score = 200
            //   33c9                 | movzx               ebx, word ptr [esi + ebp]
            //   41380a               | test                bx, bx
            //   7417                 | dec                 eax
            //   498bc2               | mov                 dword ptr [esp + 0xa0], ebp
            //   660f1f840000000000     | dec    esp
            //   ffc1                 | mov                 dword ptr [esp + 0x58], esp
            //   488d4001             | dec                 eax

        $sequence_8 = { 488bc7 ffc2 488d4001 803800 75f5 33c9 41380a }
            // n = 7, score = 200
            //   488bc7               | dec                 eax
            //   ffc2                 | mov                 eax, esi
            //   488d4001             | dec                 esp
            //   803800               | mov                 edx, dword ptr [esp + 0x240]
            //   75f5                 | sub                 edi, 1
            //   33c9                 | dec                 eax
            //   41380a               | arpl                di, ax

        $sequence_9 = { 4c03d1 458b7220 418b521c 4c03f1 458b7a24 4803d1 }
            // n = 6, score = 200
            //   4c03d1               | mov                 dword ptr [ebp + 0x50], esi
            //   458b7220             | dec                 eax
            //   418b521c             | test                eax, eax
            //   4c03f1               | je                  0xfc
            //   458b7a24             | dec                 eax
            //   4803d1               | lea                 edx, [eax + 0xa2]

    condition:
        7 of them and filesize < 643072
}
