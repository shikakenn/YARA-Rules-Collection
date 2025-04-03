rule win_dusttrap_auto {

    meta:
        id = "4CozkXr9Uu4JNscG1gL7hB"
        fingerprint = "v1_sha256_f4b4f45042cbce5a99225f86a255feaeb3d8c391ba31ee586efa9930ba8ea747"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dusttrap."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dusttrap"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7507 b904000000 eb1f 4181f800000060 7507 b920000000 eb0f }
            // n = 7, score = 100
            //   7507                 | push                edi
            //   b904000000           | dec                 eax
            //   eb1f                 | sub                 esp, 0x80
            //   4181f800000060       | dec                 eax
            //   7507                 | mov                 dword ptr [eax + 0x18], edi
            //   b920000000           | inc                 ebp
            //   eb0f                 | xor                 esp, esp

        $sequence_1 = { 488d15b1eb0000 33c9 ff15???????? 488b4c2448 85c0 7429 }
            // n = 6, score = 100
            //   488d15b1eb0000       | mov                 dword ptr [esp + 0x410], ebx
            //   33c9                 | dec                 eax
            //   ff15????????         |                     
            //   488b4c2448           | lea                 ebx, [0x2a96a]
            //   85c0                 | mov                 edx, dword ptr [edi]
            //   7429                 | dec                 eax

        $sequence_2 = { 33df 8bfb 41895f50 4133f9 448bcf }
            // n = 5, score = 100
            //   33df                 | dec                 esp
            //   8bfb                 | lea                 ebx, [0x23bfc]
            //   41895f50             | dec                 ecx
            //   4133f9               | arpl                ax, ax
            //   448bcf               | dec                 eax

        $sequence_3 = { 448d4205 4889442420 e8???????? 85c0 498bcd 480f498c24b8000000 }
            // n = 6, score = 100
            //   448d4205             | inc                 edx
            //   4889442420           | movzx               ecx, byte ptr [eax + esi]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   498bcd               | shr                 eax, 0x18
            //   480f498c24b8000000     | mov    dword ptr [esi - 0x12], ebx

        $sequence_4 = { ff90e8000000 488bd8 4885c0 754c 89442430 448d4b30 488d442430 }
            // n = 7, score = 100
            //   ff90e8000000         | add                 esp, 0x6a0
            //   488bd8               | inc                 ecx
            //   4885c0               | pop                 edi
            //   754c                 | inc                 ecx
            //   89442430             | pop                 ebp
            //   448d4b30             | pop                 edi
            //   488d442430           | inc                 ecx

        $sequence_5 = { 488bc2 448b0d???????? 90 443908 7507 6644394004 }
            // n = 6, score = 100
            //   488bc2               | dec                 esp
            //   448b0d????????       |                     
            //   90                   | mov                 edi, dword ptr [esp + 0x90]
            //   443908               | add                 esi, 4
            //   7507                 | dec                 eax
            //   6644394004           | mov                 dword ptr [esp + 0x90], eax

        $sequence_6 = { 48896c2450 0f57c0 c744244800040000 4d8bcf 488b4958 4c89742440 448d4209 }
            // n = 7, score = 100
            //   48896c2450           | mov                 dword ptr [esp + 0x48], 8
            //   0f57c0               | inc                 esp
            //   c744244800040000     | lea                 eax, [ebx + 9]
            //   4d8bcf               | dec                 eax
            //   488b4958             | mov                 dword ptr [esp + 0x40], eax
            //   4c89742440           | dec                 eax
            //   448d4209             | lea                 eax, [ebp + 0x10]

        $sequence_7 = { 4055 57 488d6c24b1 4881ecf8000000 488b0d???????? 4885c9 }
            // n = 6, score = 100
            //   4055                 | dec                 eax
            //   57                   | mov                 ecx, dword ptr [ecx + 0xf8]
            //   488d6c24b1           | inc                 ebp
            //   4881ecf8000000       | xor                 esp, esp
            //   488b0d????????       |                     
            //   4885c9               | dec                 eax

        $sequence_8 = { 48ffc1 33c2 69d093010001 493bc8 72ed 488d0dfe060200 660f1f440000 }
            // n = 7, score = 100
            //   48ffc1               | add                 ebp, esi
            //   33c2                 | dec                 eax
            //   69d093010001         | mov                 dword ptr [esp + 0x68], esi
            //   493bc8               | dec                 eax
            //   72ed                 | mov                 dword ptr [esp + 0x60], edi
            //   488d0dfe060200       | inc                 esp
            //   660f1f440000         | mov                 eax, dword ptr [ebp + 0x54]

        $sequence_9 = { 4c89642430 4c89642428 4c89642420 0f1145b0 e8???????? 3d03010000 7534 }
            // n = 7, score = 100
            //   4c89642430           | dec                 eax
            //   4c89642428           | test                edi, edi
            //   4c89642420           | jne                 0x18db
            //   0f1145b0             | dec                 ebp
            //   e8????????           |                     
            //   3d03010000           | mov                 eax, ebp
            //   7534                 | jmp                 0x18f0

    condition:
        7 of them and filesize < 421888
}
