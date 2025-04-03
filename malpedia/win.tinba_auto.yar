rule win_tinba_auto {

    meta:
        id = "RLBHftR94rX4RLQ65gPCR"
        fingerprint = "v1_sha256_12776db9a2ca5e4e1bee242492b810213115a7f9fd4fce223ca3d2d59532f5e7"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.tinba."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinba"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b7508 ad 50 56 }
            // n = 4, score = 1100
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   ad                   | lodsd               eax, dword ptr [esi]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_1 = { 8b4510 aa 8b450c ab }
            // n = 4, score = 1100
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   ab                   | stosd               dword ptr es:[edi], eax

        $sequence_2 = { 6a00 6a00 ff750c 6a00 6a00 ff7508 }
            // n = 6, score = 1000
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff7508               | push                dword ptr [ebp + 8]

        $sequence_3 = { 8a241f 88240f 88041f 41 }
            // n = 4, score = 1000
            //   8a241f               | mov                 ah, byte ptr [edi + ebx]
            //   88240f               | mov                 byte ptr [edi + ecx], ah
            //   88041f               | mov                 byte ptr [edi + ebx], al
            //   41                   | inc                 ecx

        $sequence_4 = { 0f84f2000000 49 89cf 49 }
            // n = 4, score = 900
            //   0f84f2000000         | je                  0xf8
            //   49                   | dec                 ecx
            //   89cf                 | mov                 edi, ecx
            //   49                   | dec                 ecx

        $sequence_5 = { 8b4004 8b08 8b450c 8908 }
            // n = 4, score = 900
            //   8b4004               | mov                 eax, dword ptr [eax + 4]
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8908                 | mov                 dword ptr [eax], ecx

        $sequence_6 = { 7506 8b4108 8b4014 85c0 7403 }
            // n = 5, score = 900
            //   7506                 | jne                 8
            //   8b4108               | mov                 eax, dword ptr [ecx + 8]
            //   8b4014               | mov                 eax, dword ptr [eax + 0x14]
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5

        $sequence_7 = { b8436f6f6b ab b869653a20 ab 037df8 4f }
            // n = 6, score = 900
            //   b8436f6f6b           | mov                 eax, 0x6b6f6f43
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   b869653a20           | mov                 eax, 0x203a6569
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   037df8               | add                 edi, dword ptr [ebp - 8]
            //   4f                   | dec                 edi

        $sequence_8 = { 48 89ce 49 89c8 31c9 }
            // n = 5, score = 900
            //   48                   | dec                 eax
            //   89ce                 | mov                 esi, ecx
            //   49                   | dec                 ecx
            //   89c8                 | mov                 eax, ecx
            //   31c9                 | xor                 ecx, ecx

        $sequence_9 = { 85c0 7403 b073 aa b83a2f2f00 ab 4f }
            // n = 7, score = 900
            //   85c0                 | test                eax, eax
            //   7403                 | je                  5
            //   b073                 | mov                 al, 0x73
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b83a2f2f00           | mov                 eax, 0x2f2f3a
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   4f                   | dec                 edi

        $sequence_10 = { 83ef0e 85c0 741b 66b80d0a 66ab }
            // n = 5, score = 900
            //   83ef0e               | sub                 edi, 0xe
            //   85c0                 | test                eax, eax
            //   741b                 | je                  0x1d
            //   66b80d0a             | mov                 ax, 0xa0d
            //   66ab                 | stosw               word ptr es:[edi], ax

        $sequence_11 = { c22c00 55 89e5 53 e8???????? }
            // n = 5, score = 900
            //   c22c00               | ret                 0x2c
            //   55                   | push                ebp
            //   89e5                 | mov                 ebp, esp
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_12 = { 66894208 66894a0a ac 88c1 80e1fe 80f9c4 }
            // n = 6, score = 900
            //   66894208             | mov                 word ptr [edx + 8], ax
            //   66894a0a             | mov                 word ptr [edx + 0xa], cx
            //   ac                   | lodsb               al, byte ptr [esi]
            //   88c1                 | mov                 cl, al
            //   80e1fe               | and                 cl, 0xfe
            //   80f9c4               | cmp                 cl, 0xc4

    condition:
        7 of them and filesize < 57344
}
