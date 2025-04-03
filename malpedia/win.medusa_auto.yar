rule win_medusa_auto {

    meta:
        id = "7GfTSETsZ1NoLbCW6fFLPo"
        fingerprint = "v1_sha256_b88f5d47ff30b39fc78331a46c037d026177b73d253964f40555a9ce1312bb08"
        version = "1"
        date = "2023-12-06"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.medusa."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusa"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 680049ff69 004aff 6a00 4b ff6b00 4c ff6c004d }
            // n = 7, score = 100
            //   680049ff69           | push                0x69ff4900
            //   004aff               | add                 byte ptr [edx - 1], cl
            //   6a00                 | push                0
            //   4b                   | dec                 ebx
            //   ff6b00               | ljmp                [ebx]
            //   4c                   | dec                 esp
            //   ff6c004d             | ljmp                [eax + eax + 0x4d]

        $sequence_1 = { 1a03 69c421f3ef6a 2048b3 a5 }
            // n = 4, score = 100
            //   1a03                 | sbb                 al, byte ptr [ebx]
            //   69c421f3ef6a         | imul                eax, esp, 0x6aeff321
            //   2048b3               | and                 byte ptr [eax - 0x4d], cl
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_2 = { 52 ff7200 53 ff7300 54 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   ff7200               | push                dword ptr [edx]
            //   53                   | push                ebx
            //   ff7300               | push                dword ptr [ebx]
            //   54                   | push                esp

        $sequence_3 = { 317f52 56 5c ab 92 6f 0c48 }
            // n = 7, score = 100
            //   317f52               | xor                 dword ptr [edi + 0x52], edi
            //   56                   | push                esi
            //   5c                   | pop                 esp
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   92                   | xchg                eax, edx
            //   6f                   | outsd               dx, dword ptr [esi]
            //   0c48                 | or                  al, 0x48

        $sequence_4 = { 9e 45 334a54 98 56 39ec 51 }
            // n = 7, score = 100
            //   9e                   | sahf                
            //   45                   | inc                 ebp
            //   334a54               | xor                 ecx, dword ptr [edx + 0x54]
            //   98                   | cwde                
            //   56                   | push                esi
            //   39ec                 | cmp                 esp, ebp
            //   51                   | push                ecx

        $sequence_5 = { 9f c48b2addd977 7612 a5 ba3c533f71 }
            // n = 5, score = 100
            //   9f                   | lahf                
            //   c48b2addd977         | les                 ecx, ptr [ebx + 0x77d9dd2a]
            //   7612                 | jbe                 0x14
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   ba3c533f71           | mov                 edx, 0x713f533c

        $sequence_6 = { e60e 6c 7bbc 45 }
            // n = 4, score = 100
            //   e60e                 | out                 0xe, al
            //   6c                   | insb                byte ptr es:[edi], dx
            //   7bbc                 | jnp                 0xffffffbe
            //   45                   | inc                 ebp

        $sequence_7 = { 54 ff740055 ff7500 56 }
            // n = 4, score = 100
            //   54                   | push                esp
            //   ff740055             | push                dword ptr [eax + eax + 0x55]
            //   ff7500               | push                dword ptr [ebp]
            //   56                   | push                esi

        $sequence_8 = { 99 5f 68066e570a 4f bfdb4a7adc }
            // n = 5, score = 100
            //   99                   | cdq                 
            //   5f                   | pop                 edi
            //   68066e570a           | push                0xa576e06
            //   4f                   | dec                 edi
            //   bfdb4a7adc           | mov                 edi, 0xdc7a4adb

        $sequence_9 = { 1ddf859f31 e476 0c48 ce 74ec 1b826a013061 }
            // n = 6, score = 100
            //   1ddf859f31           | sbb                 eax, 0x319f85df
            //   e476                 | in                  al, 0x76
            //   0c48                 | or                  al, 0x48
            //   ce                   | into                
            //   74ec                 | je                  0xffffffee
            //   1b826a013061         | sbb                 eax, dword ptr [edx + 0x6130016a]

        $sequence_10 = { 2a18 ae 085ffb cf }
            // n = 4, score = 100
            //   2a18                 | sub                 bl, byte ptr [eax]
            //   ae                   | scasb               al, byte ptr es:[edi]
            //   085ffb               | or                  byte ptr [edi - 5], bl
            //   cf                   | iretd               

        $sequence_11 = { b5f9 43 324dd5 1ddf859f31 e476 0c48 }
            // n = 6, score = 100
            //   b5f9                 | mov                 ch, 0xf9
            //   43                   | inc                 ebx
            //   324dd5               | xor                 cl, byte ptr [ebp - 0x2b]
            //   1ddf859f31           | sbb                 eax, 0x319f85df
            //   e476                 | in                  al, 0x76
            //   0c48                 | or                  al, 0x48

        $sequence_12 = { 5f e1fb 1cc9 3ca5 2c8e a1???????? d528 }
            // n = 7, score = 100
            //   5f                   | pop                 edi
            //   e1fb                 | loope               0xfffffffd
            //   1cc9                 | sbb                 al, 0xc9
            //   3ca5                 | cmp                 al, 0xa5
            //   2c8e                 | sub                 al, 0x8e
            //   a1????????           |                     
            //   d528                 | aad                 0x28

        $sequence_13 = { b051 9f 4a d7 b9533e507c }
            // n = 5, score = 100
            //   b051                 | mov                 al, 0x51
            //   9f                   | lahf                
            //   4a                   | dec                 edx
            //   d7                   | xlatb               
            //   b9533e507c           | mov                 ecx, 0x7c503e53

        $sequence_14 = { 6c 6f aa 97 691c85470859bab566c1a5 }
            // n = 5, score = 100
            //   6c                   | insb                byte ptr es:[edi], dx
            //   6f                   | outsd               dx, dword ptr [esi]
            //   aa                   | stosb               byte ptr es:[edi], al
            //   97                   | xchg                eax, edi
            //   691c85470859bab566c1a5     | imul    ebx, dword ptr [eax*4 - 0x45a6f7b9], 0xa5c166b5

        $sequence_15 = { 813bf80937dc 8b4c6386 8608 5f }
            // n = 4, score = 100
            //   813bf80937dc         | cmp                 dword ptr [ebx], 0xdc3709f8
            //   8b4c6386             | mov                 ecx, dword ptr [ebx - 0x7a]
            //   8608                 | xchg                byte ptr [eax], cl
            //   5f                   | pop                 edi

    condition:
        7 of them and filesize < 1720320
}
