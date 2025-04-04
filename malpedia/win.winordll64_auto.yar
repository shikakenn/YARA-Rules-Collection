rule win_winordll64_auto {

    meta:
        id = "5LAX9PBvdhKuBtIj3ztp7C"
        fingerprint = "v1_sha256_a4a004425dba88268c2d3d715c259f2863978c42cd46c83d869be58ecc44a5d1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.winordll64."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.winordll64"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33ff e9???????? 488b0b 4c8d442440 488d542450 ff5318 85c0 }
            // n = 7, score = 100
            //   33ff                 | mov                 ecx, dword ptr [esp]
            //   e9????????           |                     
            //   488b0b               | inc                 edi
            //   4c8d442440           | lea                 eax, [eax + eax + 2]
            //   488d542450           | inc                 ecx
            //   ff5318               | call                dword ptr [esp + 8]
            //   85c0                 | jmp                 0x20

        $sequence_1 = { 4533c0 8bd3 e8???????? 8bf0 85c0 }
            // n = 5, score = 100
            //   4533c0               | sub                 ecx, eax
            //   8bd3                 | mov                 eax, 0x20
            //   e8????????           |                     
            //   8bf0                 | dec                 eax
            //   85c0                 | sub                 ecx, edx

        $sequence_2 = { 488d4158 41b806000000 488d1528120100 483950f0 740b 488b10 4885d2 }
            // n = 7, score = 100
            //   488d4158             | mov                 edx, eax
            //   41b806000000         | dec                 eax
            //   488d1528120100       | mov                 ecx, edi
            //   483950f0             | dec                 esp
            //   740b                 | mov                 ebx, ebx
            //   488b10               | inc                 ecx
            //   4885d2               | lea                 ecx, [ebx + 6]

        $sequence_3 = { ba11000000 41ff5720 33d2 448be2 4889542440 8bda 4889542448 }
            // n = 7, score = 100
            //   ba11000000           | sub                 esp, 0x20
            //   41ff5720             | dec                 eax
            //   33d2                 | lea                 ebx, [ecx + 8]
            //   448be2               | dec                 eax
            //   4889542440           | mov                 ecx, ebx
            //   8bda                 | pop                 edi
            //   4889542448           | ret                 

        $sequence_4 = { 486bdb1c 4803df 48895e10 4d6be41c 4c03e7 4c896608 }
            // n = 6, score = 100
            //   486bdb1c             | mov                 esp, eax
            //   4803df               | inc                 ecx
            //   48895e10             | mov                 eax, esp
            //   4d6be41c             | mov                 ecx, esi
            //   4c03e7               | shr                 eax, cl
            //   4c896608             | test                al, 1

        $sequence_5 = { 4803d7 4c897c2420 ff15???????? 037578 33c9 e8???????? 483bc3 }
            // n = 7, score = 100
            //   4803d7               | mov                 byte ptr [ecx + ecx], al
            //   4c897c2420           | lea                 eax, [edx + edx + 2]
            //   ff15????????         |                     
            //   037578               | dec                 eax
            //   33c9                 | arpl                ax, dx
            //   e8????????           |                     
            //   483bc3               | test                eax, eax

        $sequence_6 = { ff15???????? e9???????? 488d15c61c0100 488d4dbc }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   e9????????           |                     
            //   488d15c61c0100       | rol                 esi, 8
            //   488d4dbc             | jne                 0x10b2

        $sequence_7 = { 498bcc ff15???????? 48635538 488b4dd0 ff5730 4c635d38 4d03eb }
            // n = 7, score = 100
            //   498bcc               | dec                 eax
            //   ff15????????         |                     
            //   48635538             | mov                 dword ptr [esp + 0x20], eax
            //   488b4dd0             | inc                 ebp
            //   ff5730               | test                ebx, ebx
            //   4c635d38             | je                  0x11bd
            //   4d03eb               | mov                 ecx, eax

        $sequence_8 = { eb06 ffc2 4883c002 66443930 75f4 488d742470 48837d8808 }
            // n = 7, score = 100
            //   eb06                 | dec                 eax
            //   ffc2                 | mov                 ecx, dword ptr [esp + 0x50]
            //   4883c002             | mov                 edx, esi
            //   66443930             | je                  0x738
            //   75f4                 | dec                 eax
            //   488d742470           | lea                 edx, [0x11821]
            //   48837d8808           | dec                 eax

        $sequence_9 = { 488bc1 48ffc0 ffc3 803800 75f6 4533c9 4533c0 }
            // n = 7, score = 100
            //   488bc1               | shl                 edx, 4
            //   48ffc0               | mov                 ebp, 4
            //   ffc3                 | xor                 edx, edx
            //   803800               | inc                 ecx
            //   75f6                 | mov                 esi, 0x738
            //   4533c9               | mov                 cl, byte ptr [esp + edx + 0x70]
            //   4533c0               | mov                 byte ptr [edx + esi], cl

    condition:
        7 of them and filesize < 278528
}
