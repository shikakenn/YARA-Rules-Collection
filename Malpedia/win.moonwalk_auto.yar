rule win_moonwalk_auto {

    meta:
        id = "39mwqlHlPh3nFMNRL6sqNA"
        fingerprint = "v1_sha256_1c19a679d272620c40c7a55b8a8c2eabaee5ff1d6dffe1b79863d345d92546d6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.moonwalk."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moonwalk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 660f1f840000000000 488b03 483301 0f85ce000000 4883c308 4883c108 493bdf }
            // n = 7, score = 100
            //   660f1f840000000000     | dec    eax
            //   488b03               | arpl                dx, ax
            //   483301               | mov                 byte ptr [ebp + eax - 0x54], cl
            //   0f85ce000000         | jne                 0x543
            //   4883c308             | mov                 eax, dword ptr [esp + 0x80]
            //   4883c108             | mov                 dword ptr [edi + 0x303c4], eax
            //   493bdf               | dec                 eax

        $sequence_1 = { c3 4038ac24a0000000 0f854dffffff 488b4330 8b4804 398c24a4000000 }
            // n = 6, score = 100
            //   c3                   | dec                 ecx
            //   4038ac24a0000000     | lea                 ecx, [esi + ebx]
            //   0f854dffffff         | inc                 ecx
            //   488b4330             | add                 dword ptr [edx + 0x4018], ebx
            //   8b4804               | dec                 eax
            //   398c24a4000000       | lea                 esi, [ecx - 0xb]

        $sequence_2 = { 0fb6d1 418bca c1e908 458bc2 49c1e818 428b9c8030260100 339c90303a0100 }
            // n = 7, score = 100
            //   0fb6d1               | shr                 eax, 8
            //   418bca               | movzx               edx, al
            //   c1e908               | inc                 ecx
            //   458bc2               | mov                 eax, esi
            //   49c1e818             | inc                 ebp
            //   428b9c8030260100     | xor                 ebx, dword ptr [esp + ecx*4 + 0xfa00]
            //   339c90303a0100       | mov                 edx, ebp

        $sequence_3 = { 7541 488d8538010000 89bd38010000 33d2 4889442420 488b05???????? }
            // n = 6, score = 100
            //   7541                 | xor                 edx, edx
            //   488d8538010000       | xor                 byte ptr [edi + 0x20], al
            //   89bd38010000         | mov                 eax, 0x21
            //   33d2                 | dec                 ecx
            //   4889442420           | div                 eax
            //   488b05????????       |                     

        $sequence_4 = { 488b4008 488905???????? 488d4db0 48894548 e8???????? 85c0 0f8898010000 }
            // n = 7, score = 100
            //   488b4008             | mov                 dword ptr [esp + 0x20], eax
            //   488905????????       |                     
            //   488d4db0             | inc                 ecx
            //   48894548             | call                dword ptr [edx + 0x10]
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   0f8898010000         | lea                 ecx, [edi + 0x303c4]

        $sequence_5 = { 304304 488b442448 0fb60408 304305 488b442450 0fb60408 304306 }
            // n = 7, score = 100
            //   304304               | dec                 eax
            //   488b442448           | mov                 edi, dword ptr [edi]
            //   0fb60408             | dec                 eax
            //   304305               | cmp                 edi, esi
            //   488b442450           | jne                 0x1a8a
            //   0fb60408             | inc                 ebp
            //   304306               | xor                 ebp, ebp

        $sequence_6 = { 0fb60408 30430f 488b45a0 0fb60408 304310 488b45a8 0fb60408 }
            // n = 7, score = 100
            //   0fb60408             | mov                 ecx, edi
            //   30430f               | mov                 dword ptr [esp + 0x88], edx
            //   488b45a0             | mov                 edx, 0x36
            //   0fb60408             | inc                 esp
            //   304310               | mov                 eax, edx
            //   488b45a8             | inc                 ebp
            //   0fb60408             | mov                 ecx, ebx

        $sequence_7 = { 488b4858 488d4580 48894578 48894d50 4c896d70 48899d80000000 }
            // n = 6, score = 100
            //   488b4858             | dec                 eax
            //   488d4580             | shl                 ecx, 4
            //   48894578             | mov                 eax, 0x14
            //   48894d50             | inc                 edx
            //   4c896d70             | movzx               ecx, byte ptr [edx + ecx]
            //   48899d80000000       | xor                 edx, edx

        $sequence_8 = { 0fb603 48ffc3 4403c0 493bd9 0f835a020000 3dff000000 74e7 }
            // n = 7, score = 100
            //   0fb603               | inc                 esp
            //   48ffc3               | mov                 edi, dword ptr [edx + 0x48]
            //   4403c0               | nop                 word ptr [eax + eax]
            //   493bd9               | mov                 edx, ebx
            //   0f835a020000         | mov                 eax, ebx
            //   3dff000000           | sar                 eax, 0x1a
            //   74e7                 | inc                 esp

        $sequence_9 = { c3 48895c2408 4889742410 57 4881ec90000000 488b4210 488bd9 }
            // n = 7, score = 100
            //   c3                   | dec                 eax
            //   48895c2408           | mov                 edi, eax
            //   4889742410           | dec                 eax
            //   57                   | test                eax, eax
            //   4881ec90000000       | jne                 0xa91
            //   488b4210             | lea                 eax, [edi + 0xa]
            //   488bd9               | dec                 eax

    condition:
        7 of them and filesize < 179200
}
