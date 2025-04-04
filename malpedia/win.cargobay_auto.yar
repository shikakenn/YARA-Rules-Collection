rule win_cargobay_auto {

    meta:
        id = "79ZJRQLjYZ6ckBVBL4StRh"
        fingerprint = "v1_sha256_2ae360967276d2625b03685b127c94c75664c2e3f32ade543c32daba4148b1b4"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.cargobay."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cargobay"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb28 8b05???????? f7d0 488d4c2430 488d942440030000 a900004010 7507 }
            // n = 7, score = 100
            //   eb28                 | mov                 ecx, ebx
            //   8b05????????         |                     
            //   f7d0                 | cmp                 byte ptr [esp + 0x269], 0
            //   488d4c2430           | je                  0x1341
            //   488d942440030000     | mov                 al, byte ptr [esp + 0x26a]
            //   a900004010           | mov                 byte ptr [esp + 0x54], al
            //   7507                 | dec                 eax

        $sequence_1 = { eb1c 4c8d058c761100 41b905000000 4889f9 4889da e8???????? b102 }
            // n = 7, score = 100
            //   eb1c                 | dec                 eax
            //   4c8d058c761100       | add                 eax, ebx
            //   41b905000000         | dec                 eax
            //   4889f9               | lea                 ebp, [esp + 0xd0]
            //   4889da               | dec                 eax
            //   e8????????           |                     
            //   b102                 | mov                 dword ptr [ebp - 0x10], edi

        $sequence_2 = { 4d31e8 4831eb 49c1c120 49c1c420 49c1c020 4c89442428 48c1c320 }
            // n = 7, score = 100
            //   4d31e8               | mov                 eax, edi
            //   4831eb               | nop                 
            //   49c1c120             | dec                 eax
            //   49c1c420             | add                 esp, 0x158
            //   49c1c020             | pop                 ebx
            //   4c89442428           | pop                 edi
            //   48c1c320             | dec                 esp

        $sequence_3 = { e8???????? 4c8d05e9c90d00 488d7c2440 4889f9 4889f2 e8???????? 488b37 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8d05e9c90d00       | mov                 eax, 0xa8
            //   488d7c2440           | dec                 eax
            //   4889f9               | mov                 ecx, esi
            //   4889f2               | dec                 esp
            //   e8????????           |                     
            //   488b37               | mov                 edx, ebp

        $sequence_4 = { e8???????? 488bbbd8100000 488b83e0100000 486bb3e810000018 4c8d3437 4889bb60050000 48898368050000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bbbd8100000       | mov                 eax, 4
            //   488b83e0100000       | dec                 eax
            //   486bb3e810000018     | mov                 ecx, ebx
            //   4c8d3437             | inc                 ecx
            //   4889bb60050000       | mov                 edx, dword ptr [ebp + 0xf0]
            //   48898368050000       | dec                 esp

        $sequence_5 = { e9???????? c1e70c 09c7 40f6c501 0f844c010000 66662e0f1f840000000000 81ff00001100 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   c1e70c               | ja                  0x688
            //   09c7                 | dec                 eax
            //   40f6c501             | add                 ecx, eax
            //   0f844c010000         | dec                 eax
            //   66662e0f1f840000000000     | mov    eax, ecx
            //   81ff00001100         | dec                 eax

        $sequence_6 = { 4901c0 4c89e1 4889c2 e8???????? 4d8b7c2410 408a7e40 0f104641 }
            // n = 7, score = 100
            //   4901c0               | lea                 ecx, [esi + 1]
            //   4c89e1               | dec                 eax
            //   4889c2               | mov                 edx, eax
            //   e8????????           |                     
            //   4d8b7c2410           | dec                 eax
            //   408a7e40             | shr                 edx, 8
            //   0f104641             | and                 edx, 0xffffff00

        $sequence_7 = { e8???????? 803e00 0f84c9000000 488b442428 eba2 807b0800 0f84d1000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   803e00               | dec                 eax
            //   0f84c9000000         | lea                 edx, [0xcecca]
            //   488b442428           | dec                 eax
            //   eba2                 | lea                 esi, [esp + 0x290]
            //   807b0800             | inc                 ecx
            //   0f84d1000000         | mov                 eax, 8

        $sequence_8 = { f04c0fb129 0f84ec010000 4989c6 488b4508 4885c0 0f84d9feffff f048ff08 }
            // n = 7, score = 100
            //   f04c0fb129           | inc                 ecx
            //   0f84ec010000         | movups              xmmword ptr [edi + 1], xmm0
            //   4989c6               | inc                 ecx
            //   488b4508             | mov                 byte ptr [edi], al
            //   4885c0               | dec                 eax
            //   0f84d9feffff         | mov                 edx, dword ptr [esp + 0x98]
            //   f048ff08             | jmp                 0x1fc4

        $sequence_9 = { eb0c 488d542440 48c70205000000 4889f9 e8???????? e9???????? 4c8d05fb400e00 }
            // n = 7, score = 100
            //   eb0c                 | jne                 0x1ded
            //   488d542440           | cmp                 bp, 0xa
            //   48c70205000000       | jne                 0x1d7b
            //   4889f9               | dec                 eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   4c8d05fb400e00       | mov                 eax, dword ptr [esp + 0xe8]

    condition:
        7 of them and filesize < 3432448
}
