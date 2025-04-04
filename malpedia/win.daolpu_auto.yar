rule win_daolpu_auto {

    meta:
        id = "4G4uEmwmhKZRyLWW7M0YLG"
        fingerprint = "v1_sha256_75ecbdb2c7e8916d3ac65192115d743be9db42508dfb2c41a685a14b393ff7b1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.daolpu."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daolpu"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb30 e9???????? 488d4c2440 e8???????? 48c7842428010000ffffffff 488d8c2490000000 e8???????? }
            // n = 7, score = 100
            //   eb30                 | dec                 ecx
            //   e9????????           |                     
            //   488d4c2440           | mov                 ecx, dword ptr [edi + 0x18]
            //   e8????????           |                     
            //   48c7842428010000ffffffff     | dec    ecx
            //   488d8c2490000000     | sub                 ecx, ecx
            //   e8????????           |                     

        $sequence_1 = { 75b0 0f28442430 488b5d97 0f1103 488d4dcf e8???????? 4c8b45ef }
            // n = 7, score = 100
            //   75b0                 | dec                 esp
            //   0f28442430           | mov                 eax, dword ptr [esp + 0xa8]
            //   488b5d97             | dec                 eax
            //   0f1103               | mov                 dword ptr [esp + 0xb8], ebx
            //   488d4dcf             | xorps               xmm0, xmm0
            //   e8????????           |                     
            //   4c8b45ef             | movups              xmmword ptr [esp + 0xc0], xmm0

        $sequence_2 = { ebd9 488b442428 488b00 4889442430 49ba7030525e472705d3 488b442430 ff15???????? }
            // n = 7, score = 100
            //   ebd9                 | mov                 eax, 0x8130
            //   488b442428           | dec                 eax
            //   488b00               | sub                 esp, eax
            //   4889442430           | dec                 esp
            //   49ba7030525e472705d3     | mov    dword ptr [esp + 0x18], eax
            //   488b442430           | dec                 eax
            //   ff15????????         |                     

        $sequence_3 = { 7612 49ffc0 488b542448 488d4c2440 e8???????? 4c897c2458 48c74424600f000000 }
            // n = 7, score = 100
            //   7612                 | mov                 eax, edi
            //   49ffc0               | mov                 edx, 4
            //   488b542448           | inc                 ecx
            //   488d4c2440           | cmp                 ecx, -1
            //   e8????????           |                     
            //   4c897c2458           | dec                 eax
            //   48c74424600f000000     | mov    eax, dword ptr [ecx]

        $sequence_4 = { 7460 498bff 4c8d2dbe660900 498bc7 4a8b5c2808 483beb 7233 }
            // n = 7, score = 100
            //   7460                 | dec                 eax
            //   498bff               | mov                 ecx, eax
            //   4c8d2dbe660900       | dec                 eax
            //   498bc7               | cwde                
            //   4a8b5c2808           | dec                 eax
            //   483beb               | mov                 dword ptr [esp + 8], ecx
            //   7233                 | dec                 eax

        $sequence_5 = { 66c74424380100 488b45b0 48634804 488b4c0df8 48894c2470 4885c9 0f94442478 }
            // n = 7, score = 100
            //   66c74424380100       | mov                 eax, 0xc8
            //   488b45b0             | dec                 eax
            //   48634804             | lea                 edx, [0x54df5]
            //   488b4c0df8           | mov                 ecx, 2
            //   48894c2470           | cmp                 eax, 1
            //   4885c9               | dec                 eax
            //   0f94442478           | mov                 dword ptr [esp + 0x20], eax

        $sequence_6 = { 48896c2450 4c896c2448 4c8d2d4ea2f9ff 4c89742440 41be08000000 48899c2480000000 6666660f1f840000000000 }
            // n = 7, score = 100
            //   48896c2450           | lea                 edx, [0x61d7d]
            //   4c896c2448           | dec                 eax
            //   4c8d2d4ea2f9ff       | lea                 ecx, [0x61db6]
            //   4c89742440           | mov                 dword ptr [eax], 0x16
            //   41be08000000         | dec                 eax
            //   48899c2480000000     | mov                 dword ptr [esp + 0x20], 0
            //   6666660f1f840000000000     | inc    ecx

        $sequence_7 = { 7508 4883eb01 75eb eb1e 4885db 7419 0f1f4000 }
            // n = 7, score = 100
            //   7508                 | xor                 al, al
            //   4883eb01             | dec                 eax
            //   75eb                 | mov                 dword ptr [esp + 0x10], edx
            //   eb1e                 | dec                 eax
            //   4885db               | mov                 dword ptr [esp + 8], ecx
            //   7419                 | dec                 eax
            //   0f1f4000             | sub                 esp, 0x38

        $sequence_8 = { 488b17 488d4203 483bc1 7709 4a8d0402 e9???????? 397320 }
            // n = 7, score = 100
            //   488b17               | dec                 eax
            //   488d4203             | arpl                word ptr [eax], ax
            //   483bc1               | dec                 eax
            //   7709                 | cmp                 eax, dword ptr [esp + 0x40]
            //   4a8d0402             | jae                 0x3e5
            //   e9????????           |                     
            //   397320               | dec                 eax

        $sequence_9 = { 488d8c24a8000000 e8???????? 83781000 740a b8ffff0000 e9???????? 488d8c24a8000000 }
            // n = 7, score = 100
            //   488d8c24a8000000     | dec                 eax
            //   e8????????           |                     
            //   83781000             | lea                 edx, [0x128ada]
            //   740a                 | inc                 ecx
            //   b8ffff0000           | lea                 ecx, [ecx + 2]
            //   e9????????           |                     
            //   488d8c24a8000000     | cmp                 eax, 1

    condition:
        7 of them and filesize < 2877440
}
