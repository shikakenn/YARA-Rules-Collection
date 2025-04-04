rule win_lowkey_auto {

    meta:
        id = "uGUDJReApoNEEjeL7mx1I"
        fingerprint = "v1_sha256_9d3c45875e4ddd32bb18b8cb6ded5fb4838ad62f27365a87e2390b683b239917"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lowkey."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowkey"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4d8bc7 e8???????? 2bef 396e1c 7f03 8b6e20 488b4e10 }
            // n = 7, score = 100
            //   4d8bc7               | je                  0xae9
            //   e8????????           |                     
            //   2bef                 | mov                 eax, 0x65
            //   396e1c               | mov                 word ptr [esp + 0x2d], ax
            //   7f03                 | inc                 ebp
            //   8b6e20               | xor                 eax, eax
            //   488b4e10             | dec                 eax

        $sequence_1 = { 8bc2 488d15a468feff c1e803 89442448 448be0 89442440 85c0 }
            // n = 7, score = 100
            //   8bc2                 | mov                 esi, dword ptr [esp + 0x28]
            //   488d15a468feff       | dec                 eax
            //   c1e803               | mov                 edi, dword ptr [esp + 0x30]
            //   89442448             | dec                 eax
            //   448be0               | mov                 esi, dword ptr [esp + 0x68]
            //   89442440             | or                  edi, 0xffffffff
            //   85c0                 | dec                 eax

        $sequence_2 = { 750d ff15???????? 33c0 e9???????? f644242010 7438 807c244c2e }
            // n = 7, score = 100
            //   750d                 | mov                 eax, edi
            //   ff15????????         |                     
            //   33c0                 | test                eax, eax
            //   e9????????           |                     
            //   f644242010           | jne                 0xe09
            //   7438                 | dec                 eax
            //   807c244c2e           | lea                 ecx, [0x47f8b]

        $sequence_3 = { 44897c2420 4c8d4c2448 4c8d0544e7ffff 33d2 33c9 ff15???????? 4889442440 }
            // n = 7, score = 100
            //   44897c2420           | test                ebx, ebx
            //   4c8d4c2448           | inc                 ecx
            //   4c8d0544e7ffff       | mov                 edi, eax
            //   33d2                 | xor                 ecx, ecx
            //   33c9                 | dec                 eax
            //   ff15????????         |                     
            //   4889442440           | mov                 ebp, edx

        $sequence_4 = { 4489742420 33c9 ff15???????? 488bf8 e9???????? 6644896c243d }
            // n = 6, score = 100
            //   4489742420           | add                 esp, 0x20
            //   33c9                 | ret                 
            //   ff15????????         |                     
            //   488bf8               | dec                 eax
            //   e9????????           |                     
            //   6644896c243d         | mov                 ecx, dword ptr [edx + 0x50]

        $sequence_5 = { 76c4 b868000000 895c2438 4c8d8570090000 6689442435 488d542430 }
            // n = 6, score = 100
            //   76c4                 | dec                 eax
            //   b868000000           | mov                 ebx, dword ptr [edi]
            //   895c2438             | dec                 eax
            //   4c8d8570090000       | mov                 dword ptr [esp + 0x38], ebx
            //   6689442435           | jmp                 0x278
            //   488d542430           | jne                 0x286

        $sequence_6 = { 488d542450 488b4808 e8???????? eb4e b9d6000000 663bc1 }
            // n = 6, score = 100
            //   488d542450           | cmp                 ebx, eax
            //   488b4808             | jne                 0x50
            //   e8????????           |                     
            //   eb4e                 | dec                 eax
            //   b9d6000000           | lea                 edi, [ebx + 0x10]
            //   663bc1               | dec                 eax

        $sequence_7 = { 33ff e8???????? 448bc3 8d5701 }
            // n = 4, score = 100
            //   33ff                 | lea                 ecx, [esp + 0x150]
            //   e8????????           |                     
            //   448bc3               | inc                 ecx
            //   8d5701               | mov                 eax, 0x104

        $sequence_8 = { c784243001000043726561 488d8c243c010000 c784243401000074655468 c784243801000072656164 448d4274 e8???????? }
            // n = 6, score = 100
            //   c784243001000043726561     | dec    esp
            //   488d8c243c010000     | lea                 eax, [0x131f6]
            //   c784243401000074655468     | dec    eax
            //   c784243801000072656164     | mov    esi, eax
            //   448d4274             | dec                 eax
            //   e8????????           |                     

        $sequence_9 = { 4c8d0dd8d70300 418d4002 83f801 7617 498bd0 498bc0 83e23f }
            // n = 7, score = 100
            //   4c8d0dd8d70300       | dec                 eax
            //   418d4002             | lea                 edx, [esp + 0x38]
            //   83f801               | test                eax, eax
            //   7617                 | je                  0x2d1
            //   498bd0               | inc                 ebp
            //   498bc0               | xor                 ecx, ecx
            //   83e23f               | inc                 ecx

    condition:
        7 of them and filesize < 643072
}
