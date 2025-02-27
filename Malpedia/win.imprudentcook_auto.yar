rule win_imprudentcook_auto {

    meta:
        id = "34gqSU521gbQjW5wtmWhKo"
        fingerprint = "v1_sha256_7d085ab823410a63e41a516b8f50c0d9f8600ba4763b5093b512309c5b8e436e"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.imprudentcook."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.imprudentcook"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7310 660f1f440000 4983c508 49ff4500 74f6 488bbc2498000000 488bce }
            // n = 7, score = 100
            //   7310                 | dec                 eax
            //   660f1f440000         | sub                 esp, 0x98
            //   4983c508             | inc                 eax
            //   49ff4500             | push                ebp
            //   74f6                 | push                ebx
            //   488bbc2498000000     | push                esi
            //   488bce               | push                edi

        $sequence_1 = { bb02000000 488d5568 488d4d68 448bcb 4c8bc6 e8???????? 4885c0 }
            // n = 7, score = 100
            //   bb02000000           | dec                 eax
            //   488d5568             | mov                 dword ptr [ebp - 0x61], eax
            //   488d4d68             | dec                 eax
            //   448bcb               | mov                 ecx, dword ptr [ebp - 0x41]
            //   4c8bc6               | dec                 esp
            //   e8????????           |                     
            //   4885c0               | mov                 ebx, eax

        $sequence_2 = { 4c8bef 48ffc7 448bf9 f7e1 c1ea07 8bc2 4803c7 }
            // n = 7, score = 100
            //   4c8bef               | dec                 eax
            //   48ffc7               | test                edi, edi
            //   448bf9               | jle                 0x1cf5
            //   f7e1                 | nop                 word ptr [eax + eax]
            //   c1ea07               | mov                 dword ptr [ebp + 0x130], 0xeabe449d
            //   8bc2                 | mov                 dword ptr [ebp + 0x134], 0x8d120389
            //   4803c7               | mov                 dword ptr [ebp + 0x138], 0xfca5e6be

        $sequence_3 = { e8???????? 4c8b6c2438 41b91e000000 4d8bc6 488bd3 498bcd e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4c8b6c2438           | dec                 esp
            //   41b91e000000         | sub                 ecx, ebx
            //   4d8bc6               | dec                 ebp
            //   488bd3               | add                 ecx, ebx
            //   498bcd               | nop                 word ptr [eax + eax]
            //   e8????????           |                     

        $sequence_4 = { 418bc3 48c1ea20 48c1e120 4803c8 488d0419 483bc1 488906 }
            // n = 7, score = 100
            //   418bc3               | dec                 eax
            //   48c1ea20             | mov                 edx, eax
            //   48c1e120             | dec                 eax
            //   4803c8               | mov                 ecx, eax
            //   488d0419             | dec                 esp
            //   483bc1               | mov                 eax, ebx
            //   488906               | dec                 eax

        $sequence_5 = { 4885f6 750f 4885ff 7450 49893e be01000000 eb46 }
            // n = 7, score = 100
            //   4885f6               | mov                 ecx, ecx
            //   750f                 | imul                eax, ebx
            //   4885ff               | dec                 eax
            //   7450                 | mov                 ebx, dword ptr [esp + 0x60]
            //   49893e               | mov                 dword ptr [esp + 0xe0], eax
            //   be01000000           | dec                 edx
            //   eb46                 | lea                 eax, [edx + edx + 0x20]

        $sequence_6 = { 498b1439 488b5c2478 488b4dd0 4803ca 483bca 49890c39 488b4de0 }
            // n = 7, score = 100
            //   498b1439             | mov                 edx, ecx
            //   488b5c2478           | dec                 esp
            //   488b4dd0             | mov                 edi, dword ptr [esp + 0xe8]
            //   4803ca               | dec                 ecx
            //   483bca               | mov                 esi, esp
            //   49890c39             | dec                 ecx
            //   488b4de0             | add                 ebx, esi

        $sequence_7 = { 4d0fafc6 4c8bd3 49c1ea20 480fafd1 4c0fafd9 4a8d0402 4c03d0 }
            // n = 7, score = 100
            //   4d0fafc6             | mov                 ecx, dword ptr [esp + 0x38]
            //   4c8bd3               | dec                 ecx
            //   49c1ea20             | or                  ecx, 0xffffffff
            //   480fafd1             | dec                 eax
            //   4c0fafd9             | mov                 edx, eax
            //   4a8d0402             | dec                 ecx
            //   4c03d0               | shr                 ecx, cl

        $sequence_8 = { 498bc2 33ed 48c1e004 4c03f8 4c89bc2400010000 4d85c0 0f8eb5000000 }
            // n = 7, score = 100
            //   498bc2               | dec                 esp
            //   33ed                 | mov                 eax, ebx
            //   48c1e004             | dec                 eax
            //   4c03f8               | mov                 edx, ecx
            //   4c89bc2400010000     | dec                 esp
            //   4d85c0               | sub                 eax, edi
            //   0f8eb5000000         | dec                 ebp

        $sequence_9 = { 84c0 7506 4883eb08 75ed 48ffc3 488bcb 48d3ea }
            // n = 7, score = 100
            //   84c0                 | dec                 eax
            //   7506                 | test                ebx, ebx
            //   4883eb08             | js                  0xbec
            //   75ed                 | dec                 eax
            //   48ffc3               | mov                 edx, esi
            //   488bcb               | dec                 eax
            //   48d3ea               | sub                 edx, ebp

    condition:
        7 of them and filesize < 864256
}
