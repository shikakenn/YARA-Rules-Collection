rule win_lpeclient_auto {

    meta:
        id = "2yeNx11e4peefVIaiPNMoB"
        fingerprint = "v1_sha256_fa5662e58821dbe4e01d6876bcd73f389c9fb3b6d70b4d7afea75bf844e373c6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lpeclient."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lpeclient"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 33d2 897590 e8???????? 488d8dc2000000 33d2 }
            // n = 5, score = 100
            //   33d2                 | test                eax, eax
            //   897590               | je                  0x12ad
            //   e8????????           |                     
            //   488d8dc2000000       | mov                 word ptr [esp + 0x46], ax
            //   33d2                 | test                eax, eax

        $sequence_1 = { 33d2 41b808040000 e8???????? 488bcf ff15???????? 488bce ff15???????? }
            // n = 7, score = 100
            //   33d2                 | add                 edx, ecx
            //   41b808040000         | cmp                 byte ptr [edx], al
            //   e8????????           |                     
            //   488bcf               | jne                 0x497
            //   ff15????????         |                     
            //   488bce               | jmp                 0x4e3
            //   ff15????????         |                     

        $sequence_2 = { 488d0df74e0100 ff15???????? 488d0d9a480100 ff15???????? }
            // n = 4, score = 100
            //   488d0df74e0100       | nop                 word ptr [eax + eax]
            //   ff15????????         |                     
            //   488d0d9a480100       | movzx               eax, byte ptr [ecx]
            //   ff15????????         |                     

        $sequence_3 = { ff15???????? 488d4de0 33d2 41b808040000 488bd8 e8???????? 488d4de0 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d4de0             | mov                 eax, dword ptr [esp + 0x50]
            //   33d2                 | inc                 edx
            //   41b808040000         | xor                 edx, dword ptr [ecx + eax*4 + 0x1a360]
            //   488bd8               | rol                 edx, 0xb
            //   e8????????           |                     
            //   488d4de0             | xor                 ebx, edx

        $sequence_4 = { ff15???????? 488d9500040000 488bc8 ff15???????? 488d4de0 33d2 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488d9500040000       | mov                 ecx, 0x20000000
            //   488bc8               | repne scasd         eax, dword ptr es:[edi]
            //   ff15????????         |                     
            //   488d4de0             | dec                 eax
            //   33d2                 | not                 ecx

        $sequence_5 = { 4885c0 753b 488d4dd0 488d45d0 488b15???????? 482bd0 666666660f1f840000000000 }
            // n = 7, score = 100
            //   4885c0               | lea                 ecx, [esp + 0x30]
            //   753b                 | dec                 eax
            //   488d4dd0             | lea                 edx, [0x4a61]
            //   488d45d0             | inc                 ecx
            //   488b15????????       |                     
            //   482bd0               | mov                 eax, 0x98
            //   666666660f1f840000000000     | dec    ecx

        $sequence_6 = { c7451072007500 c7451473005000 c7451872006f00 c7451c64007500 c7452063007400 66894524 }
            // n = 6, score = 100
            //   c7451072007500       | movzx               eax, byte ptr [edx + 0x16]
            //   c7451473005000       | inc                 ecx
            //   c7451872006f00       | mov                 dword ptr [ecx + 0x1c], ecx
            //   c7451c64007500       | movzx               eax, byte ptr [edx + 0x19]
            //   c7452063007400       | movzx               ecx, byte ptr [edx + 0x18]
            //   66894524             | shl                 ecx, 8

        $sequence_7 = { c7451c64007500 c7452063007400 66894524 c745b872006f00 c745bc6f007400 c745c05c005300 c745c465006300 }
            // n = 7, score = 100
            //   c7451c64007500       | inc                 esp
            //   c7452063007400       | mov                 eax, ecx
            //   66894524             | dec                 eax
            //   c745b872006f00       | shr                 ecx, 0x18
            //   c745bc6f007400       | and                 ecx, 0xf
            //   c745c05c005300       | inc                 ecx
            //   c745c465006300       | mov                 eax, eax

        $sequence_8 = { 85c0 74dc 4c8d85a0070000 488d1504f70000 }
            // n = 4, score = 100
            //   85c0                 | call                dword ptr [eax]
            //   74dc                 | test                eax, eax
            //   4c8d85a0070000       | js                  0x1da2
            //   488d1504f70000       | dec                 eax

        $sequence_9 = { 85c0 0f8e87140000 48895c2470 48896c2450 4d8d6208 4c89742438 4c8d5702 }
            // n = 7, score = 100
            //   85c0                 | dec                 eax
            //   0f8e87140000         | lea                 ecx, [0x115bb]
            //   48895c2470           | dec                 eax
            //   48896c2450           | mov                 eax, dword ptr [ecx + eax*8]
            //   4d8d6208             | inc                 ecx
            //   4c89742438           | test                byte ptr [edi + eax + 8], 0x40
            //   4c8d5702             | je                  0xc9f

    condition:
        7 of them and filesize < 289792
}
