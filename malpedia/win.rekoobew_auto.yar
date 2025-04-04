rule win_rekoobew_auto {

    meta:
        id = "4uujOmBx42YgCZIdMlYm8s"
        fingerprint = "v1_sha256_aef627dbf43f3f433f140924ae4bed9b7cb42ca10d8749c65899eb3d41030244"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rekoobew."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rekoobew"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 333cb5e07c4000 33bb14010000 89d6 c1ee10 81e6ff000000 333cb5e0744000 8b4dec }
            // n = 7, score = 100
            //   333cb5e07c4000       | xor                 edi, dword ptr [esi*4 + 0x407ce0]
            //   33bb14010000         | xor                 edi, dword ptr [ebx + 0x114]
            //   89d6                 | mov                 esi, edx
            //   c1ee10               | shr                 esi, 0x10
            //   81e6ff000000         | and                 esi, 0xff
            //   333cb5e0744000       | xor                 edi, dword ptr [esi*4 + 0x4074e0]
            //   8b4dec               | mov                 ecx, dword ptr [ebp - 0x14]

        $sequence_1 = { 0fb6f5 3314b5e08c4000 83c720 0fb6ca 8b348de0904000 }
            // n = 5, score = 100
            //   0fb6f5               | movzx               esi, ch
            //   3314b5e08c4000       | xor                 edx, dword ptr [esi*4 + 0x408ce0]
            //   83c720               | add                 edi, 0x20
            //   0fb6ca               | movzx               ecx, dl
            //   8b348de0904000       | mov                 esi, dword ptr [ecx*4 + 0x4090e0]

        $sequence_2 = { 83c202 c60200 5b 5e 5d c3 }
            // n = 6, score = 100
            //   83c202               | add                 edx, 2
            //   c60200               | mov                 byte ptr [edx], 0
            //   5b                   | pop                 ebx
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_3 = { 31cf 8b4de8 0fb6f5 8b0cb5e0804000 }
            // n = 4, score = 100
            //   31cf                 | xor                 edi, ecx
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   0fb6f5               | movzx               esi, ch
            //   8b0cb5e0804000       | mov                 ecx, dword ptr [esi*4 + 0x4080e0]

        $sequence_4 = { 333495e0744000 8b4de8 0fb6d5 89f1 330c95e0784000 83c720 0fb655e4 }
            // n = 7, score = 100
            //   333495e0744000       | xor                 esi, dword ptr [edx*4 + 0x4074e0]
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   0fb6d5               | movzx               edx, ch
            //   89f1                 | mov                 ecx, esi
            //   330c95e0784000       | xor                 ecx, dword ptr [edx*4 + 0x4078e0]
            //   83c720               | add                 edi, 0x20
            //   0fb655e4             | movzx               edx, byte ptr [ebp - 0x1c]

        $sequence_5 = { 31f9 034df0 89c3 c1c305 01d9 c1c71e 8b5db0 }
            // n = 7, score = 100
            //   31f9                 | xor                 ecx, edi
            //   034df0               | add                 ecx, dword ptr [ebp - 0x10]
            //   89c3                 | mov                 ebx, eax
            //   c1c305               | rol                 ebx, 5
            //   01d9                 | add                 ecx, ebx
            //   c1c71e               | rol                 edi, 0x1e
            //   8b5db0               | mov                 ebx, dword ptr [ebp - 0x50]

        $sequence_6 = { c1c705 01fa c1c01e 8b7de4 337dec 337db8 337dbc }
            // n = 7, score = 100
            //   c1c705               | rol                 edi, 5
            //   01fa                 | add                 edx, edi
            //   c1c01e               | rol                 eax, 0x1e
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   337dec               | xor                 edi, dword ptr [ebp - 0x14]
            //   337db8               | xor                 edi, dword ptr [ebp - 0x48]
            //   337dbc               | xor                 edi, dword ptr [ebp - 0x44]

        $sequence_7 = { 0fb65005 c1e210 09f2 0fb67007 09f2 0fb67006 }
            // n = 6, score = 100
            //   0fb65005             | movzx               edx, byte ptr [eax + 5]
            //   c1e210               | shl                 edx, 0x10
            //   09f2                 | or                  edx, esi
            //   0fb67007             | movzx               esi, byte ptr [eax + 7]
            //   09f2                 | or                  edx, esi
            //   0fb67006             | movzx               esi, byte ptr [eax + 6]

        $sequence_8 = { 89f3 31d3 21cb 31d3 035df0 89c7 c1c705 }
            // n = 7, score = 100
            //   89f3                 | mov                 ebx, esi
            //   31d3                 | xor                 ebx, edx
            //   21cb                 | and                 ebx, ecx
            //   31d3                 | xor                 ebx, edx
            //   035df0               | add                 ebx, dword ptr [ebp - 0x10]
            //   89c7                 | mov                 edi, eax
            //   c1c705               | rol                 edi, 5

        $sequence_9 = { 89d6 8b55e8 3314b5e08c4000 8955e0 }
            // n = 4, score = 100
            //   89d6                 | mov                 esi, edx
            //   8b55e8               | mov                 edx, dword ptr [ebp - 0x18]
            //   3314b5e08c4000       | xor                 edx, dword ptr [esi*4 + 0x408ce0]
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx

    condition:
        7 of them and filesize < 248832
}
