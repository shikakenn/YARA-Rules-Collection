rule win_bleachgap_auto {

    meta:
        id = "2ZK4ZnBQEBqMLCh4eDLCGZ"
        fingerprint = "v1_sha256_3130a827d52ec3314a8f25fbc828dbf76548d8c3f7d1048f0043a6b2ade8d5de"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bleachgap."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bleachgap"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff742420 e8???????? 83c404 8bc3 5f 5e 5d }
            // n = 7, score = 100
            //   ff742420             | push                dword ptr [esp + 0x20]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8bc3                 | mov                 eax, ebx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp

        $sequence_1 = { ff7604 8bf8 e8???????? 83c410 8bf0 85ff 0f8444020000 }
            // n = 7, score = 100
            //   ff7604               | push                dword ptr [esi + 4]
            //   8bf8                 | mov                 edi, eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8bf0                 | mov                 esi, eax
            //   85ff                 | test                edi, edi
            //   0f8444020000         | je                  0x24a

        $sequence_2 = { c3 ff760c e8???????? 83c404 8944241c 85c0 0f8432010000 }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   ff760c               | push                dword ptr [esi + 0xc]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   85c0                 | test                eax, eax
            //   0f8432010000         | je                  0x138

        $sequence_3 = { 8b85d8f6ffff 0fb7048574ae5f00 8d048570a55f00 50 8d85f0f6ffff 03c7 50 }
            // n = 7, score = 100
            //   8b85d8f6ffff         | mov                 eax, dword ptr [ebp - 0x928]
            //   0fb7048574ae5f00     | movzx               eax, word ptr [eax*4 + 0x5fae74]
            //   8d048570a55f00       | lea                 eax, [eax*4 + 0x5fa570]
            //   50                   | push                eax
            //   8d85f0f6ffff         | lea                 eax, [ebp - 0x910]
            //   03c7                 | add                 eax, edi
            //   50                   | push                eax

        $sequence_4 = { e8???????? 83c404 c645fc09 85ff 742d 8b4de8 8bc7 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c645fc09             | mov                 byte ptr [ebp - 4], 9
            //   85ff                 | test                edi, edi
            //   742d                 | je                  0x2f
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8bc7                 | mov                 eax, edi

        $sequence_5 = { ff442418 85f6 0f8564feffff 8b5c2410 53 e8???????? 83c404 }
            // n = 7, score = 100
            //   ff442418             | inc                 dword ptr [esp + 0x18]
            //   85f6                 | test                esi, esi
            //   0f8564feffff         | jne                 0xfffffe6a
            //   8b5c2410             | mov                 ebx, dword ptr [esp + 0x10]
            //   53                   | push                ebx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_6 = { 8b8424bc000000 8b00 85c0 0f45c8 33db 894c2410 33ed }
            // n = 7, score = 100
            //   8b8424bc000000       | mov                 eax, dword ptr [esp + 0xbc]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   85c0                 | test                eax, eax
            //   0f45c8               | cmovne              ecx, eax
            //   33db                 | xor                 ebx, ebx
            //   894c2410             | mov                 dword ptr [esp + 0x10], ecx
            //   33ed                 | xor                 ebp, ebp

        $sequence_7 = { ba02000000 89471c 8bdd 8bf5 eb42 01471c 8bdd }
            // n = 7, score = 100
            //   ba02000000           | mov                 edx, 2
            //   89471c               | mov                 dword ptr [edi + 0x1c], eax
            //   8bdd                 | mov                 ebx, ebp
            //   8bf5                 | mov                 esi, ebp
            //   eb42                 | jmp                 0x44
            //   01471c               | add                 dword ptr [edi + 0x1c], eax
            //   8bdd                 | mov                 ebx, ebp

        $sequence_8 = { c745e400000000 c745e80f000000 8a01 41 84c0 75f9 2bca }
            // n = 7, score = 100
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0
            //   c745e80f000000       | mov                 dword ptr [ebp - 0x18], 0xf
            //   8a01                 | mov                 al, byte ptr [ecx]
            //   41                   | inc                 ecx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   2bca                 | sub                 ecx, edx

        $sequence_9 = { ff7650 e8???????? 83cdff 8d4e10 83c404 896c2420 837e7800 }
            // n = 7, score = 100
            //   ff7650               | push                dword ptr [esi + 0x50]
            //   e8????????           |                     
            //   83cdff               | or                  ebp, 0xffffffff
            //   8d4e10               | lea                 ecx, [esi + 0x10]
            //   83c404               | add                 esp, 4
            //   896c2420             | mov                 dword ptr [esp + 0x20], ebp
            //   837e7800             | cmp                 dword ptr [esi + 0x78], 0

    condition:
        7 of them and filesize < 4538368
}
