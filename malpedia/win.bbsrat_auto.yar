rule win_bbsrat_auto {

    meta:
        id = "q9xSJa0vttT7MmkzzSGbr"
        fingerprint = "v1_sha256_41e9d1288a6b47bf01a3af69d556bf8b74b048345c44a671654c850d84e7f7a3"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.bbsrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bbsrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83c408 c3 6a00 8d442418 50 57 53 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   57                   | push                edi
            //   53                   | push                ebx

        $sequence_1 = { 8bec c7451001000000 c7450c01000000 833d????????00 7516 68???????? a1???????? }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   c7451001000000       | mov                 dword ptr [ebp + 0x10], 1
            //   c7450c01000000       | mov                 dword ptr [ebp + 0xc], 1
            //   833d????????00       |                     
            //   7516                 | jne                 0x18
            //   68????????           |                     
            //   a1????????           |                     

        $sequence_2 = { 85c0 7463 8b3d???????? 6a00 6a00 6a03 6a00 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7463                 | je                  0x65
            //   8b3d????????         |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a03                 | push                3
            //   6a00                 | push                0

        $sequence_3 = { 50 8d8c24de080000 51 66898424e0080000 e8???????? 33d2 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d8c24de080000       | lea                 ecx, [esp + 0x8de]
            //   51                   | push                ecx
            //   66898424e0080000     | mov                 word ptr [esp + 0x8e0], ax
            //   e8????????           |                     
            //   33d2                 | xor                 edx, edx

        $sequence_4 = { 8b8620010000 3bc3 7407 50 ff15???????? 8b8634010000 57 }
            // n = 7, score = 100
            //   8b8620010000         | mov                 eax, dword ptr [esi + 0x120]
            //   3bc3                 | cmp                 eax, ebx
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8634010000         | mov                 eax, dword ptr [esi + 0x134]
            //   57                   | push                edi

        $sequence_5 = { 752a 80780500 7524 80780600 751e b105 384807 }
            // n = 7, score = 100
            //   752a                 | jne                 0x2c
            //   80780500             | cmp                 byte ptr [eax + 5], 0
            //   7524                 | jne                 0x26
            //   80780600             | cmp                 byte ptr [eax + 6], 0
            //   751e                 | jne                 0x20
            //   b105                 | mov                 cl, 5
            //   384807               | cmp                 byte ptr [eax + 7], cl

        $sequence_6 = { 89442404 eb04 8b442404 f7d8 1bc0 }
            // n = 5, score = 100
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   eb04                 | jmp                 6
            //   8b442404             | mov                 eax, dword ptr [esp + 4]
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax

        $sequence_7 = { 53 89442404 89442408 8944240c 55 8b6c241c 89442414 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   55                   | push                ebp
            //   8b6c241c             | mov                 ebp, dword ptr [esp + 0x1c]
            //   89442414             | mov                 dword ptr [esp + 0x14], eax

        $sequence_8 = { 6a04 8d442420 50 6a1f 53 e8???????? e9???????? }
            // n = 7, score = 100
            //   6a04                 | push                4
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   6a1f                 | push                0x1f
            //   53                   | push                ebx
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_9 = { 0f8415010000 397c2418 0f860b010000 8d642400 8b442414 8b34b8 837e0401 }
            // n = 7, score = 100
            //   0f8415010000         | je                  0x11b
            //   397c2418             | cmp                 dword ptr [esp + 0x18], edi
            //   0f860b010000         | jbe                 0x111
            //   8d642400             | lea                 esp, [esp]
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b34b8               | mov                 esi, dword ptr [eax + edi*4]
            //   837e0401             | cmp                 dword ptr [esi + 4], 1

    condition:
        7 of them and filesize < 434176
}
