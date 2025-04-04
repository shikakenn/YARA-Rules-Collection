rule win_leouncia_auto {

    meta:
        id = "6xziDTpOFMUWrOKRt73ebT"
        fingerprint = "v1_sha256_f4b700de9db33424264876c9622563c2f372a2b66a216a2beabd8c8a0520c076"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.leouncia."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.leouncia"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b442444 6a64 50 ff15???????? 3bc3 }
            // n = 5, score = 100
            //   8b442444             | mov                 eax, dword ptr [esp + 0x44]
            //   6a64                 | push                0x64
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3bc3                 | cmp                 eax, ebx

        $sequence_1 = { c644046000 8d442460 50 e8???????? 8bf0 83c410 }
            // n = 6, score = 100
            //   c644046000           | mov                 byte ptr [esp + eax + 0x60], 0
            //   8d442460             | lea                 eax, [esp + 0x60]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c410               | add                 esp, 0x10

        $sequence_2 = { 7714 8088????????10 8ac8 80c120 888820af4000 eb1f }
            // n = 6, score = 100
            //   7714                 | ja                  0x16
            //   8088????????10       |                     
            //   8ac8                 | mov                 cl, al
            //   80c120               | add                 cl, 0x20
            //   888820af4000         | mov                 byte ptr [eax + 0x40af20], cl
            //   eb1f                 | jmp                 0x21

        $sequence_3 = { 55 8bac2430040000 56 8b11 8d7010 8954240c }
            // n = 6, score = 100
            //   55                   | push                ebp
            //   8bac2430040000       | mov                 ebp, dword ptr [esp + 0x430]
            //   56                   | push                esi
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   8d7010               | lea                 esi, [eax + 0x10]
            //   8954240c             | mov                 dword ptr [esp + 0xc], edx

        $sequence_4 = { 55 ff15???????? 8bd8 89442430 2bde }
            // n = 5, score = 100
            //   55                   | push                ebp
            //   ff15????????         |                     
            //   8bd8                 | mov                 ebx, eax
            //   89442430             | mov                 dword ptr [esp + 0x30], eax
            //   2bde                 | sub                 ebx, esi

        $sequence_5 = { ff15???????? 8be8 3beb 896c2424 7514 }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   8be8                 | mov                 ebp, eax
            //   3beb                 | cmp                 ebp, ebx
            //   896c2424             | mov                 dword ptr [esp + 0x24], ebp
            //   7514                 | jne                 0x16

        $sequence_6 = { c744240800540000 56 e8???????? 83c404 85c0 0f84f0000000 6a00 }
            // n = 7, score = 100
            //   c744240800540000     | mov                 dword ptr [esp + 8], 0x5400
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   0f84f0000000         | je                  0xf6
            //   6a00                 | push                0

        $sequence_7 = { 8d4c2454 8d542434 51 50 }
            // n = 4, score = 100
            //   8d4c2454             | lea                 ecx, [esp + 0x54]
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   51                   | push                ecx
            //   50                   | push                eax

        $sequence_8 = { 50 f3a4 e8???????? 8d7c2438 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   e8????????           |                     
            //   8d7c2438             | lea                 edi, [esp + 0x38]

        $sequence_9 = { e8???????? 8d542448 8bf0 52 e8???????? 83c424 81fec8000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8d542448             | lea                 edx, [esp + 0x48]
            //   8bf0                 | mov                 esi, eax
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c424               | add                 esp, 0x24
            //   81fec8000000         | cmp                 esi, 0xc8

    condition:
        7 of them and filesize < 114688
}
