rule win_mikoponi_auto {

    meta:
        id = "2s5oVhQYU0U3DZ4IWPKjbA"
        fingerprint = "v1_sha256_6fec244d34dfdfffb8f190bd531090181ff56cb0a8f461ac3c66e10426835858"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mikoponi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mikoponi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 68???????? 52 c744242004000000 ff15???????? 83bc242002000000 }
            // n = 5, score = 100
            //   68????????           |                     
            //   52                   | push                edx
            //   c744242004000000     | mov                 dword ptr [esp + 0x20], 4
            //   ff15????????         |                     
            //   83bc242002000000     | cmp                 dword ptr [esp + 0x220], 0

        $sequence_1 = { 81ec1c020000 a1???????? 33c4 89842418020000 8b842424020000 2d10010000 }
            // n = 6, score = 100
            //   81ec1c020000         | sub                 esp, 0x21c
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89842418020000       | mov                 dword ptr [esp + 0x218], eax
            //   8b842424020000       | mov                 eax, dword ptr [esp + 0x224]
            //   2d10010000           | sub                 eax, 0x110

        $sequence_2 = { 803d????????00 7521 8b542410 52 68???????? e8???????? }
            // n = 6, score = 100
            //   803d????????00       |                     
            //   7521                 | jne                 0x23
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]
            //   52                   | push                edx
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { 53 ff15???????? 88442413 807c241300 7480 03742424 }
            // n = 6, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   88442413             | mov                 byte ptr [esp + 0x13], al
            //   807c241300           | cmp                 byte ptr [esp + 0x13], 0
            //   7480                 | je                  0xffffff82
            //   03742424             | add                 esi, dword ptr [esp + 0x24]

        $sequence_4 = { e8???????? 83c408 85c0 7405 bd01000000 5f 33c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7405                 | je                  7
            //   bd01000000           | mov                 ebp, 1
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax

        $sequence_5 = { 50 8d8c2420020000 51 e8???????? 83c408 391d???????? 7516 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8c2420020000       | lea                 ecx, [esp + 0x220]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   391d????????         |                     
            //   7516                 | jne                 0x18

        $sequence_6 = { ff15???????? 50 6a00 6800110000 ff15???????? 8b1424 52 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6800110000           | push                0x1100
            //   ff15????????         |                     
            //   8b1424               | mov                 edx, dword ptr [esp]
            //   52                   | push                edx

        $sequence_7 = { 56 68???????? e8???????? 83c408 5e 8bc3 5b }
            // n = 7, score = 100
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   5e                   | pop                 esi
            //   8bc3                 | mov                 eax, ebx
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 330752
}
