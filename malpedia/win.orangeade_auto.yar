rule win_orangeade_auto {

    meta:
        id = "3weOXFMdk9IXdDsbEdvrwQ"
        fingerprint = "v1_sha256_bc9cfd6680cc4f32cd41e9edf43afa43b54975c598906df96ea95e31fa6c1612"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.orangeade."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orangeade"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bb42428050000 50 8bce e8???????? c744241001000000 }
            // n = 5, score = 100
            //   8bb42428050000       | mov                 esi, dword ptr [esp + 0x528]
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   c744241001000000     | mov                 dword ptr [esp + 0x10], 1

        $sequence_1 = { 50 8d942470020000 51 52 ff15???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8d942470020000       | lea                 edx, [esp + 0x270]
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_2 = { f3ab 66ab aa 8d842468020000 50 }
            // n = 5, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d842468020000       | lea                 eax, [esp + 0x268]
            //   50                   | push                eax

        $sequence_3 = { 6881000000 6a00 c784249428010000000000 ff15???????? 8bf0 56 }
            // n = 6, score = 100
            //   6881000000           | push                0x81
            //   6a00                 | push                0
            //   c784249428010000000000     | mov    dword ptr [esp + 0x12894], 0
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi

        $sequence_4 = { aa b93f000000 33c0 8dbc2465010000 }
            // n = 4, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b93f000000           | mov                 ecx, 0x3f
            //   33c0                 | xor                 eax, eax
            //   8dbc2465010000       | lea                 edi, [esp + 0x165]

        $sequence_5 = { 8d4c2424 c684248828010002 e8???????? 8d4c2410 c684248828010001 e8???????? 8d4c2414 }
            // n = 7, score = 100
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   c684248828010002     | mov                 byte ptr [esp + 0x12888], 2
            //   e8????????           |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   c684248828010001     | mov                 byte ptr [esp + 0x12888], 1
            //   e8????????           |                     
            //   8d4c2414             | lea                 ecx, [esp + 0x14]

        $sequence_6 = { b93f000000 33c0 8d7c2479 885c2478 f3ab }
            // n = 5, score = 100
            //   b93f000000           | mov                 ecx, 0x3f
            //   33c0                 | xor                 eax, eax
            //   8d7c2479             | lea                 edi, [esp + 0x79]
            //   885c2478             | mov                 byte ptr [esp + 0x78], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_7 = { 68???????? 8d4c2410 e8???????? 68???????? 6884000000 53 ff15???????? }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   e8????????           |                     
            //   68????????           |                     
            //   6884000000           | push                0x84
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_8 = { e8???????? 83c404 8d4c2424 c684248828010002 }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   c684248828010002     | mov                 byte ptr [esp + 0x12888], 2

        $sequence_9 = { 50 8d4c2410 c684248400000001 e8???????? }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8d4c2410             | lea                 ecx, [esp + 0x10]
            //   c684248400000001     | mov                 byte ptr [esp + 0x84], 1
            //   e8????????           |                     

    condition:
        7 of them and filesize < 139264
}
