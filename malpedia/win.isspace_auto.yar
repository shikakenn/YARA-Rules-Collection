rule win_isspace_auto {

    meta:
        id = "7HkwpzVw8oHe7h5Q4O3BSz"
        fingerprint = "v1_sha256_f9cfbe43c7bd218df762aeca13b65476ac7bccb2b29d82571f83ea3511bd9d7b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.isspace."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isspace"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a3???????? e8???????? 6800200300 a3???????? e8???????? }
            // n = 5, score = 200
            //   a3????????           |                     
            //   e8????????           |                     
            //   6800200300           | push                0x32000
            //   a3????????           |                     
            //   e8????????           |                     

        $sequence_1 = { 50 81eca8000000 a1???????? 3145f8 33c5 8945e4 }
            // n = 6, score = 200
            //   50                   | push                eax
            //   81eca8000000         | sub                 esp, 0xa8
            //   a1????????           |                     
            //   3145f8               | xor                 dword ptr [ebp - 8], eax
            //   33c5                 | xor                 eax, ebp
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_2 = { 68???????? eb04 83c007 50 }
            // n = 4, score = 200
            //   68????????           |                     
            //   eb04                 | jmp                 6
            //   83c007               | add                 eax, 7
            //   50                   | push                eax

        $sequence_3 = { 83c40c 5f c7400400000000 c70012140000 }
            // n = 4, score = 200
            //   83c40c               | add                 esp, 0xc
            //   5f                   | pop                 edi
            //   c7400400000000       | mov                 dword ptr [eax + 4], 0
            //   c70012140000         | mov                 dword ptr [eax], 0x1412

        $sequence_4 = { 6870170000 ff15???????? e9???????? 6a40 6a00 68???????? e8???????? }
            // n = 7, score = 200
            //   6870170000           | push                0x1770
            //   ff15????????         |                     
            //   e9????????           |                     
            //   6a40                 | push                0x40
            //   6a00                 | push                0
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_5 = { b898a30000 e8???????? a1???????? 3145f8 }
            // n = 4, score = 200
            //   b898a30000           | mov                 eax, 0xa398
            //   e8????????           |                     
            //   a1????????           |                     
            //   3145f8               | xor                 dword ptr [ebp - 8], eax

        $sequence_6 = { 83c404 6683f809 740c 6683f806 }
            // n = 4, score = 200
            //   83c404               | add                 esp, 4
            //   6683f809             | cmp                 ax, 9
            //   740c                 | je                  0xe
            //   6683f806             | cmp                 ax, 6

        $sequence_7 = { 50 8d45f0 64a300000000 8965e8 c745fc00000000 ff15???????? 3d04080000 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   ff15????????         |                     
            //   3d04080000           | cmp                 eax, 0x804

    condition:
        7 of them and filesize < 434176
}
