rule win_icedid_downloader_auto {

    meta:
        id = "2JH1UOFY9UMnT1ze80N8GO"
        fingerprint = "v1_sha256_8833f99bb1bd77711eb78fc1bd4033ed964a1a4a33594d443cf638144662738b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.icedid_downloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid_downloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 57 ff742430 ff5660 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff742430             | push                dword ptr [esp + 0x30]
            //   ff5660               | call                dword ptr [esi + 0x60]

        $sequence_1 = { 8bd8 85db 7413 6a01 56 }
            // n = 5, score = 400
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7413                 | je                  0x15
            //   6a01                 | push                1
            //   56                   | push                esi

        $sequence_2 = { 6a01 6a08 6689742434 ff15???????? 68???????? 89442434 }
            // n = 6, score = 400
            //   6a01                 | push                1
            //   6a08                 | push                8
            //   6689742434           | mov                 word ptr [esp + 0x34], si
            //   ff15????????         |                     
            //   68????????           |                     
            //   89442434             | mov                 dword ptr [esp + 0x34], eax

        $sequence_3 = { 0ad8 885c2418 45 83c708 3b2e }
            // n = 5, score = 400
            //   0ad8                 | or                  bl, al
            //   885c2418             | mov                 byte ptr [esp + 0x18], bl
            //   45                   | inc                 ebp
            //   83c708               | add                 edi, 8
            //   3b2e                 | cmp                 ebp, dword ptr [esi]

        $sequence_4 = { ff7010 ff75f4 e8???????? 83c410 8bd8 ff75ec ff15???????? }
            // n = 7, score = 400
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8bd8                 | mov                 ebx, eax
            //   ff75ec               | push                dword ptr [ebp - 0x14]
            //   ff15????????         |                     

        $sequence_5 = { 8d442428 50 ff742438 ff15???????? 8d442440 50 68???????? }
            // n = 7, score = 400
            //   8d442428             | lea                 eax, [esp + 0x28]
            //   50                   | push                eax
            //   ff742438             | push                dword ptr [esp + 0x38]
            //   ff15????????         |                     
            //   8d442440             | lea                 eax, [esp + 0x40]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_6 = { ff15???????? 6a05 5b 8d4554 c7450001000000 50 }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   6a05                 | push                5
            //   5b                   | pop                 ebx
            //   8d4554               | lea                 eax, [ebp + 0x54]
            //   c7450001000000       | mov                 dword ptr [ebp], 1
            //   50                   | push                eax

        $sequence_7 = { 6a0b 58 668945c4 8d75d4 33c0 c745dc00330000 6a16 }
            // n = 7, score = 400
            //   6a0b                 | push                0xb
            //   58                   | pop                 eax
            //   668945c4             | mov                 word ptr [ebp - 0x3c], ax
            //   8d75d4               | lea                 esi, [ebp - 0x2c]
            //   33c0                 | xor                 eax, eax
            //   c745dc00330000       | mov                 dword ptr [ebp - 0x24], 0x3300
            //   6a16                 | push                0x16

        $sequence_8 = { b805400080 eb76 ff7508 ff15???????? }
            // n = 4, score = 400
            //   b805400080           | mov                 eax, 0x80004005
            //   eb76                 | jmp                 0x78
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_9 = { 50 8d45d4 66895d04 50 57 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   66895d04             | mov                 word ptr [ebp + 4], bx
            //   50                   | push                eax
            //   57                   | push                edi

    condition:
        7 of them and filesize < 40960
}
