rule win_badhatch_auto {

    meta:
        id = "31eQPZYuWZBdRR3hhASlVL"
        fingerprint = "v1_sha256_d1799db66ba63d047ab24cbcf38644792982827a0f2e3a856828a5d589d13430"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.badhatch."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.badhatch"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85db 7503 8b5f10 03de 8b7710 037508 eb26 }
            // n = 7, score = 100
            //   85db                 | test                ebx, ebx
            //   7503                 | jne                 5
            //   8b5f10               | mov                 ebx, dword ptr [edi + 0x10]
            //   03de                 | add                 ebx, esi
            //   8b7710               | mov                 esi, dword ptr [edi + 0x10]
            //   037508               | add                 esi, dword ptr [ebp + 8]
            //   eb26                 | jmp                 0x28

        $sequence_1 = { 68???????? ff7718 e9???????? 68???????? 8dbd54dfffff e8???????? 59 }
            // n = 7, score = 100
            //   68????????           |                     
            //   ff7718               | push                dword ptr [edi + 0x18]
            //   e9????????           |                     
            //   68????????           |                     
            //   8dbd54dfffff         | lea                 edi, [ebp - 0x20ac]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_2 = { 53 57 68???????? 50 ff15???????? ff761c ff15???????? }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   57                   | push                edi
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   ff761c               | push                dword ptr [esi + 0x1c]
            //   ff15????????         |                     

        $sequence_3 = { 3bca 7619 8b1d???????? 03da 3bcb 730d }
            // n = 6, score = 100
            //   3bca                 | cmp                 ecx, edx
            //   7619                 | jbe                 0x1b
            //   8b1d????????         |                     
            //   03da                 | add                 ebx, edx
            //   3bcb                 | cmp                 ecx, ebx
            //   730d                 | jae                 0xf

        $sequence_4 = { 89742434 89742438 8974243c ff15???????? 8bf8 3bfe 0f852f010000 }
            // n = 7, score = 100
            //   89742434             | mov                 dword ptr [esp + 0x34], esi
            //   89742438             | mov                 dword ptr [esp + 0x38], esi
            //   8974243c             | mov                 dword ptr [esp + 0x3c], esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   3bfe                 | cmp                 edi, esi
            //   0f852f010000         | jne                 0x135

        $sequence_5 = { 6a02 56 ff15???????? 8bc7 5f 5b c9 }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi
            //   5b                   | pop                 ebx
            //   c9                   | leave               

        $sequence_6 = { ffd6 ff75cc ffd6 895dcc 895dd0 ffb738010000 }
            // n = 6, score = 100
            //   ffd6                 | call                esi
            //   ff75cc               | push                dword ptr [ebp - 0x34]
            //   ffd6                 | call                esi
            //   895dcc               | mov                 dword ptr [ebp - 0x34], ebx
            //   895dd0               | mov                 dword ptr [ebp - 0x30], ebx
            //   ffb738010000         | push                dword ptr [edi + 0x138]

        $sequence_7 = { 8d8564ffffff 50 ff15???????? 8945dc 83f8ff 7405 895de4 }
            // n = 7, score = 100
            //   8d8564ffffff         | lea                 eax, [ebp - 0x9c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   83f8ff               | cmp                 eax, -1
            //   7405                 | je                  7
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx

        $sequence_8 = { 81fee0327077 7415 81fedec5c08a 0f851c010000 894c2424 e9???????? }
            // n = 6, score = 100
            //   81fee0327077         | cmp                 esi, 0x777032e0
            //   7415                 | je                  0x17
            //   81fedec5c08a         | cmp                 esi, 0x8ac0c5de
            //   0f851c010000         | jne                 0x122
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   e9????????           |                     

        $sequence_9 = { 6a01 8b7d08 8bc7 e8???????? 59 8945e4 85c0 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8bc7                 | mov                 eax, edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 156672
}
