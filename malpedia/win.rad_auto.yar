rule win_rad_auto {

    meta:
        id = "1rfHIS7iyv612JA605rqHU"
        fingerprint = "v1_sha256_1eec20ddabb813a5b7c10180af0c0f122f744f026c6b5d60bcc21414af7a0dac"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rad."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rad"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e9???????? 8d8520feffff 50 e8???????? c3 8d85c0fcffff 50 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8d8520feffff         | lea                 eax, [ebp - 0x1e0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c3                   | ret                 
            //   8d85c0fcffff         | lea                 eax, [ebp - 0x340]
            //   50                   | push                eax

        $sequence_1 = { 68???????? 8d4df8 68???????? 51 ffd7 83c410 }
            // n = 6, score = 100
            //   68????????           |                     
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd7                 | call                edi
            //   83c410               | add                 esp, 0x10

        $sequence_2 = { 8db514faffff e9???????? 8db5f8f9ffff e9???????? 8d8d88faffff ff25???????? 8db5dcf9ffff }
            // n = 7, score = 100
            //   8db514faffff         | lea                 esi, [ebp - 0x5ec]
            //   e9????????           |                     
            //   8db5f8f9ffff         | lea                 esi, [ebp - 0x608]
            //   e9????????           |                     
            //   8d8d88faffff         | lea                 ecx, [ebp - 0x578]
            //   ff25????????         |                     
            //   8db5dcf9ffff         | lea                 esi, [ebp - 0x624]

        $sequence_3 = { ff15???????? 8bc6 8b8c24e0000000 64890d00000000 59 5e 5b }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bc6                 | mov                 eax, esi
            //   8b8c24e0000000       | mov                 ecx, dword ptr [esp + 0xe0]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx
            //   59                   | pop                 ecx
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_4 = { c684240001000002 85f6 7439 8d8c24d4000000 }
            // n = 4, score = 100
            //   c684240001000002     | mov                 byte ptr [esp + 0x100], 2
            //   85f6                 | test                esi, esi
            //   7439                 | je                  0x3b
            //   8d8c24d4000000       | lea                 ecx, [esp + 0xd4]

        $sequence_5 = { 7556 8bce 897508 ff15???????? 8d55f0 52 8bce }
            // n = 7, score = 100
            //   7556                 | jne                 0x58
            //   8bce                 | mov                 ecx, esi
            //   897508               | mov                 dword ptr [ebp + 8], esi
            //   ff15????????         |                     
            //   8d55f0               | lea                 edx, [ebp - 0x10]
            //   52                   | push                edx
            //   8bce                 | mov                 ecx, esi

        $sequence_6 = { 51 8d8d34ffffff ff15???????? 8d8d10ffffff c645fc03 ff15???????? 8b35???????? }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   8d8d34ffffff         | lea                 ecx, [ebp - 0xcc]
            //   ff15????????         |                     
            //   8d8d10ffffff         | lea                 ecx, [ebp - 0xf0]
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   ff15????????         |                     
            //   8b35????????         |                     

        $sequence_7 = { 84c0 0f84c5000000 b8???????? 8dbc24e0000000 e8???????? 8bcf 51 }
            // n = 7, score = 100
            //   84c0                 | test                al, al
            //   0f84c5000000         | je                  0xcb
            //   b8????????           |                     
            //   8dbc24e0000000       | lea                 edi, [esp + 0xe0]
            //   e8????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   51                   | push                ecx

        $sequence_8 = { c684240c06000022 ff15???????? 8b4c241c 50 81c1c4030000 c684240c06000023 ff15???????? }
            // n = 7, score = 100
            //   c684240c06000022     | mov                 byte ptr [esp + 0x60c], 0x22
            //   ff15????????         |                     
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]
            //   50                   | push                eax
            //   81c1c4030000         | add                 ecx, 0x3c4
            //   c684240c06000023     | mov                 byte ptr [esp + 0x60c], 0x23
            //   ff15????????         |                     

        $sequence_9 = { 8b8d00ffffff 8b5104 8d8550ffffff 898510fdffff c7841500ffffffa4e64000 8d8504ffffff }
            // n = 6, score = 100
            //   8b8d00ffffff         | mov                 ecx, dword ptr [ebp - 0x100]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   8d8550ffffff         | lea                 eax, [ebp - 0xb0]
            //   898510fdffff         | mov                 dword ptr [ebp - 0x2f0], eax
            //   c7841500ffffffa4e64000     | mov    dword ptr [ebp + edx - 0x100], 0x40e6a4
            //   8d8504ffffff         | lea                 eax, [ebp - 0xfc]

    condition:
        7 of them and filesize < 207872
}
