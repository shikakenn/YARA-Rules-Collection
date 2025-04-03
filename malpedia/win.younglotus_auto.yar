rule win_younglotus_auto {

    meta:
        id = "26imW8TFpZQKUbAkQGYB6B"
        fingerprint = "v1_sha256_22c4cfdc7fd425b818daae07117ab2b0a1f6250b75eb7983096dfb11564bd4bb"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.younglotus."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6802000080 e8???????? 83c41c 6a01 }
            // n = 4, score = 1000
            //   6802000080           | push                0x80000002
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   6a01                 | push                1

        $sequence_1 = { 8945fc 8b4dfc 3b4d0c 7d26 }
            // n = 4, score = 800
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   3b4d0c               | cmp                 ecx, dword ptr [ebp + 0xc]
            //   7d26                 | jge                 0x28

        $sequence_2 = { 8b55fc 8b4210 50 ff15???????? 8b4dfc 8981b4000000 }
            // n = 6, score = 800
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4210               | mov                 eax, dword ptr [edx + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8981b4000000         | mov                 dword ptr [ecx + 0xb4], eax

        $sequence_3 = { 8b45fc 8b484c 51 ff15???????? 8be5 5d c3 }
            // n = 7, score = 800
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b484c               | mov                 ecx, dword ptr [eax + 0x4c]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 

        $sequence_4 = { 837df800 740a 8b4df8 51 ff15???????? 32c0 e9???????? }
            // n = 7, score = 800
            //   837df800             | cmp                 dword ptr [ebp - 8], 0
            //   740a                 | je                  0xc
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al
            //   e9????????           |                     

        $sequence_5 = { 7511 c645e000 8b45e0 25ff000000 e9???????? }
            // n = 5, score = 800
            //   7511                 | jne                 0x13
            //   c645e000             | mov                 byte ptr [ebp - 0x20], 0
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   25ff000000           | and                 eax, 0xff
            //   e9????????           |                     

        $sequence_6 = { 8d55dc 52 ff15???????? 8d45d0 50 }
            // n = 5, score = 800
            //   8d55dc               | lea                 edx, [ebp - 0x24]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   50                   | push                eax

        $sequence_7 = { 8b4de8 894d98 8b5598 52 }
            // n = 4, score = 800
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   894d98               | mov                 dword ptr [ebp - 0x68], ecx
            //   8b5598               | mov                 edx, dword ptr [ebp - 0x68]
            //   52                   | push                edx

        $sequence_8 = { 56 57 68???????? ff15???????? 8945dc 68???????? }
            // n = 6, score = 600
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   ff15????????         |                     
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   68????????           |                     

        $sequence_9 = { ff7514 e8???????? 59 be02000080 }
            // n = 4, score = 400
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   be02000080           | mov                 esi, 0x80000002

        $sequence_10 = { 8bf8 8b45fc 33c9 6a04 6800100000 894704 894f0c }
            // n = 7, score = 400
            //   8bf8                 | mov                 edi, eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   33c9                 | xor                 ecx, ecx
            //   6a04                 | push                4
            //   6800100000           | push                0x1000
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   894f0c               | mov                 dword ptr [edi + 0xc], ecx

        $sequence_11 = { ff74240c 6a00 56 e8???????? 6a00 }
            // n = 5, score = 400
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_12 = { 85c0 7509 ff75d4 ff55d0 8975e0 834dfcff }
            // n = 6, score = 400
            //   85c0                 | test                eax, eax
            //   7509                 | jne                 0xb
            //   ff75d4               | push                dword ptr [ebp - 0x2c]
            //   ff55d0               | call                dword ptr [ebp - 0x30]
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff

        $sequence_13 = { ff7514 6a02 68???????? 50 56 e8???????? 83c41c }
            // n = 7, score = 400
            //   ff7514               | push                dword ptr [ebp + 0x14]
            //   6a02                 | push                2
            //   68????????           |                     
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c

        $sequence_14 = { ffd3 85c0 8945fc 7514 6a04 57 ff7650 }
            // n = 7, score = 400
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   7514                 | jne                 0x16
            //   6a04                 | push                4
            //   57                   | push                edi
            //   ff7650               | push                dword ptr [esi + 0x50]

        $sequence_15 = { ff742404 ff15???????? 83f8ff 750e ff15???????? 83f802 7503 }
            // n = 7, score = 400
            //   ff742404             | push                dword ptr [esp + 4]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   83f802               | cmp                 eax, 2
            //   7503                 | jne                 5

    condition:
        7 of them and filesize < 106496
}
