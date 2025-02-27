rule win_sdbbot_auto {

    meta:
        id = "5vO70BQQe3WQL4n79ZNs9r"
        fingerprint = "v1_sha256_869a5323254bb19be34889ba3dd9fff300dc452318f40f9c34e9c0c7014796e1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sdbbot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sdbbot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bf0 56 8975fc ff55ec }
            // n = 4, score = 700
            //   8bf0                 | mov                 esi, eax
            //   56                   | push                esi
            //   8975fc               | mov                 dword ptr [ebp - 4], esi
            //   ff55ec               | call                dword ptr [ebp - 0x14]

        $sequence_1 = { 81f95bbc4a6a 0f85cf000000 8b5dfc bf04000000 8b7310 8b463c 8b443078 }
            // n = 7, score = 700
            //   81f95bbc4a6a         | cmp                 ecx, 0x6a4abc5b
            //   0f85cf000000         | jne                 0xd5
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   bf04000000           | mov                 edi, 4
            //   8b7310               | mov                 esi, dword ptr [ebx + 0x10]
            //   8b463c               | mov                 eax, dword ptr [esi + 0x3c]
            //   8b443078             | mov                 eax, dword ptr [eax + esi + 0x78]

        $sequence_2 = { ff55e8 8bd8 85db 7460 }
            // n = 4, score = 700
            //   ff55e8               | call                dword ptr [ebp - 0x18]
            //   8bd8                 | mov                 ebx, eax
            //   85db                 | test                ebx, ebx
            //   7460                 | je                  0x62

        $sequence_3 = { 8b75fc 8b7dec 83c714 897dec 833f00 }
            // n = 5, score = 700
            //   8b75fc               | mov                 esi, dword ptr [ebp - 4]
            //   8b7dec               | mov                 edi, dword ptr [ebp - 0x14]
            //   83c714               | add                 edi, 0x14
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   833f00               | cmp                 dword ptr [edi], 0

        $sequence_4 = { 33c9 8a02 660f1f440000 c1c90d 8d5201 }
            // n = 5, score = 700
            //   33c9                 | xor                 ecx, ecx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   660f1f440000         | nop                 word ptr [eax + eax]
            //   c1c90d               | ror                 ecx, 0xd
            //   8d5201               | lea                 edx, [edx + 1]

        $sequence_5 = { 8b5b10 8b433c 8b441878 03c3 8945dc }
            // n = 5, score = 700
            //   8b5b10               | mov                 ebx, dword ptr [ebx + 0x10]
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   8b441878             | mov                 eax, dword ptr [eax + ebx + 0x78]
            //   03c3                 | add                 eax, ebx
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax

        $sequence_6 = { 84c0 75ef 81f9b80a4c53 7521 8b45dc 0fb70e }
            // n = 6, score = 700
            //   84c0                 | test                al, al
            //   75ef                 | jne                 0xfffffff1
            //   81f9b80a4c53         | cmp                 ecx, 0x534c0ab8
            //   7521                 | jne                 0x23
            //   8b45dc               | mov                 eax, dword ptr [ebp - 0x24]
            //   0fb70e               | movzx               ecx, word ptr [esi]

        $sequence_7 = { 81c2ffff0000 03cf 46 6685d2 }
            // n = 4, score = 700
            //   81c2ffff0000         | add                 edx, 0xffff
            //   03cf                 | add                 ecx, edi
            //   46                   | inc                 esi
            //   6685d2               | test                dx, dx

        $sequence_8 = { c3 803d????????00 750c c605????????01 }
            // n = 4, score = 400
            //   c3                   | ret                 
            //   803d????????00       |                     
            //   750c                 | jne                 0xe
            //   c605????????01       |                     

        $sequence_9 = { 0fb602 84c0 75ed 81f9b80a4c53 751b }
            // n = 5, score = 300
            //   0fb602               | cmove               eax, esi
            //   84c0                 | je                  0x36
            //   75ed                 | mov                 eax, dword ptr [ebp - 8]
            //   81f9b80a4c53         | add                 edi, 0x2c
            //   751b                 | mov                 ecx, dword ptr [edi - 8]

        $sequence_10 = { 488b5c2478 41bb01000000 4d85f6 7414 }
            // n = 4, score = 300
            //   488b5c2478           | mov                 dword ptr [esp + 0x80], esi
            //   41bb01000000         | inc                 ecx
            //   4d85f6               | mov                 ebp, 4
            //   7414                 | cmp                 eax, 0x3cfa685d

        $sequence_11 = { 49ffca 0fb7ca 0fb7c2 66c1e90c 6683f90a 7514 }
            // n = 6, score = 300
            //   49ffca               | dec                 eax
            //   0fb7ca               | mov                 ebx, dword ptr [esp + 0x78]
            //   0fb7c2               | movzx               eax, byte ptr [edx]
            //   66c1e90c             | nop                 dword ptr [eax + eax]
            //   6683f90a             | ror                 ecx, 0xd
            //   7514                 | dec                 eax

        $sequence_12 = { 0fb602 0f1f440000 c1c90d 488d5201 0fbec0 03c8 }
            // n = 6, score = 300
            //   0fb602               | inc                 ecx
            //   0f1f440000           | mov                 byte ptr [eax + ecx], al
            //   c1c90d               | dec                 eax
            //   488d5201             | lea                 ecx, [ecx + 1]
            //   0fbec0               | inc                 bp
            //   03c8                 | test                ebx, ebx

        $sequence_13 = { 4c89b42480000000 41bd04000000 e9???????? 3d5d68fa3c 0f859e000000 4d8b5720 }
            // n = 6, score = 300
            //   4c89b42480000000     | jne                 0xffffffae
            //   41bd04000000         | dec                 esp
            //   e9????????           |                     
            //   3d5d68fa3c           | mov                 esi, dword ptr [esp + 0x80]
            //   0f859e000000         | inc                 ecx
            //   4d8b5720             | mov                 ecx, 0xffff

        $sequence_14 = { 664585db 75ac 4c8bb42480000000 41b9ffff0000 488b5c2478 }
            // n = 5, score = 300
            //   664585db             | dec                 ebp
            //   75ac                 | mov                 eax, esi
            //   4c8bb42480000000     | dec                 ebp
            //   41b9ffff0000         | sub                 eax, ebp
            //   488b5c2478           | movzx               eax, byte ptr [ecx]

        $sequence_15 = { 4963553c 488d4ac0 4881f9bf030000 770a 42813c2a50450000 7405 }
            // n = 6, score = 300
            //   4963553c             | dec                 ecx
            //   488d4ac0             | arpl                word ptr [ebp + 0x3c], dx
            //   4881f9bf030000       | dec                 eax
            //   770a                 | lea                 ecx, [edx - 0x40]
            //   42813c2a50450000     | dec                 eax
            //   7405                 | cmp                 ecx, 0x3bf

        $sequence_16 = { 4885d2 7417 4d8bc6 4d2bc5 0fb601 41880408 488d4901 }
            // n = 7, score = 300
            //   4885d2               | ja                  0xc
            //   7417                 | inc                 edx
            //   4d8bc6               | cmp                 dword ptr [edx + ebp], 0x4550
            //   4d2bc5               | je                  7
            //   0fb601               | dec                 eax
            //   41880408             | test                edx, edx
            //   488d4901             | je                  0x1c

    condition:
        7 of them and filesize < 1015808
}
