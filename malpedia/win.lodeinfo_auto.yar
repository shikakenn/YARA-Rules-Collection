rule win_lodeinfo_auto {

    meta:
        id = "1BLhwNJ4koMLloJ2X6RYJ1"
        fingerprint = "v1_sha256_e42d005c217ef3b217f52a6115c139a42c70e499d47cac23508862c48ef328f6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lodeinfo."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lodeinfo"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 898300010000 8b8558ffffff c7837001000000000000 e9???????? ba???????? 8bcf e8???????? }
            // n = 7, score = 200
            //   898300010000         | mov                 dword ptr [ebx + 0x100], eax
            //   8b8558ffffff         | mov                 eax, dword ptr [ebp - 0xa8]
            //   c7837001000000000000     | mov    dword ptr [ebx + 0x170], 0
            //   e9????????           |                     
            //   ba????????           |                     
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_1 = { 75a8 8b55e4 8b7d14 8b4508 3bcf 0f84440a0000 }
            // n = 6, score = 200
            //   75a8                 | jne                 0xffffffaa
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   3bcf                 | cmp                 ecx, edi
            //   0f84440a0000         | je                  0xa4a

        $sequence_2 = { 3bf2 743f 50 ffb548ffffff 51 8b8d5cffffff 8bd1 }
            // n = 7, score = 200
            //   3bf2                 | cmp                 esi, edx
            //   743f                 | je                  0x41
            //   50                   | push                eax
            //   ffb548ffffff         | push                dword ptr [ebp - 0xb8]
            //   51                   | push                ecx
            //   8b8d5cffffff         | mov                 ecx, dword ptr [ebp - 0xa4]
            //   8bd1                 | mov                 edx, ecx

        $sequence_3 = { 7534 0fb64e04 0fbec3 3bc8 7529 0fb64e05 }
            // n = 6, score = 200
            //   7534                 | jne                 0x36
            //   0fb64e04             | movzx               ecx, byte ptr [esi + 4]
            //   0fbec3               | movsx               eax, bl
            //   3bc8                 | cmp                 ecx, eax
            //   7529                 | jne                 0x2b
            //   0fb64e05             | movzx               ecx, byte ptr [esi + 5]

        $sequence_4 = { 8be5 5d c3 83f806 754d 837e0408 8b4d14 }
            // n = 7, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   83f806               | cmp                 eax, 6
            //   754d                 | jne                 0x4f
            //   837e0408             | cmp                 dword ptr [esi + 4], 8
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_5 = { 0f8586000000 8d4ffc 034d08 e8???????? 8b1b 33ff 89450c }
            // n = 7, score = 200
            //   0f8586000000         | jne                 0x8c
            //   8d4ffc               | lea                 ecx, [edi - 4]
            //   034d08               | add                 ecx, dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   33ff                 | xor                 edi, edi
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax

        $sequence_6 = { 8955d4 8d1418 8b45fc 8955d8 3b5008 7641 8b4008 }
            // n = 7, score = 200
            //   8955d4               | mov                 dword ptr [ebp - 0x2c], edx
            //   8d1418               | lea                 edx, [eax + ebx]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx
            //   3b5008               | cmp                 edx, dword ptr [eax + 8]
            //   7641                 | jbe                 0x43
            //   8b4008               | mov                 eax, dword ptr [eax + 8]

        $sequence_7 = { e8???????? 84c0 0f8481000000 83fe09 0f8592020000 8bb554ffffff }
            // n = 6, score = 200
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f8481000000         | je                  0x87
            //   83fe09               | cmp                 esi, 9
            //   0f8592020000         | jne                 0x298
            //   8bb554ffffff         | mov                 esi, dword ptr [ebp - 0xac]

        $sequence_8 = { 024df4 8b45c4 880c30 8bc3 0fb64dfc 2bc1 99 }
            // n = 7, score = 200
            //   024df4               | add                 cl, byte ptr [ebp - 0xc]
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   880c30               | mov                 byte ptr [eax + esi], cl
            //   8bc3                 | mov                 eax, ebx
            //   0fb64dfc             | movzx               ecx, byte ptr [ebp - 4]
            //   2bc1                 | sub                 eax, ecx
            //   99                   | cdq                 

        $sequence_9 = { e8???????? ff75bc e8???????? ff75c0 e8???????? ff75cc }
            // n = 6, score = 200
            //   e8????????           |                     
            //   ff75bc               | push                dword ptr [ebp - 0x44]
            //   e8????????           |                     
            //   ff75c0               | push                dword ptr [ebp - 0x40]
            //   e8????????           |                     
            //   ff75cc               | push                dword ptr [ebp - 0x34]

    condition:
        7 of them and filesize < 712704
}
