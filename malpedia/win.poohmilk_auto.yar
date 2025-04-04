rule win_poohmilk_auto {

    meta:
        id = "23y0AsVEtBLYeEIud2jrK7"
        fingerprint = "v1_sha256_f0431f01a34a1352435470a98d80c3656cef1cd2a7cc3eb4ac4c25c7f03235a9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.poohmilk."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poohmilk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f4 98 40 0020 99 40 00449940 }
            // n = 7, score = 200
            //   f4                   | hlt                 
            //   98                   | cwde                
            //   40                   | inc                 eax
            //   0020                 | add                 byte ptr [eax], ah
            //   99                   | cdq                 
            //   40                   | inc                 eax
            //   00449940             | add                 byte ptr [ecx + ebx*4 + 0x40], al

        $sequence_1 = { 3b8de4efffff 7405 83f901 7577 8b502a }
            // n = 5, score = 200
            //   3b8de4efffff         | cmp                 ecx, dword ptr [ebp - 0x101c]
            //   7405                 | je                  7
            //   83f901               | cmp                 ecx, 1
            //   7577                 | jne                 0x79
            //   8b502a               | mov                 edx, dword ptr [eax + 0x2a]

        $sequence_2 = { 74dc 8bb5acfdffff 8bc6 0b85b0fdffff }
            // n = 4, score = 200
            //   74dc                 | je                  0xffffffde
            //   8bb5acfdffff         | mov                 esi, dword ptr [ebp - 0x254]
            //   8bc6                 | mov                 eax, esi
            //   0b85b0fdffff         | or                  eax, dword ptr [ebp - 0x250]

        $sequence_3 = { 33ff 397e38 0f8583000000 397e14 757e 397e1c }
            // n = 6, score = 200
            //   33ff                 | xor                 edi, edi
            //   397e38               | cmp                 dword ptr [esi + 0x38], edi
            //   0f8583000000         | jne                 0x89
            //   397e14               | cmp                 dword ptr [esi + 0x14], edi
            //   757e                 | jne                 0x80
            //   397e1c               | cmp                 dword ptr [esi + 0x1c], edi

        $sequence_4 = { 8bd6 0bd7 0f85ae000000 8b9570d2ffff 8b5238 }
            // n = 5, score = 200
            //   8bd6                 | mov                 edx, esi
            //   0bd7                 | or                  edx, edi
            //   0f85ae000000         | jne                 0xb4
            //   8b9570d2ffff         | mov                 edx, dword ptr [ebp - 0x2d90]
            //   8b5238               | mov                 edx, dword ptr [edx + 0x38]

        $sequence_5 = { 6880000000 6a03 6a00 6a07 6800000080 56 ff15???????? }
            // n = 7, score = 200
            //   6880000000           | push                0x80
            //   6a03                 | push                3
            //   6a00                 | push                0
            //   6a07                 | push                7
            //   6800000080           | push                0x80000000
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_6 = { 0f8574020000 0fb79d02f0ffff 0fb79500f0ffff 895e10 3bda 0f855b020000 }
            // n = 6, score = 200
            //   0f8574020000         | jne                 0x27a
            //   0fb79d02f0ffff       | movzx               ebx, word ptr [ebp - 0xffe]
            //   0fb79500f0ffff       | movzx               edx, word ptr [ebp - 0x1000]
            //   895e10               | mov                 dword ptr [esi + 0x10], ebx
            //   3bda                 | cmp                 ebx, edx
            //   0f855b020000         | jne                 0x261

        $sequence_7 = { 7425 56 ff15???????? 8b856cf3ffff }
            // n = 4, score = 200
            //   7425                 | je                  0x27
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b856cf3ffff         | mov                 eax, dword ptr [ebp - 0xc94]

        $sequence_8 = { ffd3 8d85a0f3ffff 50 8d8decfdffff 51 ffd3 }
            // n = 6, score = 200
            //   ffd3                 | call                ebx
            //   8d85a0f3ffff         | lea                 eax, [ebp - 0xc60]
            //   50                   | push                eax
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   51                   | push                ecx
            //   ffd3                 | call                ebx

        $sequence_9 = { ffd3 6a00 8d85ecfdffff 50 }
            // n = 4, score = 200
            //   ffd3                 | call                ebx
            //   6a00                 | push                0
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 245760
}
