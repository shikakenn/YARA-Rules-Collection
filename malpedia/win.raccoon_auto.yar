rule win_raccoon_auto {

    meta:
        id = "7DrgkuioRfgZoHyAlfCfk5"
        fingerprint = "v1_sha256_490a547d291c29560eb0a750de21265ccd9b82463cd0d04b08babd8cc5f3ca9a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.raccoon."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.raccoon"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 59 85c0 7505 8a07 8806 46 }
            // n = 7, score = 2400
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   8a07                 | mov                 al, byte ptr [edi]
            //   8806                 | mov                 byte ptr [esi], al
            //   46                   | inc                 esi

        $sequence_1 = { 85ff 7464 833e00 53 }
            // n = 4, score = 2400
            //   85ff                 | test                edi, edi
            //   7464                 | je                  0x66
            //   833e00               | cmp                 dword ptr [esi], 0
            //   53                   | push                ebx

        $sequence_2 = { 7437 837b1410 7202 8b1b 837f1410 7202 8b3f }
            // n = 7, score = 2400
            //   7437                 | je                  0x39
            //   837b1410             | cmp                 dword ptr [ebx + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b1b                 | mov                 ebx, dword ptr [ebx]
            //   837f1410             | cmp                 dword ptr [edi + 0x14], 0x10
            //   7202                 | jb                  4
            //   8b3f                 | mov                 edi, dword ptr [edi]

        $sequence_3 = { 897dec 3b7de4 75bf 83f9fa 7e1e 83c108 c1e308 }
            // n = 7, score = 2400
            //   897dec               | mov                 dword ptr [ebp - 0x14], edi
            //   3b7de4               | cmp                 edi, dword ptr [ebp - 0x1c]
            //   75bf                 | jne                 0xffffffc1
            //   83f9fa               | cmp                 ecx, -6
            //   7e1e                 | jle                 0x20
            //   83c108               | add                 ecx, 8
            //   c1e308               | shl                 ebx, 8

        $sequence_4 = { 8bf0 59 85f6 742d 8d4514 50 }
            // n = 6, score = 2400
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx
            //   85f6                 | test                esi, esi
            //   742d                 | je                  0x2f
            //   8d4514               | lea                 eax, [ebp + 0x14]
            //   50                   | push                eax

        $sequence_5 = { 57 8b7d0c 8955f8 894df4 85ff 7403 832700 }
            // n = 7, score = 2400
            //   57                   | push                edi
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8955f8               | mov                 dword ptr [ebp - 8], edx
            //   894df4               | mov                 dword ptr [ebp - 0xc], ecx
            //   85ff                 | test                edi, edi
            //   7403                 | je                  5
            //   832700               | and                 dword ptr [edi], 0

        $sequence_6 = { 03ce e8???????? 8d4dd4 e8???????? 8b4df4 8bc6 }
            // n = 6, score = 2400
            //   03ce                 | add                 ecx, esi
            //   e8????????           |                     
            //   8d4dd4               | lea                 ecx, [ebp - 0x2c]
            //   e8????????           |                     
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { e8???????? 89450c 85c0 0f8486000000 53 8b1d???????? 68???????? }
            // n = 7, score = 2400
            //   e8????????           |                     
            //   89450c               | mov                 dword ptr [ebp + 0xc], eax
            //   85c0                 | test                eax, eax
            //   0f8486000000         | je                  0x8c
            //   53                   | push                ebx
            //   8b1d????????         |                     
            //   68????????           |                     

        $sequence_8 = { 56 57 ff15???????? 8b35???????? 57 ffd6 ff75e8 }
            // n = 7, score = 2400
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   57                   | push                edi
            //   ffd6                 | call                esi
            //   ff75e8               | push                dword ptr [ebp - 0x18]

        $sequence_9 = { 8bcf e8???????? 59 59 8d7301 56 ff15???????? }
            // n = 7, score = 2400
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8d7301               | lea                 esi, [ebx + 1]
            //   56                   | push                esi
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 1212416
}
