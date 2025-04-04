rule win_windealer_auto {

    meta:
        id = "6Y2UqvFctoXJYLIUGNjcx6"
        fingerprint = "v1_sha256_cda4114916f5f955b9ea27c4701626023386bb93ae37a566cf799b5d0e98aca8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.windealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.windealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a01 50 56 e8???????? 83c410 8bc7 }
            // n = 6, score = 800
            //   6a01                 | push                1
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8bc7                 | mov                 eax, edi

        $sequence_1 = { ff15???????? 85c0 7407 50 ff15???????? 6a01 }
            // n = 6, score = 800
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a01                 | push                1

        $sequence_2 = { 50 56 e8???????? 83c410 8b4618 }
            // n = 5, score = 800
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]

        $sequence_3 = { 6a00 ff15???????? 85c0 7407 50 ff15???????? 6a01 }
            // n = 7, score = 800
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   50                   | push                eax
            //   ff15????????         |                     
            //   6a01                 | push                1

        $sequence_4 = { 53 56 57 68da070000 }
            // n = 4, score = 800
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   68da070000           | push                0x7da

        $sequence_5 = { 668b91d2070000 8a89d0070000 52 51 }
            // n = 4, score = 800
            //   668b91d2070000       | mov                 dx, word ptr [ecx + 0x7d2]
            //   8a89d0070000         | mov                 cl, byte ptr [ecx + 0x7d0]
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_6 = { 8b4d08 668b91d2070000 8a89d0070000 52 51 }
            // n = 5, score = 800
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   668b91d2070000       | mov                 dx, word ptr [ecx + 0x7d2]
            //   8a89d0070000         | mov                 cl, byte ptr [ecx + 0x7d0]
            //   52                   | push                edx
            //   51                   | push                ecx

        $sequence_7 = { 6a04 50 6a04 68???????? 68???????? }
            // n = 5, score = 800
            //   6a04                 | push                4
            //   50                   | push                eax
            //   6a04                 | push                4
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { 56 57 68da070000 e8???????? }
            // n = 4, score = 800
            //   56                   | push                esi
            //   57                   | push                edi
            //   68da070000           | push                0x7da
            //   e8????????           |                     

        $sequence_9 = { 8b4d08 668b91d2070000 8a89d0070000 52 }
            // n = 4, score = 800
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   668b91d2070000       | mov                 dx, word ptr [ecx + 0x7d2]
            //   8a89d0070000         | mov                 cl, byte ptr [ecx + 0x7d0]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 770048
}
