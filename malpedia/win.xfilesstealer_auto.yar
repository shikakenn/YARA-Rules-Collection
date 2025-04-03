rule win_xfilesstealer_auto {

    meta:
        id = "2pprb6S3U7CgKrH9JnIjyf"
        fingerprint = "v1_sha256_138d1abd0a6a4049681c2efa03d515f66cec169dd57e831e33b1e8811e6e1990"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.xfilesstealer."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfilesstealer"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7505 488b1b ebc7 c707bd0000c0 e9???????? 8907 e9???????? }
            // n = 7, score = 100
            //   7505                 | dec                 eax
            //   488b1b               | mov                 esi, edx
            //   ebc7                 | dec                 eax
            //   c707bd0000c0         | mov                 ecx, edi
            //   e9????????           |                     
            //   8907                 | lea                 ebx, [eax + 1]
            //   e9????????           |                     

        $sequence_1 = { f30f7f4510 48897d20 4533c9 448d4703 488d5510 488d8df0010000 e8???????? }
            // n = 7, score = 100
            //   f30f7f4510           | and                 dword ptr [esp + 0x20], 0
            //   48897d20             | inc                 ebp
            //   4533c9               | xor                 ecx, ecx
            //   448d4703             | dec                 esp
            //   488d5510             | mov                 eax, ebp
            //   488d8df0010000       | dec                 ecx
            //   e8????????           |                     

        $sequence_2 = { e8???????? 488bd0 4c8bc3 488d8dd0030000 e8???????? 488d15210a3200 488d4da0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bd0               | mov                 dword ptr [ebp - 0x40], eax
            //   4c8bc3               | dec                 eax
            //   488d8dd0030000       | lea                 eax, [0x70ad9d]
            //   e8????????           |                     
            //   488d15210a3200       | push                edi
            //   488d4da0             | dec                 eax

        $sequence_3 = { e8???????? 90 837c244800 7424 488b742440 4885f6 7415 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   90                   | je                  0x2e3
            //   837c244800           | sub                 edx, 2
            //   7424                 | je                  0x2df
            //   488b742440           | sub                 edx, 1
            //   4885f6               | je                  0x2d8
            //   7415                 | je                  0x2fb

        $sequence_4 = { e8???????? 85c0 784b 8b05???????? 83f82d 0f83a6e81c00 8b4c8320 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | je                  0x1227
            //   784b                 | mov                 dword ptr [ebp - 0x10], 1
            //   8b05????????         |                     
            //   83f82d               | bts                 dword ptr [edi + 0x14], 0x1f
            //   0f83a6e81c00         | xor                 eax, eax
            //   8b4c8320             | dec                 ecx

        $sequence_5 = { e8???????? 89442474 448b45d8 4533d2 488bcf e8???????? f7d8 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   89442474             | mov                 edx, eax
            //   448b45d8             | dec                 ecx
            //   4533d2               | mov                 ecx, esi
            //   488bcf               | int3                
            //   e8????????           |                     
            //   f7d8                 | je                  0x218

        $sequence_6 = { e8???????? 8bd8 85c0 791e e9???????? ff15???????? cc }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bd8                 | test                eax, eax
            //   85c0                 | je                  0xa96
            //   791e                 | inc                 esp
            //   e9????????           |                     
            //   ff15????????         |                     
            //   cc                   | mov                 dword ptr [esi + 0xc], esp

        $sequence_7 = { ffd3 85c0 0f8868010000 498b9630020000 488b4de0 4883c203 e8???????? }
            // n = 7, score = 100
            //   ffd3                 | jne                 0xe73
            //   85c0                 | dec                 eax
            //   0f8868010000         | and                 dword ptr [ebp - 0x20], 0
            //   498b9630020000       | and                 dword ptr [ebp - 0x18], 0
            //   488b4de0             | test                eax, eax
            //   4883c203             | js                  0xead
            //   e8????????           |                     

        $sequence_8 = { 83ea2f 7422 83ea01 0f8486fa2e00 83fa01 0f8427120600 498d48fe }
            // n = 7, score = 100
            //   83ea2f               | dec                 eax
            //   7422                 | lea                 ecx, [ebp - 0x30]
            //   83ea01               | test                eax, eax
            //   0f8486fa2e00         | je                  0x147d
            //   83fa01               | dec                 eax
            //   0f8427120600         | mov                 eax, dword ptr [ebp - 0x40]
            //   498d48fe             | dec                 eax

        $sequence_9 = { e8???????? 8bf8 85c0 781d 498bce 395d50 7409 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bf8                 | test                byte ptr [ebx + 3], 4
            //   85c0                 | jne                 0xfff3f82c
            //   781d                 | dec                 eax
            //   498bce               | mov                 ecx, ebx
            //   395d50               | je                  0x3e5
            //   7409                 | and                 eax, 0xc0000

    condition:
        7 of them and filesize < 20821780
}
