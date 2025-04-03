rule win_ispy_keylogger_auto {

    meta:
        id = "2FC5iVM3xZqwyQSFcDawnQ"
        fingerprint = "v1_sha256_338dc8ef8d7093a66fad889ac06c77384be00721927de4b10cc0d1a531590b05"
        version = "1"
        date = "2020-05-30"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ispy_keylogger"
        malpedia_rule_date = "20200529"
        malpedia_hash = "92c362319514e5a6da26204961446caa3a8b32a8"
        malpedia_version = "20200529"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 024a11 f8 0c91 0102 26810789030e1d }
            // n = 5, score = 100
            //   024a11               | add                 cl, byte ptr [edx + 0x11]
            //   f8                   | clc                 
            //   0c91                 | or                  al, 0x91
            //   0102                 | add                 dword ptr [edx], eax
            //   26810789030e1d       | add                 dword ptr es:[edi], 0x1d0e0389

        $sequence_1 = { 0416 24ae 0239 043b }
            // n = 4, score = 100
            //   0416                 | add                 al, 0x16
            //   24ae                 | and                 al, 0xae
            //   0239                 | add                 bh, byte ptr [ecx]
            //   043b                 | add                 al, 0x3b

        $sequence_2 = { 2813 00890396284a 0e f1 03691f 51 0e }
            // n = 7, score = 100
            //   2813                 | sub                 byte ptr [ebx], dl
            //   00890396284a         | add                 byte ptr [ecx + 0x4a289603], cl
            //   0e                   | push                cs
            //   f1                   | int1                
            //   03691f               | add                 ebp, dword ptr [ecx + 0x1f]
            //   51                   | push                ecx
            //   0e                   | push                cs

        $sequence_3 = { 0499 0477 019f09a104be 25df0c7101 3f }
            // n = 5, score = 100
            //   0499                 | add                 al, 0x99
            //   0477                 | add                 al, 0x77
            //   019f09a104be         | add                 dword ptr [edi - 0x41fb5ef7], ebx
            //   25df0c7101           | and                 eax, 0x1710cdf
            //   3f                   | aas                 

        $sequence_4 = { 090458 0988012103ea 28760e 1105???????? 54 007701 1300 }
            // n = 7, score = 100
            //   090458               | or                  dword ptr [eax + ebx*2], eax
            //   0988012103ea         | or                  dword ptr [eax - 0x15fcdeff], ecx
            //   28760e               | sub                 byte ptr [esi + 0xe], dh
            //   1105????????         |                     
            //   54                   | push                esp
            //   007701               | add                 byte ptr [edi + 1], dh
            //   1300                 | adc                 eax, dword ptr [eax]

        $sequence_5 = { 07 b104 7701 9f 095102 }
            // n = 5, score = 100
            //   07                   | pop                 es
            //   b104                 | mov                 cl, 4
            //   7701                 | ja                  3
            //   9f                   | lahf                
            //   095102               | or                  dword ptr [ecx + 2], edx

        $sequence_6 = { 0c61 04bc 24d5 006104 f323410c 61 04d4 }
            // n = 7, score = 100
            //   0c61                 | or                  al, 0x61
            //   04bc                 | add                 al, 0xbc
            //   24d5                 | and                 al, 0xd5
            //   006104               | add                 byte ptr [ecx + 4], ah
            //   f323410c             | and                 eax, dword ptr [ecx + 0xc]
            //   61                   | popal               
            //   04d4                 | add                 al, 0xd4

        $sequence_7 = { 009101102681 07 b104 7701 9f 095102 }
            // n = 6, score = 100
            //   009101102681         | add                 byte ptr [ecx - 0x7ed9efff], dl
            //   07                   | pop                 es
            //   b104                 | mov                 cl, 4
            //   7701                 | ja                  3
            //   9f                   | lahf                
            //   095102               | or                  dword ptr [ecx + 2], edx

        $sequence_8 = { f323410c 61 04d4 2448 0c61 04e6 }
            // n = 6, score = 100
            //   f323410c             | and                 eax, dword ptr [ecx + 0xc]
            //   61                   | popal               
            //   04d4                 | add                 al, 0xd4
            //   2448                 | and                 al, 0x48
            //   0c61                 | or                  al, 0x61
            //   04e6                 | add                 al, 0xe6

        $sequence_9 = { 2813 00890396284a 0e f1 }
            // n = 4, score = 100
            //   2813                 | sub                 byte ptr [ebx], dl
            //   00890396284a         | add                 byte ptr [ecx + 0x4a289603], cl
            //   0e                   | push                cs
            //   f1                   | int1                

    condition:
        7 of them and filesize < 212992
}
