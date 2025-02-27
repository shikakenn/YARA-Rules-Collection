rule win_blackremote_auto {

    meta:
        id = "3kiTF4otCftI7aGAuLts7"
        fingerprint = "v1_sha256_925f94fc6d52e8e387a337971bb2b032850454ad74aeab9a7e0150509f261106"
        version = "1"
        date = "2020-05-30"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.4.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackremote"
        malpedia_rule_date = "20200529"
        malpedia_hash = "92c362319514e5a6da26204961446caa3a8b32a8"
        malpedia_version = "20200529"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c8204500 0800 cc 20c5 050800e420 }
            // n = 5, score = 100
            //   c8204500             | enter               0x4520, 0
            //   0800                 | or                  byte ptr [eax], al
            //   cc                   | int3                
            //   20c5                 | and                 ch, al
            //   050800e420           | add                 eax, 0x20e40008

        $sequence_1 = { 0e 0800 60 2137 }
            // n = 4, score = 100
            //   0e                   | push                cs
            //   0800                 | or                  byte ptr [eax], al
            //   60                   | pushal              
            //   2137                 | and                 dword ptr [edi], esi

        $sequence_2 = { f5 3b00 1f f9 }
            // n = 4, score = 100
            //   f5                   | cmc                 
            //   3b00                 | cmp                 eax, dword ptr [eax]
            //   1f                   | pop                 ds
            //   f9                   | stc                 

        $sequence_3 = { 49 5e 0800 1c20 4e 5e }
            // n = 6, score = 100
            //   49                   | dec                 ecx
            //   5e                   | pop                 esi
            //   0800                 | or                  byte ptr [eax], al
            //   1c20                 | sbb                 al, 0x20
            //   4e                   | dec                 esi
            //   5e                   | pop                 esi

        $sequence_4 = { cc 20c5 050800e420 5f 0a08 00e8 }
            // n = 6, score = 100
            //   cc                   | int3                
            //   20c5                 | and                 ch, al
            //   050800e420           | add                 eax, 0x20e40008
            //   5f                   | pop                 edi
            //   0a08                 | or                  cl, byte ptr [eax]
            //   00e8                 | add                 al, ch

        $sequence_5 = { 98 23d1 3808 009c23d6380800 a0???????? 00a423e0380800 a823 }
            // n = 7, score = 100
            //   98                   | cwde                
            //   23d1                 | and                 edx, ecx
            //   3808                 | cmp                 byte ptr [eax], cl
            //   009c23d6380800       | add                 byte ptr [ebx + 0x838d6], bl
            //   a0????????           |                     
            //   00a423e0380800       | add                 byte ptr [ebx + 0x838e0], ah
            //   a823                 | test                al, 0x23

        $sequence_6 = { 3808 00b423e5380800 b823b96408 00bc23be640800 }
            // n = 4, score = 100
            //   3808                 | cmp                 byte ptr [eax], cl
            //   00b423e5380800       | add                 byte ptr [ebx + 0x838e5], dh
            //   b823b96408           | mov                 eax, 0x864b923
            //   00bc23be640800       | add                 byte ptr [ebx + 0x864be], bh

        $sequence_7 = { c505???????? ac 0a08 008023b10a08 008423b60a0800 8823 bb0a080090 }
            // n = 7, score = 100
            //   c505????????         |                     
            //   ac                   | lodsb               al, byte ptr [esi]
            //   0a08                 | or                  cl, byte ptr [eax]
            //   008023b10a08         | add                 byte ptr [eax + 0x80ab123], al
            //   008423b60a0800       | add                 byte ptr [ebx + 0x80ab6], al
            //   8823                 | mov                 byte ptr [ebx], ah
            //   bb0a080090           | mov                 ebx, 0x9000080a

        $sequence_8 = { 22b10a08003c 22b60a080040 22bb0a080064 235f0a }
            // n = 4, score = 100
            //   22b10a08003c         | and                 dh, byte ptr [ecx + 0x3c00080a]
            //   22b60a080040         | and                 dh, byte ptr [esi + 0x4000080a]
            //   22bb0a080064         | and                 bh, byte ptr [ebx + 0x6400080a]
            //   235f0a               | and                 ebx, dword ptr [edi + 0xa]

        $sequence_9 = { 2002 5f 0800 b020 07 5f 0800 }
            // n = 7, score = 100
            //   2002                 | and                 byte ptr [edx], al
            //   5f                   | pop                 edi
            //   0800                 | or                  byte ptr [eax], al
            //   b020                 | mov                 al, 0x20
            //   07                   | pop                 es
            //   5f                   | pop                 edi
            //   0800                 | or                  byte ptr [eax], al

    condition:
        7 of them and filesize < 1934336
}
