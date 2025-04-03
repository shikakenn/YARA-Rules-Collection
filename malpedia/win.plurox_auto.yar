rule win_plurox_auto {

    meta:
        id = "4Tqy9eVpFalseutPl6Ivs6"
        fingerprint = "v1_sha256_fa579257df25509063a4df447932e0b25e6ea4c45a2af23b4dfc95998427a19a"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.plurox."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.plurox"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 0416 128bc606091a f6870f1a000000 e10d 21c9 8918 }
            // n = 6, score = 100
            //   0416                 | add                 al, 0x16
            //   128bc606091a         | adc                 cl, byte ptr [ebx + 0x1a0906c6]
            //   f6870f1a000000       | test                byte ptr [edi + 0x1a0f], 0
            //   e10d                 | loope               0xf
            //   21c9                 | and                 ecx, ecx
            //   8918                 | mov                 dword ptr [eax], ebx

        $sequence_1 = { 0a20 0816 ec bbf2000000 }
            // n = 4, score = 100
            //   0a20                 | or                  ah, byte ptr [eax]
            //   0816                 | or                  byte ptr [esi], dl
            //   ec                   | in                  al, dx
            //   bbf2000000           | mov                 ebx, 0xf2

        $sequence_2 = { 300f 353e0fee3c 031e 2200 }
            // n = 4, score = 100
            //   300f                 | xor                 byte ptr [edi], cl
            //   353e0fee3c           | xor                 eax, 0x3cee0f3e
            //   031e                 | add                 ebx, dword ptr [esi]
            //   2200                 | and                 al, byte ptr [eax]

        $sequence_3 = { 624a8b 0416 128bc606091a f6870f1a000000 e10d 21c9 }
            // n = 6, score = 100
            //   624a8b               | bound               ecx, qword ptr [edx - 0x75]
            //   0416                 | add                 al, 0x16
            //   128bc606091a         | adc                 cl, byte ptr [ebx + 0x1a0906c6]
            //   f6870f1a000000       | test                byte ptr [edi + 0x1a0f], 0
            //   e10d                 | loope               0xf
            //   21c9                 | and                 ecx, ecx

        $sequence_4 = { 94 f8 21480e 2a15???????? 6f }
            // n = 5, score = 100
            //   94                   | xchg                eax, esp
            //   f8                   | clc                 
            //   21480e               | and                 dword ptr [eax + 0xe], ecx
            //   2a15????????         |                     
            //   6f                   | outsd               dx, dword ptr [esi]

        $sequence_5 = { 6808486409 58 0000 00e4 0487 58 }
            // n = 6, score = 100
            //   6808486409           | push                0x9644808
            //   58                   | pop                 eax
            //   0000                 | add                 byte ptr [eax], al
            //   00e4                 | add                 ah, ah
            //   0487                 | add                 al, 0x87
            //   58                   | pop                 eax

        $sequence_6 = { 0925???????? 0000 c48dcd713240 89f5 }
            // n = 4, score = 100
            //   0925????????         |                     
            //   0000                 | add                 byte ptr [eax], al
            //   c48dcd713240         | les                 ecx, ptr [ebp + 0x403271cd]
            //   89f5                 | mov                 ebp, esi

        $sequence_7 = { 0416 128bc606091a f6870f1a000000 e10d }
            // n = 4, score = 100
            //   0416                 | add                 al, 0x16
            //   128bc606091a         | adc                 cl, byte ptr [ebx + 0x1a0906c6]
            //   f6870f1a000000       | test                byte ptr [edi + 0x1a0f], 0
            //   e10d                 | loope               0xf

        $sequence_8 = { 0442 6808486409 58 0000 }
            // n = 4, score = 100
            //   0442                 | add                 al, 0x42
            //   6808486409           | push                0x9644808
            //   58                   | pop                 eax
            //   0000                 | add                 byte ptr [eax], al

        $sequence_9 = { 0d04b8ca08 6af3 dac9 0000 00ee }
            // n = 5, score = 100
            //   0d04b8ca08           | or                  eax, 0x8cab804
            //   6af3                 | push                -0xd
            //   dac9                 | fcmove              st(0), st(1)
            //   0000                 | add                 byte ptr [eax], al
            //   00ee                 | add                 dh, ch

    condition:
        7 of them and filesize < 475136
}
