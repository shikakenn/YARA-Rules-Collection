rule win_oderoor_auto {

    meta:
        id = "4Olkt4YeFszb0YGD5gadpK"
        fingerprint = "v1_sha256_705d5b4a266b0c2f312f72fd5cb1e86ab39ec049fd53173701ccf137ec51b933"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.oderoor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oderoor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 2deb1427d9 8c2413 b166 3b01 95 1e c194a0c0b855158d }
            // n = 7, score = 100
            //   2deb1427d9           | sub                 eax, 0xd92714eb
            //   8c2413               | mov                 word ptr [ebx + edx], fs
            //   b166                 | mov                 cl, 0x66
            //   3b01                 | cmp                 eax, dword ptr [ecx]
            //   95                   | xchg                eax, ebp
            //   1e                   | push                ds
            //   c194a0c0b855158d     | rcl                 dword ptr [eax + 0x1555b8c0], 0x8d

        $sequence_1 = { f8 660fbdd9 6611e5 e8???????? 54 }
            // n = 5, score = 100
            //   f8                   | clc                 
            //   660fbdd9             | bsr                 bx, cx
            //   6611e5               | adc                 bp, sp
            //   e8????????           |                     
            //   54                   | push                esp

        $sequence_2 = { e9???????? 6689442404 c1ce06 9c 9c 8d642440 e9???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   6689442404           | mov                 word ptr [esp + 4], ax
            //   c1ce06               | ror                 esi, 6
            //   9c                   | pushfd              
            //   9c                   | pushfd              
            //   8d642440             | lea                 esp, [esp + 0x40]
            //   e9????????           |                     

        $sequence_3 = { 69d20a000000 e8???????? 38f4 c0f304 c1c31c 660fbafb02 89c3 }
            // n = 7, score = 100
            //   69d20a000000         | imul                edx, edx, 0xa
            //   e8????????           |                     
            //   38f4                 | cmp                 ah, dh
            //   c0f304               | sal                 bl, 4
            //   c1c31c               | rol                 ebx, 0x1c
            //   660fbafb02           | btc                 bx, 2
            //   89c3                 | mov                 ebx, eax

        $sequence_4 = { 686c193202 e8???????? 309c865a407526 b3df e04a 9b 68d69156e5 }
            // n = 7, score = 100
            //   686c193202           | push                0x232196c
            //   e8????????           |                     
            //   309c865a407526       | xor                 byte ptr [esi + eax*4 + 0x2675405a], bl
            //   b3df                 | mov                 bl, 0xdf
            //   e04a                 | loopne              0x4c
            //   9b                   | wait                
            //   68d69156e5           | push                0xe55691d6

        $sequence_5 = { 2b984e407fc0 c5adcaa19a9e 1882c1c921d4 06 ed }
            // n = 5, score = 100
            //   2b984e407fc0         | sub                 ebx, dword ptr [eax - 0x3f80bfb2]
            //   c5adcaa19a9e         | lds                 ebp, ptr [ebp - 0x61655e36]
            //   1882c1c921d4         | sbb                 byte ptr [edx - 0x2bde363f], al
            //   06                   | push                es
            //   ed                   | in                  eax, dx

        $sequence_6 = { df570e 29dc 9b 7f65 197e7e a2???????? }
            // n = 6, score = 100
            //   df570e               | fist                word ptr [edi + 0xe]
            //   29dc                 | sub                 esp, ebx
            //   9b                   | wait                
            //   7f65                 | jg                  0x67
            //   197e7e               | sbb                 dword ptr [esi + 0x7e], edi
            //   a2????????           |                     

        $sequence_7 = { 0fbae107 0428 55 895c240c f6d0 660fbae70f 9c }
            // n = 7, score = 100
            //   0fbae107             | bt                  ecx, 7
            //   0428                 | add                 al, 0x28
            //   55                   | push                ebp
            //   895c240c             | mov                 dword ptr [esp + 0xc], ebx
            //   f6d0                 | not                 al
            //   660fbae70f           | bt                  di, 0xf
            //   9c                   | pushfd              

        $sequence_8 = { 8d642410 e9???????? 66891407 881424 9c 68f4110af5 }
            // n = 6, score = 100
            //   8d642410             | lea                 esp, [esp + 0x10]
            //   e9????????           |                     
            //   66891407             | mov                 word ptr [edi + eax], dx
            //   881424               | mov                 byte ptr [esp], dl
            //   9c                   | pushfd              
            //   68f4110af5           | push                0xf50a11f4

        $sequence_9 = { f1 6c aa 620b e3ed e28f 1a00 }
            // n = 7, score = 100
            //   f1                   | int1                
            //   6c                   | insb                byte ptr es:[edi], dx
            //   aa                   | stosb               byte ptr es:[edi], al
            //   620b                 | bound               ecx, qword ptr [ebx]
            //   e3ed                 | jecxz               0xffffffef
            //   e28f                 | loop                0xffffff91
            //   1a00                 | sbb                 al, byte ptr [eax]

    condition:
        7 of them and filesize < 13688832
}
