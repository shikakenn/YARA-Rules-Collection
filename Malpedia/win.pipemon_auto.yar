rule win_pipemon_auto {

    meta:
        id = "7L8jDhHE7LcHEUcqDpI2tS"
        fingerprint = "v1_sha256_81e25c1dde542bb643a4ac77dae07f1869016dd02282de1f135701fd67f912a5"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pipemon."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pipemon"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { cd29 488d0d7b120200 e8???????? 488b442428 488905???????? 488d442428 }
            // n = 6, score = 100
            //   cd29                 | jmp                 0x255
            //   488d0d7b120200       | dec                 eax
            //   e8????????           |                     
            //   488b442428           | lea                 ecx, [0x212ac]
            //   488905????????       |                     
            //   488d442428           | test                eax, eax

        $sequence_1 = { 488d0d7b120200 e8???????? 488b442428 488905???????? 488d442428 4883c008 }
            // n = 6, score = 100
            //   488d0d7b120200       | mov                 eax, 6
            //   e8????????           |                     
            //   488b442428           | dec                 eax
            //   488905????????       |                     
            //   488d442428           | lea                 edx, [0x11529]
            //   4883c008             | dec                 eax

        $sequence_2 = { ff15???????? 488bf8 c7459038020000 0f1f4000 66660f1f840000000000 488d95d0010000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488bf8               | inc                 ecx
            //   c7459038020000       | mov                 ecx, eax
            //   0f1f4000             | dec                 ecx
            //   66660f1f840000000000     | add    ecx, esi
            //   488d95d0010000       | movsd               qword ptr [esp + 0x20], xmm0

        $sequence_3 = { c745ef41445641 33f6 488945e3 8975df }
            // n = 4, score = 100
            //   c745ef41445641       | dec                 eax
            //   33f6                 | shl                 esi, 2
            //   488945e3             | movzx               eax, word ptr [ecx + edi*4 + 0x205b0]
            //   8975df               | dec                 eax

        $sequence_4 = { 488d15aed40100 488d4df7 e8???????? cc e8???????? cc }
            // n = 6, score = 100
            //   488d15aed40100       | movzx               ecx, byte ptr [edx + eax*4 + 0x205b2]
            //   488d4df7             | movzx               esi, byte ptr [edx + eax*4 + 0x205b3]
            //   e8????????           |                     
            //   cc                   | mov                 ebx, ecx
            //   e8????????           |                     
            //   cc                   | inc                 esp

        $sequence_5 = { 33f6 8975f7 660f1f840000000000 488b0f 4c8d4df7 33c0 4889742420 }
            // n = 7, score = 100
            //   33f6                 | dec                 eax
            //   8975f7               | lea                 edx, [0xc224]
            //   660f1f840000000000     | dec    eax
            //   488b0f               | mov                 edi, eax
            //   4c8d4df7             | dec                 esp
            //   33c0                 | lea                 ecx, [0xc344]
            //   4889742420           | dec                 eax

        $sequence_6 = { b9f4010000 ff15???????? 48c744243000000000 488d0d44470200 c744242880000000 4533c9 }
            // n = 6, score = 100
            //   b9f4010000           | dec                 eax
            //   ff15????????         |                     
            //   48c744243000000000     | lea    eax, [0x137cd]
            //   488d0d44470200       | dec                 eax
            //   c744242880000000     | cmp                 ecx, eax
            //   4533c9               | je                  0xd9

        $sequence_7 = { 488bcf ff15???????? 85c0 0f84a0000000 }
            // n = 4, score = 100
            //   488bcf               | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | sub                 esp, 0x20
            //   0f84a0000000         | dec                 eax

        $sequence_8 = { 83f801 7518 488b0d???????? 488d053b3c0100 483bc8 7405 e8???????? }
            // n = 7, score = 100
            //   83f801               | lea                 edx, [esp + 0x50]
            //   7518                 | dec                 eax
            //   488b0d????????       |                     
            //   488d053b3c0100       | mov                 edi, eax
            //   483bc8               | dec                 eax
            //   7405                 | lea                 eax, [esp + 0x40]
            //   e8????????           |                     

        $sequence_9 = { 72c3 4c8b842490000000 ba01000000 498bcc ffd3 488b7c2460 488bc3 }
            // n = 7, score = 100
            //   72c3                 | test                eax, eax
            //   4c8b842490000000     | je                  0x4a2
            //   ba01000000           | dec                 eax
            //   498bcc               | mov                 ecx, ebp
            //   ffd3                 | dec                 eax
            //   488b7c2460           | lea                 edx, [0x17e11]
            //   488bc3               | and                 ecx, 0x3f

    condition:
        7 of them and filesize < 389120
}
