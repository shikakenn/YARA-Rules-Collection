rule win_deria_lock_auto {

    meta:
        id = "6HqJ8yyfUT6gY4vEFpF2kP"
        fingerprint = "v1_sha256_4893cee300bda320fc9c59d837a4f87118d15fa35f666446a92761b54280695d"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deria_lock"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 022d???????? 0135???????? 003a 122a 0019 025e12 }
            // n = 6, score = 100
            //   022d????????         |                     
            //   0135????????         |                     
            //   003a                 | add                 byte ptr [edx], bh
            //   122a                 | adc                 ch, byte ptr [edx]
            //   0019                 | add                 byte ptr [ecx], bl
            //   025e12               | add                 bl, byte ptr [esi + 0x12]

        $sequence_1 = { 030406 a0???????? 04a3 006303 }
            // n = 4, score = 100
            //   030406               | add                 eax, dword ptr [esi + eax]
            //   a0????????           |                     
            //   04a3                 | add                 al, 0xa3
            //   006303               | add                 byte ptr [ebx + 3], ah

        $sequence_2 = { 003a 122a 0019 025e12 }
            // n = 4, score = 100
            //   003a                 | add                 byte ptr [edx], bh
            //   122a                 | adc                 ch, byte ptr [edx]
            //   0019                 | add                 byte ptr [ecx], bl
            //   025e12               | add                 bl, byte ptr [esi + 0x12]

        $sequence_3 = { 04da 00d1 02d6 018306d902d6 }
            // n = 4, score = 100
            //   04da                 | add                 al, 0xda
            //   00d1                 | add                 cl, dl
            //   02d6                 | add                 dl, dh
            //   018306d902d6         | add                 dword ptr [ebx - 0x29fd26fa], eax

        $sequence_4 = { 02d1 01b010f40321 001f 1209 }
            // n = 4, score = 100
            //   02d1                 | add                 dl, cl
            //   01b010f40321         | add                 dword ptr [eax + 0x2103f410], esi
            //   001f                 | add                 byte ptr [edi], bl
            //   1209                 | adc                 cl, byte ptr [ecx]

        $sequence_5 = { cd16 ec 07 8400 d6 0193025900d2 16 }
            // n = 7, score = 100
            //   cd16                 | int                 0x16
            //   ec                   | in                  al, dx
            //   07                   | pop                 es
            //   8400                 | test                byte ptr [eax], al
            //   d6                   | salc                
            //   0193025900d2         | add                 dword ptr [ebx - 0x2dffa6fe], edx
            //   16                   | push                ss

        $sequence_6 = { 00eb 030406 a0???????? 04a3 006303 }
            // n = 5, score = 100
            //   00eb                 | add                 bl, ch
            //   030406               | add                 eax, dword ptr [esi + eax]
            //   a0????????           |                     
            //   04a3                 | add                 al, 0xa3
            //   006303               | add                 byte ptr [ebx + 3], ah

        $sequence_7 = { 43 10cc 01a9017310a1 03c1 01d6 012a }
            // n = 6, score = 100
            //   43                   | inc                 ebx
            //   10cc                 | adc                 ah, cl
            //   01a9017310a1         | add                 dword ptr [ecx - 0x5eef8cff], ebp
            //   03c1                 | add                 eax, ecx
            //   01d6                 | add                 esi, edx
            //   012a                 | add                 dword ptr [edx], ebp

        $sequence_8 = { 59 006216 a5 07 6900d601a507 7100 7416 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   006216               | add                 byte ptr [edx + 0x16], ah
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   07                   | pop                 es
            //   6900d601a507         | imul                eax, dword ptr [eax], 0x7a501d6
            //   7100                 | jno                 2
            //   7416                 | je                  0x18

        $sequence_9 = { 43 10cc 01a9017310a1 03c1 01d6 012a 00e9 }
            // n = 7, score = 100
            //   43                   | inc                 ebx
            //   10cc                 | adc                 ah, cl
            //   01a9017310a1         | add                 dword ptr [ecx - 0x5eef8cff], ebp
            //   03c1                 | add                 eax, ecx
            //   01d6                 | add                 esi, edx
            //   012a                 | add                 dword ptr [edx], ebp
            //   00e9                 | add                 cl, ch

    condition:
        7 of them and filesize < 1220608
}
