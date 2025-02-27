rule win_hzrat_auto {

    meta:
        id = "n8VGmsnsXVMx3U37MDOeg"
        fingerprint = "v1_sha256_caebe3b063bb24ee2db19144295d7a39f41baf69a2ce331f663ee48cf20d8acf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hzrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hzrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 ff7704 ff15???????? 85c0 7516 5f }
            // n = 6, score = 100
            //   50                   | push                eax
            //   ff7704               | push                dword ptr [edi + 4]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7516                 | jne                 0x18
            //   5f                   | pop                 edi

        $sequence_1 = { 8d85f0fbffff 50 56 e8???????? 83c40c c6043e00 eb1e }
            // n = 7, score = 100
            //   8d85f0fbffff         | lea                 eax, [ebp - 0x410]
            //   50                   | push                eax
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c6043e00             | mov                 byte ptr [esi + edi], 0
            //   eb1e                 | jmp                 0x20

        $sequence_2 = { 8b4130 8b7804 8bcf 897dd8 8b07 ff5004 6a00 }
            // n = 7, score = 100
            //   8b4130               | mov                 eax, dword ptr [ecx + 0x30]
            //   8b7804               | mov                 edi, dword ptr [eax + 4]
            //   8bcf                 | mov                 ecx, edi
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   ff5004               | call                dword ptr [eax + 4]
            //   6a00                 | push                0

        $sequence_3 = { 0f848c000000 6a04 c645e802 ff15???????? }
            // n = 4, score = 100
            //   0f848c000000         | je                  0x92
            //   6a04                 | push                4
            //   c645e802             | mov                 byte ptr [ebp - 0x18], 2
            //   ff15????????         |                     

        $sequence_4 = { 56 8bf0 898588feffff 57 56 e8???????? 8b8de1feffff }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   898588feffff         | mov                 dword ptr [ebp - 0x178], eax
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b8de1feffff         | mov                 ecx, dword ptr [ebp - 0x11f]

        $sequence_5 = { 03fe 83bd7cfeffff00 7476 85ff }
            // n = 4, score = 100
            //   03fe                 | add                 edi, esi
            //   83bd7cfeffff00       | cmp                 dword ptr [ebp - 0x184], 0
            //   7476                 | je                  0x78
            //   85ff                 | test                edi, edi

        $sequence_6 = { 57 e8???????? 83c404 e9???????? 6a04 68???????? 8d8d94feffff }
            // n = 7, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   e9????????           |                     
            //   6a04                 | push                4
            //   68????????           |                     
            //   8d8d94feffff         | lea                 ecx, [ebp - 0x16c]

        $sequence_7 = { 5b 5d c3 85c0 78f5 8b1cc564444200 6a55 }
            // n = 7, score = 100
            //   5b                   | pop                 ebx
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   85c0                 | test                eax, eax
            //   78f5                 | js                  0xfffffff7
            //   8b1cc564444200       | mov                 ebx, dword ptr [eax*8 + 0x424464]
            //   6a55                 | push                0x55

        $sequence_8 = { 7462 0faee8 0fb67ee2 0fb642e2 2bf8 751e 0faee8 }
            // n = 7, score = 100
            //   7462                 | je                  0x64
            //   0faee8               | lfence              
            //   0fb67ee2             | movzx               edi, byte ptr [esi - 0x1e]
            //   0fb642e2             | movzx               eax, byte ptr [edx - 0x1e]
            //   2bf8                 | sub                 edi, eax
            //   751e                 | jne                 0x20
            //   0faee8               | lfence              

        $sequence_9 = { 884c382b 83fa03 7511 8b45fc 8a0e 46 8b048510fa4200 }
            // n = 7, score = 100
            //   884c382b             | mov                 byte ptr [eax + edi + 0x2b], cl
            //   83fa03               | cmp                 edx, 3
            //   7511                 | jne                 0x13
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8a0e                 | mov                 cl, byte ptr [esi]
            //   46                   | inc                 esi
            //   8b048510fa4200       | mov                 eax, dword ptr [eax*4 + 0x42fa10]

    condition:
        7 of them and filesize < 409600
}
