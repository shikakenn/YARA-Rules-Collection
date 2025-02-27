rule win_shakti_auto {

    meta:
        id = "2D85RPzhWGBIZfVdmD4NBV"
        fingerprint = "v1_sha256_f9488b8a8445549b2d17849193cda20ba79220110ad09656a16f1b56d9644dea"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.shakti."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shakti"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b45cc 0fb608 83f961 7c12 8b55cc 0fb602 }
            // n = 6, score = 500
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   0fb608               | movzx               ecx, byte ptr [eax]
            //   83f961               | cmp                 ecx, 0x61
            //   7c12                 | jl                  0x14
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]
            //   0fb602               | movzx               eax, byte ptr [edx]

        $sequence_1 = { 8b45cc 83c002 50 8b4dc0 51 ff55dc }
            // n = 6, score = 500
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   83c002               | add                 eax, 2
            //   50                   | push                eax
            //   8b4dc0               | mov                 ecx, dword ptr [ebp - 0x40]
            //   51                   | push                ecx
            //   ff55dc               | call                dword ptr [ebp - 0x24]

        $sequence_2 = { 8945e0 837de000 0f848b000000 8b4de0 8b5128 }
            // n = 5, score = 500
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   837de000             | cmp                 dword ptr [ebp - 0x20], 0
            //   0f848b000000         | je                  0x91
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   8b5128               | mov                 edx, dword ptr [ecx + 0x28]

        $sequence_3 = { 8b55f8 0fb74206 8b4df8 668b5106 6683ea01 }
            // n = 5, score = 500
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   0fb74206             | movzx               eax, word ptr [edx + 6]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   668b5106             | mov                 dx, word ptr [ecx + 6]
            //   6683ea01             | sub                 dx, 1

        $sequence_4 = { 8b45cc 0fb608 034dfc 894dfc 8b55cc }
            // n = 5, score = 500
            //   8b45cc               | mov                 eax, dword ptr [ebp - 0x34]
            //   0fb608               | movzx               ecx, byte ptr [eax]
            //   034dfc               | add                 ecx, dword ptr [ebp - 4]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55cc               | mov                 edx, dword ptr [ebp - 0x34]

        $sequence_5 = { 6a00 52 e8???????? 8d442418 }
            // n = 4, score = 500
            //   6a00                 | push                0
            //   52                   | push                edx
            //   e8????????           |                     
            //   8d442418             | lea                 eax, [esp + 0x18]

        $sequence_6 = { 662301 0fb7d0 8b45c0 25ffff0000 0fb7c8 8b45e0 }
            // n = 6, score = 500
            //   662301               | and                 ax, word ptr [ecx]
            //   0fb7d0               | movzx               edx, ax
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   25ffff0000           | and                 eax, 0xffff
            //   0fb7c8               | movzx               ecx, ax
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_7 = { 0fb711 8b45c4 8d0c90 894dc4 }
            // n = 4, score = 500
            //   0fb711               | movzx               edx, word ptr [ecx]
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   8d0c90               | lea                 ecx, [eax + edx*4]
            //   894dc4               | mov                 dword ptr [ebp - 0x3c], ecx

        $sequence_8 = { 55 8bec 51 51 a1???????? 8945f8 8b801c090000 }
            // n = 7, score = 400
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   a1????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b801c090000         | mov                 eax, dword ptr [eax + 0x91c]

        $sequence_9 = { 7443 8b7de4 8d45e8 50 6a40 57 ff75f4 }
            // n = 7, score = 400
            //   7443                 | je                  0x45
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   6a40                 | push                0x40
            //   57                   | push                edi
            //   ff75f4               | push                dword ptr [ebp - 0xc]

        $sequence_10 = { 7281 ff75e8 e8???????? 59 }
            // n = 4, score = 400
            //   7281                 | jb                  0xffffff83
            //   ff75e8               | push                dword ptr [ebp - 0x18]
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_11 = { 894810 894808 c3 56 8b742408 }
            // n = 5, score = 400
            //   894810               | mov                 dword ptr [eax + 0x10], ecx
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8b742408             | mov                 esi, dword ptr [esp + 8]

        $sequence_12 = { a3???????? a1???????? c705????????b5434000 8935???????? }
            // n = 4, score = 400
            //   a3????????           |                     
            //   a1????????           |                     
            //   c705????????b5434000     |     
            //   8935????????         |                     

        $sequence_13 = { 3b04cd10a04000 7413 41 83f92d }
            // n = 4, score = 400
            //   3b04cd10a04000       | cmp                 eax, dword ptr [ecx*8 + 0x40a010]
            //   7413                 | je                  0x15
            //   41                   | inc                 ecx
            //   83f92d               | cmp                 ecx, 0x2d

        $sequence_14 = { ff15???????? 68???????? 50 ff15???????? 8bf0 85f6 7468 }
            // n = 7, score = 400
            //   ff15????????         |                     
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7468                 | je                  0x6a

        $sequence_15 = { 888820a64000 40 ebe9 33c0 8945e4 }
            // n = 5, score = 400
            //   888820a64000         | mov                 byte ptr [eax + 0x40a620], cl
            //   40                   | inc                 eax
            //   ebe9                 | jmp                 0xffffffeb
            //   33c0                 | xor                 eax, eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax

    condition:
        7 of them and filesize < 191488
}
