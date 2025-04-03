rule win_getmail_auto {

    meta:
        id = "4CHpd44HBj1NETjwh3dFjc"
        fingerprint = "v1_sha256_f392c7d302de7668ac9b3700c0372997d2f7bd630f275b38a7b8618bbfecba8b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.getmail."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.getmail"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 83c404 895e28 895e2c 8b4618 3bc3 741d }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   895e28               | mov                 dword ptr [esi + 0x28], ebx
            //   895e2c               | mov                 dword ptr [esi + 0x2c], ebx
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   3bc3                 | cmp                 eax, ebx
            //   741d                 | je                  0x1f

        $sequence_1 = { e8???????? 83c404 8b4c2440 895c2430 3bcb 895c2434 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c2440             | mov                 ecx, dword ptr [esp + 0x40]
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx
            //   3bcb                 | cmp                 ecx, ebx
            //   895c2434             | mov                 dword ptr [esp + 0x34], ebx

        $sequence_2 = { 3bc6 7709 e8???????? 8b54244c 85f6 7643 8d2c32 }
            // n = 7, score = 100
            //   3bc6                 | cmp                 eax, esi
            //   7709                 | ja                  0xb
            //   e8????????           |                     
            //   8b54244c             | mov                 edx, dword ptr [esp + 0x4c]
            //   85f6                 | test                esi, esi
            //   7643                 | jbe                 0x45
            //   8d2c32               | lea                 ebp, [edx + esi]

        $sequence_3 = { c1e902 f3a5 8bcb 83e103 f3a4 a1???????? 85c0 }
            // n = 7, score = 100
            //   c1e902               | shr                 ecx, 2
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcb                 | mov                 ecx, ebx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   a1????????           |                     
            //   85c0                 | test                eax, eax

        $sequence_4 = { 51 50 e8???????? 83c408 c3 81ec04010000 b941000000 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   81ec04010000         | sub                 esp, 0x104
            //   b941000000           | mov                 ecx, 0x41

        $sequence_5 = { 8b742474 896c243c 881c28 8b4c241c }
            // n = 4, score = 100
            //   8b742474             | mov                 esi, dword ptr [esp + 0x74]
            //   896c243c             | mov                 dword ptr [esp + 0x3c], ebp
            //   881c28               | mov                 byte ptr [eax + ebp], bl
            //   8b4c241c             | mov                 ecx, dword ptr [esp + 0x1c]

        $sequence_6 = { 89442424 7426 8d54246c 53 52 }
            // n = 5, score = 100
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   7426                 | je                  0x28
            //   8d54246c             | lea                 edx, [esp + 0x6c]
            //   53                   | push                ebx
            //   52                   | push                edx

        $sequence_7 = { 894c2478 68???????? 68???????? e8???????? 83c40c 8d542414 8d442468 }
            // n = 7, score = 100
            //   894c2478             | mov                 dword ptr [esp + 0x78], ecx
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   8d442468             | lea                 eax, [esp + 0x68]

        $sequence_8 = { 49 51 e8???????? 83c404 8b4c245c 897c2448 897c244c }
            // n = 7, score = 100
            //   49                   | dec                 ecx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4c245c             | mov                 ecx, dword ptr [esp + 0x5c]
            //   897c2448             | mov                 dword ptr [esp + 0x48], edi
            //   897c244c             | mov                 dword ptr [esp + 0x4c], edi

        $sequence_9 = { 8b10 50 ff5208 eb52 8b08 8d542414 52 }
            // n = 7, score = 100
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   50                   | push                eax
            //   ff5208               | call                dword ptr [edx + 8]
            //   eb52                 | jmp                 0x54
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 188416
}
