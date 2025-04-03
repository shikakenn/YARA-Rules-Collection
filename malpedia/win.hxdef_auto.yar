rule win_hxdef_auto {

    meta:
        id = "3mtbc1jfKNfP7OarxQkqBn"
        fingerprint = "v1_sha256_4767091363fb13ba8f5ccb632137f38f1a28280ef78480a23853d802dd2a1712"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hxdef"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff7628 8d83b8684000 ffd0 8b7df8 }
            // n = 4, score = 100
            //   ff7628               | push                dword ptr [esi + 0x28]
            //   8d83b8684000         | lea                 eax, [ebx + 0x4068b8]
            //   ffd0                 | call                eax
            //   8b7df8               | mov                 edi, dword ptr [ebp - 8]

        $sequence_1 = { 7516 6a00 eb02 6a01 6a01 ff7520 ff7514 }
            // n = 7, score = 100
            //   7516                 | jne                 0x18
            //   6a00                 | push                0
            //   eb02                 | jmp                 4
            //   6a01                 | push                1
            //   6a01                 | push                1
            //   ff7520               | push                dword ptr [ebp + 0x20]
            //   ff7514               | push                dword ptr [ebp + 0x14]

        $sequence_2 = { 8d85f8feffff 50 6a00 e8???????? 8bd0 8d8415f8feffff 85d2 }
            // n = 7, score = 100
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   8d8415f8feffff       | lea                 eax, [ebp + edx - 0x108]
            //   85d2                 | test                edx, edx

        $sequence_3 = { 68???????? a1???????? 50 e8???????? 5d c20400 55 }
            // n = 7, score = 100
            //   68????????           |                     
            //   a1????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   55                   | push                ebp

        $sequence_4 = { 8b472c 85c0 74f2 8b4614 85c0 0f8476010000 8b4604 }
            // n = 7, score = 100
            //   8b472c               | mov                 eax, dword ptr [edi + 0x2c]
            //   85c0                 | test                eax, eax
            //   74f2                 | je                  0xfffffff4
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   85c0                 | test                eax, eax
            //   0f8476010000         | je                  0x17c
            //   8b4604               | mov                 eax, dword ptr [esi + 4]

        $sequence_5 = { b8???????? 668b55e0 668910 66c7030000 83c302 895db0 }
            // n = 6, score = 100
            //   b8????????           |                     
            //   668b55e0             | mov                 dx, word ptr [ebp - 0x20]
            //   668910               | mov                 word ptr [eax], dx
            //   66c7030000           | mov                 word ptr [ebx], 0
            //   83c302               | add                 ebx, 2
            //   895db0               | mov                 dword ptr [ebp - 0x50], ebx

        $sequence_6 = { 0375f0 8dbde8fdffff 57 f3a4 31c0 66ab }
            // n = 6, score = 100
            //   0375f0               | add                 esi, dword ptr [ebp - 0x10]
            //   8dbde8fdffff         | lea                 edi, [ebp - 0x218]
            //   57                   | push                edi
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   31c0                 | xor                 eax, eax
            //   66ab                 | stosw               word ptr es:[edi], ax

        $sequence_7 = { 8bcf 49 ba01000000 8b45f4 e8???????? 8b85a8fefcff 8d95acfefcff }
            // n = 7, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   49                   | dec                 ecx
            //   ba01000000           | mov                 edx, 1
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   e8????????           |                     
            //   8b85a8fefcff         | mov                 eax, dword ptr [ebp - 0x30158]
            //   8d95acfefcff         | lea                 edx, [ebp - 0x30154]

        $sequence_8 = { 3b05???????? 7531 a1???????? 3dff000000 740b 3dfe000000 7404 }
            // n = 7, score = 100
            //   3b05????????         |                     
            //   7531                 | jne                 0x33
            //   a1????????           |                     
            //   3dff000000           | cmp                 eax, 0xff
            //   740b                 | je                  0xd
            //   3dfe000000           | cmp                 eax, 0xfe
            //   7404                 | je                  6

        $sequence_9 = { 41 88c4 662507c0 80fcc0 0f8474ffffff f6c210 752d }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   88c4                 | mov                 ah, al
            //   662507c0             | and                 ax, 0xc007
            //   80fcc0               | cmp                 ah, 0xc0
            //   0f8474ffffff         | je                  0xffffff7a
            //   f6c210               | test                dl, 0x10
            //   752d                 | jne                 0x2f

    condition:
        7 of them and filesize < 1253376
}
