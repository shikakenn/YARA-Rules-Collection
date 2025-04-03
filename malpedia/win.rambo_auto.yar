rule win_rambo_auto {

    meta:
        id = "7HO9pSpIW3AWxmLm4csVpx"
        fingerprint = "v1_sha256_43a3f5e58cc73b887b9d9425ae48fd61511eb3413bc03e0babb322fa4b593a9b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.rambo."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rambo"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 85f6 745e 57 6a02 6a00 56 }
            // n = 6, score = 200
            //   85f6                 | test                esi, esi
            //   745e                 | je                  0x60
            //   57                   | push                edi
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_1 = { ff15???????? 8bf0 83c420 85f6 7437 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83c420               | add                 esp, 0x20
            //   85f6                 | test                esi, esi
            //   7437                 | je                  0x39

        $sequence_2 = { 83c428 6a32 ff15???????? 8d85f8faffff 50 }
            // n = 5, score = 200
            //   83c428               | add                 esp, 0x28
            //   6a32                 | push                0x32
            //   ff15????????         |                     
            //   8d85f8faffff         | lea                 eax, [ebp - 0x508]
            //   50                   | push                eax

        $sequence_3 = { 57 8d85f8faffff 6a01 50 ff15???????? 80a43df8faffff00 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   8d85f8faffff         | lea                 eax, [ebp - 0x508]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   80a43df8faffff00     | and                 byte ptr [ebp + edi - 0x508], 0

        $sequence_4 = { e8???????? 8065fe00 8d45fc 50 8d85f8feffff 50 c645fc72 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8065fe00             | and                 byte ptr [ebp - 2], 0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   50                   | push                eax
            //   c645fc72             | mov                 byte ptr [ebp - 4], 0x72

        $sequence_5 = { 8d85f0feffff 50 8d85ecfdffff 50 e8???????? ff750c 8d85ecfdffff }
            // n = 7, score = 200
            //   8d85f0feffff         | lea                 eax, [ebp - 0x110]
            //   50                   | push                eax
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]
            //   50                   | push                eax
            //   e8????????           |                     
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   8d85ecfdffff         | lea                 eax, [ebp - 0x214]

        $sequence_6 = { 7437 56 6a01 ff7508 e8???????? 59 50 }
            // n = 7, score = 200
            //   7437                 | je                  0x39
            //   56                   | push                esi
            //   6a01                 | push                1
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_7 = { 8d85fcfeffff 59 50 ff15???????? 33c0 c9 }
            // n = 6, score = 200
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   c9                   | leave               

        $sequence_8 = { c68424000400000b e8???????? 8d4c2424 8d542420 51 8d442414 }
            // n = 6, score = 100
            //   c68424000400000b     | mov                 byte ptr [esp + 0x400], 0xb
            //   e8????????           |                     
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   8d542420             | lea                 edx, [esp + 0x20]
            //   51                   | push                ecx
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_9 = { 8dbc24ec000000 be???????? f3ab b906000000 8dbc24d0000000 f3a5 6804010000 }
            // n = 7, score = 100
            //   8dbc24ec000000       | lea                 edi, [esp + 0xec]
            //   be????????           |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   b906000000           | mov                 ecx, 6
            //   8dbc24d0000000       | lea                 edi, [esp + 0xd0]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   6804010000           | push                0x104

        $sequence_10 = { e8???????? 50 8d4c2428 c68424040400000a e8???????? }
            // n = 5, score = 100
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   c68424040400000a     | mov                 byte ptr [esp + 0x404], 0xa
            //   e8????????           |                     

        $sequence_11 = { e8???????? 8d4c2464 c684240004000001 e8???????? }
            // n = 4, score = 100
            //   e8????????           |                     
            //   8d4c2464             | lea                 ecx, [esp + 0x64]
            //   c684240004000001     | mov                 byte ptr [esp + 0x400], 1
            //   e8????????           |                     

        $sequence_12 = { 33c9 89542474 894c245c 8d542474 }
            // n = 4, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   89542474             | mov                 dword ptr [esp + 0x74], edx
            //   894c245c             | mov                 dword ptr [esp + 0x5c], ecx
            //   8d542474             | lea                 edx, [esp + 0x74]

        $sequence_13 = { 8d4c241c c68424000400000f e8???????? 8d8c249c000000 }
            // n = 4, score = 100
            //   8d4c241c             | lea                 ecx, [esp + 0x1c]
            //   c68424000400000f     | mov                 byte ptr [esp + 0x400], 0xf
            //   e8????????           |                     
            //   8d8c249c000000       | lea                 ecx, [esp + 0x9c]

        $sequence_14 = { 8b430d 84c9 7403 50 ffd5 8a4b04 }
            // n = 6, score = 100
            //   8b430d               | mov                 eax, dword ptr [ebx + 0xd]
            //   84c9                 | test                cl, cl
            //   7403                 | je                  5
            //   50                   | push                eax
            //   ffd5                 | call                ebp
            //   8a4b04               | mov                 cl, byte ptr [ebx + 4]

        $sequence_15 = { aa ff15???????? 8b4c2408 8d54240c 50 }
            // n = 5, score = 100
            //   aa                   | stosb               byte ptr es:[edi], al
            //   ff15????????         |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   8d54240c             | lea                 edx, [esp + 0xc]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 57344
}
