rule win_derusbi_auto {

    meta:
        id = "2KuBnEjKMYhT1fmD4ld7rY"
        fingerprint = "v1_sha256_caf9d1cd989612f714b35d25a26a8b4ab8e67beec50b5a767b0d4e5f975c75e0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.derusbi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.derusbi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 48 48 7436 48 742c }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   48                   | dec                 eax
            //   48                   | dec                 eax
            //   7436                 | je                  0x38
            //   48                   | dec                 eax
            //   742c                 | je                  0x2e

        $sequence_1 = { ffb5f4fbffff ffd6 85c0 7461 b800010000 8985e4fbffff 8985e8fbffff }
            // n = 7, score = 200
            //   ffb5f4fbffff         | push                dword ptr [ebp - 0x40c]
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7461                 | je                  0x63
            //   b800010000           | mov                 eax, 0x100
            //   8985e4fbffff         | mov                 dword ptr [ebp - 0x41c], eax
            //   8985e8fbffff         | mov                 dword ptr [ebp - 0x418], eax

        $sequence_2 = { 53 be???????? 8dbda8f1ffff 50 f3a5 e8???????? 899d28f2ffff }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   be????????           |                     
            //   8dbda8f1ffff         | lea                 edi, [ebp - 0xe58]
            //   50                   | push                eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   e8????????           |                     
            //   899d28f2ffff         | mov                 dword ptr [ebp - 0xdd8], ebx

        $sequence_3 = { 8b800c010000 c3 83790405 750e 83790800 7408 8b81a0000000 }
            // n = 7, score = 200
            //   8b800c010000         | mov                 eax, dword ptr [eax + 0x10c]
            //   c3                   | ret                 
            //   83790405             | cmp                 dword ptr [ecx + 4], 5
            //   750e                 | jne                 0x10
            //   83790800             | cmp                 dword ptr [ecx + 8], 0
            //   7408                 | je                  0xa
            //   8b81a0000000         | mov                 eax, dword ptr [ecx + 0xa0]

        $sequence_4 = { 89442434 e8???????? 39442434 7467 68a4000000 ff15???????? 8bf0 }
            // n = 7, score = 200
            //   89442434             | mov                 dword ptr [esp + 0x34], eax
            //   e8????????           |                     
            //   39442434             | cmp                 dword ptr [esp + 0x34], eax
            //   7467                 | je                  0x69
            //   68a4000000           | push                0xa4
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_5 = { 8d85b4fdffff 53 50 c685fcfeffff00 c6857cffffff00 c6857cfeffff00 ffd6 }
            // n = 7, score = 200
            //   8d85b4fdffff         | lea                 eax, [ebp - 0x24c]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   c685fcfeffff00       | mov                 byte ptr [ebp - 0x104], 0
            //   c6857cffffff00       | mov                 byte ptr [ebp - 0x84], 0
            //   c6857cfeffff00       | mov                 byte ptr [ebp - 0x184], 0
            //   ffd6                 | call                esi

        $sequence_6 = { 51 ffb5dcf9ffff 8d85f4fdffff 50 ff15???????? 33c0 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   ffb5dcf9ffff         | push                dword ptr [ebp - 0x624]
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 8db405aff7ffff 68???????? 56 ff15???????? 56 ffd7 8b8d9cf3ffff }
            // n = 7, score = 200
            //   8db405aff7ffff       | lea                 esi, [ebp + eax - 0x851]
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   8b8d9cf3ffff         | mov                 ecx, dword ptr [ebp - 0xc64]

        $sequence_8 = { 50 ff15???????? 59 59 6a43 58 6689442414 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   6a43                 | push                0x43
            //   58                   | pop                 eax
            //   6689442414           | mov                 word ptr [esp + 0x14], ax

        $sequence_9 = { 50 ff15???????? c70424???????? 33f6 56 6801001f00 ff15???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   c70424????????       |                     
            //   33f6                 | xor                 esi, esi
            //   56                   | push                esi
            //   6801001f00           | push                0x1f0001
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 360448
}
