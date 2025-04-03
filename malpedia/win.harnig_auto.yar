rule win_harnig_auto {

    meta:
        id = "1xbE0t2iqzEirItoZa5DZA"
        fingerprint = "v1_sha256_6b0da0575293c2afced8a49894e42bab87f6771cbe3d56035db53ed07d7267fe"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.harnig."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.harnig"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd7 6a21 56 68???????? e8???????? 56 }
            // n = 6, score = 100
            //   ffd7                 | call                edi
            //   6a21                 | push                0x21
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_1 = { c9 c20800 55 8bec 83ec54 57 6a10 }
            // n = 7, score = 100
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec54               | sub                 esp, 0x54
            //   57                   | push                edi
            //   6a10                 | push                0x10

        $sequence_2 = { ff74240c 0fb674240c 6a02 e8???????? 6a08 }
            // n = 5, score = 100
            //   ff74240c             | push                dword ptr [esp + 0xc]
            //   0fb674240c           | movzx               esi, byte ptr [esp + 0xc]
            //   6a02                 | push                2
            //   e8????????           |                     
            //   6a08                 | push                8

        $sequence_3 = { 59 68c78a3146 33c0 c745ac44000000 }
            // n = 4, score = 100
            //   59                   | pop                 ecx
            //   68c78a3146           | push                0x46318ac7
            //   33c0                 | xor                 eax, eax
            //   c745ac44000000       | mov                 dword ptr [ebp - 0x54], 0x44

        $sequence_4 = { 837dfc00 8d85e0fcffff 7406 8d85e0fbffff 50 8d85e0fdffff 50 }
            // n = 7, score = 100
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   8d85e0fcffff         | lea                 eax, [ebp - 0x320]
            //   7406                 | je                  8
            //   8d85e0fbffff         | lea                 eax, [ebp - 0x420]
            //   50                   | push                eax
            //   8d85e0fdffff         | lea                 eax, [ebp - 0x220]
            //   50                   | push                eax

        $sequence_5 = { 81ec18080000 53 56 57 ba00010000 33c0 }
            // n = 6, score = 100
            //   81ec18080000         | sub                 esp, 0x818
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   ba00010000           | mov                 edx, 0x100
            //   33c0                 | xor                 eax, eax

        $sequence_6 = { 50 8d85e0fdffff 50 ffd7 6a04 56 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8d85e0fdffff         | lea                 eax, [ebp - 0x220]
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   6a04                 | push                4
            //   56                   | push                esi

        $sequence_7 = { 0f845d020000 895dfc 8b1d???????? 837dfc00 8d85e0fcffff 7406 }
            // n = 6, score = 100
            //   0f845d020000         | je                  0x263
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   8b1d????????         |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   8d85e0fcffff         | lea                 eax, [ebp - 0x320]
            //   7406                 | je                  8

        $sequence_8 = { 6a04 8d4df8 51 6a05 ff750c ffd0 bf6229211a }
            // n = 7, score = 100
            //   6a04                 | push                4
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   51                   | push                ecx
            //   6a05                 | push                5
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ffd0                 | call                eax
            //   bf6229211a           | mov                 edi, 0x1a212962

        $sequence_9 = { 6a04 c745c03c000000 897dc8 c745cc6c104000 8945d4 897dd8 }
            // n = 6, score = 100
            //   6a04                 | push                4
            //   c745c03c000000       | mov                 dword ptr [ebp - 0x40], 0x3c
            //   897dc8               | mov                 dword ptr [ebp - 0x38], edi
            //   c745cc6c104000       | mov                 dword ptr [ebp - 0x34], 0x40106c
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   897dd8               | mov                 dword ptr [ebp - 0x28], edi

    condition:
        7 of them and filesize < 49152
}
