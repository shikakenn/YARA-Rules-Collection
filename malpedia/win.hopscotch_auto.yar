rule win_hopscotch_auto {

    meta:
        id = "2IdEAa7QJSskCVBuI85TyD"
        fingerprint = "v1_sha256_87c8060052c7a27df707d3c608dced07179361cdfbcc1ac24fe99b2c3ce14a55"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.hopscotch."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hopscotch"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd7 8b742410 8d4c2408 51 6a00 6a00 68???????? }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   8b742410             | mov                 esi, dword ptr [esp + 0x10]
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   68????????           |                     

        $sequence_1 = { e8???????? 83c404 85c0 7512 53 55 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   85c0                 | test                eax, eax
            //   7512                 | jne                 0x14
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   e8????????           |                     

        $sequence_2 = { 752c ff15???????? 3d26040000 741f 68???????? e8???????? }
            // n = 6, score = 100
            //   752c                 | jne                 0x2e
            //   ff15????????         |                     
            //   3d26040000           | cmp                 eax, 0x426
            //   741f                 | je                  0x21
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_3 = { f7c600ffffff 7538 8a00 23c7 }
            // n = 4, score = 100
            //   f7c600ffffff         | test                esi, 0xffffff00
            //   7538                 | jne                 0x3a
            //   8a00                 | mov                 al, byte ptr [eax]
            //   23c7                 | and                 eax, edi

        $sequence_4 = { 85f6 7511 ff15???????? 50 68???????? e9???????? 8b84241c010000 }
            // n = 7, score = 100
            //   85f6                 | test                esi, esi
            //   7511                 | jne                 0x13
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   e9????????           |                     
            //   8b84241c010000       | mov                 eax, dword ptr [esp + 0x11c]

        $sequence_5 = { 8d44240c 68???????? 50 ffd6 83c408 85c0 }
            // n = 6, score = 100
            //   8d44240c             | lea                 eax, [esp + 0xc]
            //   68????????           |                     
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax

        $sequence_6 = { 5b 81c4a0030000 c3 6a00 8d4c2428 6a00 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   81c4a0030000         | add                 esp, 0x3a0
            //   c3                   | ret                 
            //   6a00                 | push                0
            //   8d4c2428             | lea                 ecx, [esp + 0x28]
            //   6a00                 | push                0

        $sequence_7 = { c3 8b0d???????? 8d542404 52 8b542410 }
            // n = 5, score = 100
            //   c3                   | ret                 
            //   8b0d????????         |                     
            //   8d542404             | lea                 edx, [esp + 4]
            //   52                   | push                edx
            //   8b542410             | mov                 edx, dword ptr [esp + 0x10]

        $sequence_8 = { 57 6af6 ff15???????? 8b35???????? 8bf8 8d442408 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   6af6                 | push                -0xa
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   8d442408             | lea                 eax, [esp + 8]

        $sequence_9 = { 6a3f eb0b a1???????? 83c020 50 }
            // n = 5, score = 100
            //   6a3f                 | push                0x3f
            //   eb0b                 | jmp                 0xd
            //   a1????????           |                     
            //   83c020               | add                 eax, 0x20
            //   50                   | push                eax

    condition:
        7 of them and filesize < 1143808
}
