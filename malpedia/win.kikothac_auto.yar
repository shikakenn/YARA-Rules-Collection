rule win_kikothac_auto {

    meta:
        id = "40EzGRbR7r7yr00dfUjls5"
        fingerprint = "v1_sha256_44c91c13eb1dd4a6656263ce0b69b86cf3ff2448fb7726df446bdef3b4382332"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kikothac."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kikothac"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 68???????? 6802000080 c7450c00000000 ff15???????? 85c0 753a }
            // n = 7, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   6802000080           | push                0x80000002
            //   c7450c00000000       | mov                 dword ptr [ebp + 0xc], 0
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   753a                 | jne                 0x3c

        $sequence_1 = { 884c240c 9c 89542438 c6042486 }
            // n = 4, score = 200
            //   884c240c             | mov                 byte ptr [esp + 0xc], cl
            //   9c                   | pushfd              
            //   89542438             | mov                 dword ptr [esp + 0x38], edx
            //   c6042486             | mov                 byte ptr [esp], 0x86

        $sequence_2 = { 10c6 f5 8b5504 f8 e9???????? 9c 60 }
            // n = 7, score = 200
            //   10c6                 | adc                 dh, al
            //   f5                   | cmc                 
            //   8b5504               | mov                 edx, dword ptr [ebp + 4]
            //   f8                   | clc                 
            //   e9????????           |                     
            //   9c                   | pushfd              
            //   60                   | pushal              

        $sequence_3 = { 66d3cd 894c2420 6897d1eb0f f5 6895c1b1d4 c744242400000000 66c704240957 }
            // n = 7, score = 200
            //   66d3cd               | ror                 bp, cl
            //   894c2420             | mov                 dword ptr [esp + 0x20], ecx
            //   6897d1eb0f           | push                0xfebd197
            //   f5                   | cmc                 
            //   6895c1b1d4           | push                0xd4b1c195
            //   c744242400000000     | mov                 dword ptr [esp + 0x24], 0
            //   66c704240957         | mov                 word ptr [esp], 0x5709

        $sequence_4 = { 53 56 c745e890024100 894dec 894df0 380d???????? 746f }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   56                   | push                esi
            //   c745e890024100       | mov                 dword ptr [ebp - 0x18], 0x410290
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   380d????????         |                     
            //   746f                 | je                  0x71

        $sequence_5 = { 8b15???????? 50 51 52 ff15???????? 8b06 8b10 }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8b10                 | mov                 edx, dword ptr [eax]

        $sequence_6 = { 56 33c0 68fe070000 50 8d8d02f8ffff 51 }
            // n = 6, score = 200
            //   56                   | push                esi
            //   33c0                 | xor                 eax, eax
            //   68fe070000           | push                0x7fe
            //   50                   | push                eax
            //   8d8d02f8ffff         | lea                 ecx, [ebp - 0x7fe]
            //   51                   | push                ecx

        $sequence_7 = { e9???????? 0fb6d2 fec8 882424 c0c004 f7da 660fb3ca }
            // n = 7, score = 200
            //   e9????????           |                     
            //   0fb6d2               | movzx               edx, dl
            //   fec8                 | dec                 al
            //   882424               | mov                 byte ptr [esp], ah
            //   c0c004               | rol                 al, 4
            //   f7da                 | neg                 edx
            //   660fb3ca             | btr                 dx, cx

        $sequence_8 = { f9 83c502 f5 9c 0fa5d0 ff74241c }
            // n = 6, score = 200
            //   f9                   | stc                 
            //   83c502               | add                 ebp, 2
            //   f5                   | cmc                 
            //   9c                   | pushfd              
            //   0fa5d0               | shld                eax, edx, cl
            //   ff74241c             | push                dword ptr [esp + 0x1c]

        $sequence_9 = { 85c0 7644 3d00040000 760d b800040000 8d4df4 }
            // n = 6, score = 200
            //   85c0                 | test                eax, eax
            //   7644                 | jbe                 0x46
            //   3d00040000           | cmp                 eax, 0x400
            //   760d                 | jbe                 0xf
            //   b800040000           | mov                 eax, 0x400
            //   8d4df4               | lea                 ecx, [ebp - 0xc]

    condition:
        7 of them and filesize < 581632
}
