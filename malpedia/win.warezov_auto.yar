rule win_warezov_auto {

    meta:
        id = "rhDHNMAbDEy9IF136lfqJ"
        fingerprint = "v1_sha256_76ba225e2c2800078c3a09fe679ba4718fd1f03fa3d573bef216fead7a711c12"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.warezov."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.warezov"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f805 7cf2 c684244002000064 c6842441020000b0 c68424420200005d c68424430200006c c684244402000063 }
            // n = 7, score = 100
            //   83f805               | cmp                 eax, 5
            //   7cf2                 | jl                  0xfffffff4
            //   c684244002000064     | mov                 byte ptr [esp + 0x240], 0x64
            //   c6842441020000b0     | mov                 byte ptr [esp + 0x241], 0xb0
            //   c68424420200005d     | mov                 byte ptr [esp + 0x242], 0x5d
            //   c68424430200006c     | mov                 byte ptr [esp + 0x243], 0x6c
            //   c684244402000063     | mov                 byte ptr [esp + 0x244], 0x63

        $sequence_1 = { c64424156d c644241610 885c2417 c64424183c c6442419f9 c644241ae3 c644241b02 }
            // n = 7, score = 100
            //   c64424156d           | mov                 byte ptr [esp + 0x15], 0x6d
            //   c644241610           | mov                 byte ptr [esp + 0x16], 0x10
            //   885c2417             | mov                 byte ptr [esp + 0x17], bl
            //   c64424183c           | mov                 byte ptr [esp + 0x18], 0x3c
            //   c6442419f9           | mov                 byte ptr [esp + 0x19], 0xf9
            //   c644241ae3           | mov                 byte ptr [esp + 0x1a], 0xe3
            //   c644241b02           | mov                 byte ptr [esp + 0x1b], 2

        $sequence_2 = { 89456c 57 c64520ec c64521c7 c6452254 c645237d c64524dc }
            // n = 7, score = 100
            //   89456c               | mov                 dword ptr [ebp + 0x6c], eax
            //   57                   | push                edi
            //   c64520ec             | mov                 byte ptr [ebp + 0x20], 0xec
            //   c64521c7             | mov                 byte ptr [ebp + 0x21], 0xc7
            //   c6452254             | mov                 byte ptr [ebp + 0x22], 0x54
            //   c645237d             | mov                 byte ptr [ebp + 0x23], 0x7d
            //   c64524dc             | mov                 byte ptr [ebp + 0x24], 0xdc

        $sequence_3 = { 0f857afeffff 393cb5c0214300 742e a1???????? 8d70ff 85f6 7c10 }
            // n = 7, score = 100
            //   0f857afeffff         | jne                 0xfffffe80
            //   393cb5c0214300       | cmp                 dword ptr [esi*4 + 0x4321c0], edi
            //   742e                 | je                  0x30
            //   a1????????           |                     
            //   8d70ff               | lea                 esi, [eax - 1]
            //   85f6                 | test                esi, esi
            //   7c10                 | jl                  0x12

        $sequence_4 = { 51 55 6aff 52 50 ff15???????? 85c0 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   55                   | push                ebp
            //   6aff                 | push                -1
            //   52                   | push                edx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_5 = { 83f813 7cec 56 6804010000 }
            // n = 4, score = 100
            //   83f813               | cmp                 eax, 0x13
            //   7cec                 | jl                  0xffffffee
            //   56                   | push                esi
            //   6804010000           | push                0x104

        $sequence_6 = { 8a4b2c 8d530c 51 8b4d0c 52 50 51 }
            // n = 7, score = 100
            //   8a4b2c               | mov                 cl, byte ptr [ebx + 0x2c]
            //   8d530c               | lea                 edx, [ebx + 0xc]
            //   51                   | push                ecx
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   52                   | push                edx
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { c6442459bd c644245a2a c644245b20 c644245c3b 33c0 8a5c0410 8a4c044c }
            // n = 7, score = 100
            //   c6442459bd           | mov                 byte ptr [esp + 0x59], 0xbd
            //   c644245a2a           | mov                 byte ptr [esp + 0x5a], 0x2a
            //   c644245b20           | mov                 byte ptr [esp + 0x5b], 0x20
            //   c644245c3b           | mov                 byte ptr [esp + 0x5c], 0x3b
            //   33c0                 | xor                 eax, eax
            //   8a5c0410             | mov                 bl, byte ptr [esp + eax + 0x10]
            //   8a4c044c             | mov                 cl, byte ptr [esp + eax + 0x4c]

        $sequence_8 = { 897c2474 c644246400 c7842484000000ffffffff 720d 8b442428 50 e8???????? }
            // n = 7, score = 100
            //   897c2474             | mov                 dword ptr [esp + 0x74], edi
            //   c644246400           | mov                 byte ptr [esp + 0x64], 0
            //   c7842484000000ffffffff     | mov    dword ptr [esp + 0x84], 0xffffffff
            //   720d                 | jb                  0xf
            //   8b442428             | mov                 eax, dword ptr [esp + 0x28]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_9 = { 898c2404010000 89942408010000 8b54246c 8d8c2498010000 898c240c010000 8b4c247c 89942410010000 }
            // n = 7, score = 100
            //   898c2404010000       | mov                 dword ptr [esp + 0x104], ecx
            //   89942408010000       | mov                 dword ptr [esp + 0x108], edx
            //   8b54246c             | mov                 edx, dword ptr [esp + 0x6c]
            //   8d8c2498010000       | lea                 ecx, [esp + 0x198]
            //   898c240c010000       | mov                 dword ptr [esp + 0x10c], ecx
            //   8b4c247c             | mov                 ecx, dword ptr [esp + 0x7c]
            //   89942410010000       | mov                 dword ptr [esp + 0x110], edx

    condition:
        7 of them and filesize < 827392
}
