rule win_agfspy_auto {

    meta:
        id = "5nR7GaEhsrQkGOg8CYym6c"
        fingerprint = "v1_sha256_2e86502162b077190fa9b6bc0039b0226221ca91b45f721fc1b45981eaf2202d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.agfspy."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.agfspy"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b01 6a01 ff10 c645fc05 8bce 8b07 66c745e00100 }
            // n = 7, score = 400
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   6a01                 | push                1
            //   ff10                 | call                dword ptr [eax]
            //   c645fc05             | mov                 byte ptr [ebp - 4], 5
            //   8bce                 | mov                 ecx, esi
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   66c745e00100         | mov                 word ptr [ebp - 0x20], 1

        $sequence_1 = { 745e 33c0 663b07 7457 50 50 50 }
            // n = 7, score = 400
            //   745e                 | je                  0x60
            //   33c0                 | xor                 eax, eax
            //   663b07               | cmp                 ax, word ptr [edi]
            //   7457                 | je                  0x59
            //   50                   | push                eax
            //   50                   | push                eax
            //   50                   | push                eax

        $sequence_2 = { 03c0 03c7 83d600 3b5ddc 736e 8b55e4 ebaa }
            // n = 7, score = 400
            //   03c0                 | add                 eax, eax
            //   03c7                 | add                 eax, edi
            //   83d600               | adc                 esi, 0
            //   3b5ddc               | cmp                 ebx, dword ptr [ebp - 0x24]
            //   736e                 | jae                 0x70
            //   8b55e4               | mov                 edx, dword ptr [ebp - 0x1c]
            //   ebaa                 | jmp                 0xffffffac

        $sequence_3 = { 8d4dd8 e8???????? 0f1005???????? 8bd0 c745e82e000000 c745ec2f000000 8955d8 }
            // n = 7, score = 400
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   0f1005????????       |                     
            //   8bd0                 | mov                 edx, eax
            //   c745e82e000000       | mov                 dword ptr [ebp - 0x18], 0x2e
            //   c745ec2f000000       | mov                 dword ptr [ebp - 0x14], 0x2f
            //   8955d8               | mov                 dword ptr [ebp - 0x28], edx

        $sequence_4 = { 25ff000000 740e 83f807 0f8557020000 e9???????? c745e400000000 }
            // n = 6, score = 400
            //   25ff000000           | and                 eax, 0xff
            //   740e                 | je                  0x10
            //   83f807               | cmp                 eax, 7
            //   0f8557020000         | jne                 0x25d
            //   e9????????           |                     
            //   c745e400000000       | mov                 dword ptr [ebp - 0x1c], 0

        $sequence_5 = { 64a300000000 894dc8 8b7508 8b7d0c 8bcf 8975d0 8b4608 }
            // n = 7, score = 400
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   894dc8               | mov                 dword ptr [ebp - 0x38], ecx
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8bcf                 | mov                 ecx, edi
            //   8975d0               | mov                 dword ptr [ebp - 0x30], esi
            //   8b4608               | mov                 eax, dword ptr [esi + 8]

        $sequence_6 = { bb04000000 895de4 eb28 4e eba8 8b17 8b4a04 }
            // n = 7, score = 400
            //   bb04000000           | mov                 ebx, 4
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   eb28                 | jmp                 0x2a
            //   4e                   | dec                 esi
            //   eba8                 | jmp                 0xffffffaa
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]

        $sequence_7 = { 56 ff15???????? 33f6 8b9564ffffff 83fa10 722b 8b8d50ffffff }
            // n = 7, score = 400
            //   56                   | push                esi
            //   ff15????????         |                     
            //   33f6                 | xor                 esi, esi
            //   8b9564ffffff         | mov                 edx, dword ptr [ebp - 0x9c]
            //   83fa10               | cmp                 edx, 0x10
            //   722b                 | jb                  0x2d
            //   8b8d50ffffff         | mov                 ecx, dword ptr [ebp - 0xb0]

        $sequence_8 = { 3bcf 0f820a020000 8b55ec 8bc2 2bc1 83f801 }
            // n = 6, score = 400
            //   3bcf                 | cmp                 ecx, edi
            //   0f820a020000         | jb                  0x210
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   8bc2                 | mov                 eax, edx
            //   2bc1                 | sub                 eax, ecx
            //   83f801               | cmp                 eax, 1

        $sequence_9 = { 75ed eb7c 83f85c 7403 50 eb6d 3bf9 }
            // n = 7, score = 400
            //   75ed                 | jne                 0xffffffef
            //   eb7c                 | jmp                 0x7e
            //   83f85c               | cmp                 eax, 0x5c
            //   7403                 | je                  5
            //   50                   | push                eax
            //   eb6d                 | jmp                 0x6f
            //   3bf9                 | cmp                 edi, ecx

    condition:
        7 of them and filesize < 1482752
}
