rule win_ratankba_auto {

    meta:
        id = "8gyhZoBZZO9z0afsWP2LR"
        fingerprint = "v1_sha256_28a3493a9c6143ba99ec99eb8912043c44e1319e93a131fe32deda9f1f93952d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.ratankba."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankba"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d1443 895108 33d2 3911 7637 }
            // n = 5, score = 400
            //   8d1443               | lea                 edx, [ebx + eax*2]
            //   895108               | mov                 dword ptr [ecx + 8], edx
            //   33d2                 | xor                 edx, edx
            //   3911                 | cmp                 dword ptr [ecx], edx
            //   7637                 | jbe                 0x39

        $sequence_1 = { 8b4de4 891cc1 46 eb96 8b5710 8bc6 8955e4 }
            // n = 7, score = 400
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   891cc1               | mov                 dword ptr [ecx + eax*8], ebx
            //   46                   | inc                 esi
            //   eb96                 | jmp                 0xffffff98
            //   8b5710               | mov                 edx, dword ptr [edi + 0x10]
            //   8bc6                 | mov                 eax, esi
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx

        $sequence_2 = { 897004 83ff09 750c 8b45f4 5f }
            // n = 5, score = 400
            //   897004               | mov                 dword ptr [eax + 4], esi
            //   83ff09               | cmp                 edi, 9
            //   750c                 | jne                 0xe
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   5f                   | pop                 edi

        $sequence_3 = { 0f83a9000000 52 56 8d8d00ffffff }
            // n = 4, score = 400
            //   0f83a9000000         | jae                 0xaf
            //   52                   | push                edx
            //   56                   | push                esi
            //   8d8d00ffffff         | lea                 ecx, [ebp - 0x100]

        $sequence_4 = { 6800000001 50 51 56 ff15???????? 85c0 750c }
            // n = 7, score = 400
            //   6800000001           | push                0x1000000
            //   50                   | push                eax
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750c                 | jne                 0xe

        $sequence_5 = { 8b1d???????? 3bfe 7413 8b4df0 8b55ec 51 }
            // n = 6, score = 400
            //   8b1d????????         |                     
            //   3bfe                 | cmp                 edi, esi
            //   7413                 | je                  0x15
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   51                   | push                ecx

        $sequence_6 = { 3bce 7f13 7c05 83f820 730c }
            // n = 5, score = 400
            //   3bce                 | cmp                 ecx, esi
            //   7f13                 | jg                  0x15
            //   7c05                 | jl                  7
            //   83f820               | cmp                 eax, 0x20
            //   730c                 | jae                 0xe

        $sequence_7 = { e8???????? 8b86dc000000 3bc3 7409 50 e8???????? 83c404 }
            // n = 7, score = 400
            //   e8????????           |                     
            //   8b86dc000000         | mov                 eax, dword ptr [esi + 0xdc]
            //   3bc3                 | cmp                 eax, ebx
            //   7409                 | je                  0xb
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_8 = { 8955e4 8945f8 e8???????? 8945f4 85c0 }
            // n = 5, score = 400
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   85c0                 | test                eax, eax

        $sequence_9 = { 899ef4000000 66898ee4000000 8d8e00010000 c645fc07 33d2 }
            // n = 5, score = 400
            //   899ef4000000         | mov                 dword ptr [esi + 0xf4], ebx
            //   66898ee4000000       | mov                 word ptr [esi + 0xe4], cx
            //   8d8e00010000         | lea                 ecx, [esi + 0x100]
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7
            //   33d2                 | xor                 edx, edx

    condition:
        7 of them and filesize < 303104
}
