rule win_herpes_auto {

    meta:
        id = "7fb6MGo9CnzDLrl3SktnoI"
        fingerprint = "v1_sha256_769ea4914adc8e6bb491030ee0781ca8f47cafb6846f9263dbbc09dc62dc70a2"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.herpes."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.herpes"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffd7 68???????? ffb6f0010000 89863c010000 ffd7 68???????? ffb6f0010000 }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   ffb6f0010000         | push                dword ptr [esi + 0x1f0]
            //   89863c010000         | mov                 dword ptr [esi + 0x13c], eax
            //   ffd7                 | call                edi
            //   68????????           |                     
            //   ffb6f0010000         | push                dword ptr [esi + 0x1f0]

        $sequence_1 = { 6a02 6a00 6a00 6800000040 8d95f4fdffff 52 ff15???????? }
            // n = 7, score = 100
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6800000040           | push                0x40000000
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]
            //   52                   | push                edx
            //   ff15????????         |                     

        $sequence_2 = { 894dd0 c745c804000000 ffd6 85c0 755c 8b1d???????? ffd3 }
            // n = 7, score = 100
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   c745c804000000       | mov                 dword ptr [ebp - 0x38], 4
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   755c                 | jne                 0x5e
            //   8b1d????????         |                     
            //   ffd3                 | call                ebx

        $sequence_3 = { 8d8d24faffff 51 57 ff15???????? 85c0 0f84e2000000 8b1d???????? }
            // n = 7, score = 100
            //   8d8d24faffff         | lea                 ecx, [ebp - 0x5dc]
            //   51                   | push                ecx
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84e2000000         | je                  0xe8
            //   8b1d????????         |                     

        $sequence_4 = { 33c9 3b04cd10c84100 7413 41 83f92d 72f1 8d48ed }
            // n = 7, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   3b04cd10c84100       | cmp                 eax, dword ptr [ecx*8 + 0x41c810]
            //   7413                 | je                  0x15
            //   41                   | inc                 ecx
            //   83f92d               | cmp                 ecx, 0x2d
            //   72f1                 | jb                  0xfffffff3
            //   8d48ed               | lea                 ecx, [eax - 0x13]

        $sequence_5 = { 50 6a01 8d45cc 50 56 ff15???????? 894590 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   6a01                 | push                1
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   50                   | push                eax
            //   56                   | push                esi
            //   ff15????????         |                     
            //   894590               | mov                 dword ptr [ebp - 0x70], eax

        $sequence_6 = { 8dbd88fcffff e8???????? 84c0 745a 8b0d???????? 8d85c0fcffff 50 }
            // n = 7, score = 100
            //   8dbd88fcffff         | lea                 edi, [ebp - 0x378]
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   745a                 | je                  0x5c
            //   8b0d????????         |                     
            //   8d85c0fcffff         | lea                 eax, [ebp - 0x340]
            //   50                   | push                eax

        $sequence_7 = { 8b0d???????? 8d85c0fcffff 50 51 e8???????? c645fc0b 8b15???????? }
            // n = 7, score = 100
            //   8b0d????????         |                     
            //   8d85c0fcffff         | lea                 eax, [ebp - 0x340]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   c645fc0b             | mov                 byte ptr [ebp - 4], 0xb
            //   8b15????????         |                     

        $sequence_8 = { e8???????? eb15 3bc3 7511 8b45b8 895dc8 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   eb15                 | jmp                 0x17
            //   3bc3                 | cmp                 eax, ebx
            //   7511                 | jne                 0x13
            //   8b45b8               | mov                 eax, dword ptr [ebp - 0x48]
            //   895dc8               | mov                 dword ptr [ebp - 0x38], ebx

        $sequence_9 = { 83c404 ff15???????? 85c0 7418 6804010000 8d8c24e00a0000 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7418                 | je                  0x1a
            //   6804010000           | push                0x104
            //   8d8c24e00a0000       | lea                 ecx, [esp + 0xae0]

    condition:
        7 of them and filesize < 319488
}
