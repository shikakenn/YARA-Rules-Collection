rule win_computrace_auto {

    meta:
        id = "1LRrfbeBPU0RQa9GXsckSm"
        fingerprint = "v1_sha256_b73f0b7c109f121cef0d44673877d18ab031d29ad8713526e9f7233d01c0d2e0"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.computrace."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.computrace"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83f802 7462 3bf3 7505 83f8ff 750f 53 }
            // n = 7, score = 200
            //   83f802               | cmp                 eax, 2
            //   7462                 | je                  0x64
            //   3bf3                 | cmp                 esi, ebx
            //   7505                 | jne                 7
            //   83f8ff               | cmp                 eax, -1
            //   750f                 | jne                 0x11
            //   53                   | push                ebx

        $sequence_1 = { 68???????? 56 e8???????? 8cc8 a803 7503 800e08 }
            // n = 7, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8cc8                 | mov                 eax, cs
            //   a803                 | test                al, 3
            //   7503                 | jne                 5
            //   800e08               | or                  byte ptr [esi], 8

        $sequence_2 = { 8d8558ffffff 50 e8???????? 3bc7 0f8eaa000000 }
            // n = 5, score = 200
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   3bc7                 | cmp                 eax, edi
            //   0f8eaa000000         | jle                 0xb0

        $sequence_3 = { 57 8b750c 8b7d10 8b1f 837d0c00 }
            // n = 5, score = 200
            //   57                   | push                edi
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   8b1f                 | mov                 ebx, dword ptr [edi]
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0

        $sequence_4 = { e8???????? 8d85fcfeffff 50 ff15???????? 85c0 7505 a1???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   a1????????           |                     

        $sequence_5 = { 83f878 751e b8800d0000 2b4608 8945c0 3945dc 760e }
            // n = 7, score = 200
            //   83f878               | cmp                 eax, 0x78
            //   751e                 | jne                 0x20
            //   b8800d0000           | mov                 eax, 0xd80
            //   2b4608               | sub                 eax, dword ptr [esi + 8]
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   3945dc               | cmp                 dword ptr [ebp - 0x24], eax
            //   760e                 | jbe                 0x10

        $sequence_6 = { ffb3101b0000 ff15???????? 6840020000 57 53 }
            // n = 5, score = 200
            //   ffb3101b0000         | push                dword ptr [ebx + 0x1b10]
            //   ff15????????         |                     
            //   6840020000           | push                0x240
            //   57                   | push                edi
            //   53                   | push                ebx

        $sequence_7 = { 0af6 750f 43 51 8bc4 }
            // n = 5, score = 200
            //   0af6                 | or                  dh, dh
            //   750f                 | jne                 0x11
            //   43                   | inc                 ebx
            //   51                   | push                ecx
            //   8bc4                 | mov                 eax, esp

        $sequence_8 = { 74ee 48 0f85ec000000 8d85acfdffff 50 6801010000 }
            // n = 6, score = 200
            //   74ee                 | je                  0xfffffff0
            //   48                   | dec                 eax
            //   0f85ec000000         | jne                 0xf2
            //   8d85acfdffff         | lea                 eax, [ebp - 0x254]
            //   50                   | push                eax
            //   6801010000           | push                0x101

        $sequence_9 = { 837dfc00 74bb 53 e8???????? 8945f8 ff75fc }
            // n = 6, score = 200
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   74bb                 | je                  0xffffffbd
            //   53                   | push                ebx
            //   e8????????           |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   ff75fc               | push                dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 73728
}
