rule win_kwampirs_auto {

    meta:
        id = "1xgYoyxUQ4LWFEIHIEjQmT"
        fingerprint = "v1_sha256_05da0209b4ac4234af04c94a25b568ea854e2af3b982527383637ef20b197483"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.kwampirs."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kwampirs"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 51 e8???????? 83c404 a3???????? 33f6 }
            // n = 5, score = 800
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   33f6                 | xor                 esi, esi

        $sequence_1 = { 83c418 85c0 7512 8b07 }
            // n = 4, score = 800
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax
            //   7512                 | jne                 0x14
            //   8b07                 | mov                 eax, dword ptr [edi]

        $sequence_2 = { 7512 8b07 50 e8???????? 83c404 891f }
            // n = 6, score = 800
            //   7512                 | jne                 0x14
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   891f                 | mov                 dword ptr [edi], ebx

        $sequence_3 = { f7d9 0bc8 51 e8???????? 83c404 a3???????? 33f6 }
            // n = 7, score = 800
            //   f7d9                 | neg                 ecx
            //   0bc8                 | or                  ecx, eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { e8???????? 83c404 8a45e7 8b4df0 64890d00000000 }
            // n = 5, score = 800
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8a45e7               | mov                 al, byte ptr [ebp - 0x19]
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_5 = { 33c5 50 8d45f0 64a300000000 8965e8 8bf9 33db }
            // n = 7, score = 800
            //   33c5                 | xor                 eax, ebp
            //   50                   | push                eax
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   8bf9                 | mov                 edi, ecx
            //   33db                 | xor                 ebx, ebx

        $sequence_6 = { 668955f4 33d2 668955f6 e8???????? }
            // n = 4, score = 800
            //   668955f4             | mov                 word ptr [ebp - 0xc], dx
            //   33d2                 | xor                 edx, edx
            //   668955f6             | mov                 word ptr [ebp - 0xa], dx
            //   e8????????           |                     

        $sequence_7 = { 8d45f0 64a300000000 8965e8 8bf9 33db }
            // n = 5, score = 800
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   8bf9                 | mov                 edi, ecx
            //   33db                 | xor                 ebx, ebx

        $sequence_8 = { 6a01 56 8b0f 51 e8???????? 83c418 }
            // n = 6, score = 800
            //   6a01                 | push                1
            //   56                   | push                esi
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18

        $sequence_9 = { 56 8b0f 51 e8???????? 83c418 85c0 }
            // n = 6, score = 800
            //   56                   | push                esi
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   85c0                 | test                eax, eax

    condition:
        7 of them and filesize < 2695168
}
