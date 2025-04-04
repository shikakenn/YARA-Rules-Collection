rule win_danbot_auto {

    meta:
        id = "6Tqpzz2TUOjretrHcFDjhU"
        fingerprint = "v1_sha256_5da6053f066e9d13d04800876e4e18c27ca9158fbdceb66408c8360c250a0789"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.danbot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.danbot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 440fb77c2430 41beffff0000 4885ff 7412 410fb7d7 488bcf e8???????? }
            // n = 7, score = 200
            //   440fb77c2430         | lea                 ebx, [esp + 0x610]
            //   41beffff0000         | dec                 ecx
            //   4885ff               | mov                 ebx, dword ptr [ebx + 0x20]
            //   7412                 | dec                 ecx
            //   410fb7d7             | mov                 esi, dword ptr [ebx + 0x28]
            //   488bcf               | dec                 eax
            //   e8????????           |                     

        $sequence_1 = { e8???????? 488b4d10 4533d2 eba8 488b4d10 488d4500 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   488b4d10             | mov                 ecx, ebx
            //   4533d2               | dec                 esp
            //   eba8                 | lea                 esp, [edi + edi]
            //   488b4d10             | dec                 eax
            //   488d4500             | cmp                 dword ptr [ebx + 0x18], 8

        $sequence_2 = { 4d8bc6 498bcf e8???????? e9???????? 4883fe10 7217 }
            // n = 6, score = 200
            //   4d8bc6               | mov                 dword ptr [eax + edx*8 + 8], ecx
            //   498bcf               | jae                 0x3c2
            //   e8????????           |                     
            //   e9????????           |                     
            //   4883fe10             | dec                 eax
            //   7217                 | mov                 ecx, dword ptr [ebx + 8]

        $sequence_3 = { c644243001 4883c702 4983ed01 75d6 e9???????? 0f29442430 488d7dbf }
            // n = 7, score = 200
            //   c644243001           | movups              xmm1, xmmword ptr [esi + 0x10]
            //   4883c702             | movups              xmmword ptr [ebp - 0x29], xmm1
            //   4983ed01             | dec                 esp
            //   75d6                 | mov                 dword ptr [esi + 0x10], ebp
            //   e9????????           |                     
            //   0f29442430           | dec                 eax
            //   488d7dbf             | mov                 dword ptr [esi + 0x18], edi

        $sequence_4 = { eb03 4d8be3 488b442448 8b5818 81e3c0010000 895c2424 83fb40 }
            // n = 7, score = 200
            //   eb03                 | movzx               ebx, byte ptr [ebp + 0x7f]
            //   4d8be3               | dec                 eax
            //   488b442448           | mov                 edi, dword ptr [edx + 0x48]
            //   8b5818               | inc                 ecx
            //   81e3c0010000         | test                dword ptr [ecx + 0x18], 0x4000
            //   895c2424             | jne                 0xfd0
            //   83fb40               | inc                 ecx

        $sequence_5 = { 4983c8ff 49ffc0 46383402 75f7 488d4db0 e8???????? 488d45b0 }
            // n = 7, score = 200
            //   4983c8ff             | sar                 edx, 2
            //   49ffc0               | inc                 ecx
            //   46383402             | mov                 eax, 4
            //   75f7                 | je                  0x1e7
            //   488d4db0             | dec                 eax
            //   e8????????           |                     
            //   488d45b0             | mov                 ecx, ebx

        $sequence_6 = { 418ade 488bcf e8???????? 498bd7 488bcf e8???????? 84c0 }
            // n = 7, score = 200
            //   418ade               | dec                 eax
            //   488bcf               | test                eax, eax
            //   e8????????           |                     
            //   498bd7               | je                  0x154e
            //   488bcf               | xor                 esi, esi
            //   e8????????           |                     
            //   84c0                 | dec                 eax

        $sequence_7 = { eb03 488bc3 6644893448 eb22 48837b1808 7205 488b03 }
            // n = 7, score = 200
            //   eb03                 | js                  0xaa3
            //   488bc3               | inc                 ecx
            //   6644893448           | cmp                 byte ptr [edi], 0
            //   eb22                 | inc                 ecx
            //   48837b1808           | mov                 byte ptr [edi], 1
            //   7205                 | dec                 ecx
            //   488b03               | add                 dword ptr [esi], 2

        $sequence_8 = { 48837dff10 732c 4533c0 418d5008 488d4def e8???????? 4c8b4597 }
            // n = 7, score = 200
            //   48837dff10           | dec                 eax
            //   732c                 | lea                 eax, [0x42471]
            //   4533c0               | dec                 eax
            //   418d5008             | mov                 esi, eax
            //   488d4def             | dec                 eax
            //   e8????????           |                     
            //   4c8b4597             | mov                 dword ptr [ebp - 0x60], eax

        $sequence_9 = { 90 e9???????? 84c9 0f8453020000 8b442430 85c0 7408 }
            // n = 7, score = 200
            //   90                   | mov                 ecx, ebx
            //   e9????????           |                     
            //   84c9                 | dec                 eax
            //   0f8453020000         | lea                 edx, [0x4cb04]
            //   8b442430             | dec                 eax
            //   85c0                 | mov                 ecx, ebx
            //   7408                 | dec                 eax

    condition:
        7 of them and filesize < 1492992
}
