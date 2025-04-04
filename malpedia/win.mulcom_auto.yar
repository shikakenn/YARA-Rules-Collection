rule win_mulcom_auto {

    meta:
        id = "6GIwvkPn3VUrOPm3LP1wtc"
        fingerprint = "v1_sha256_372ee2b3e45726bdecfcc73339ca35421a12f3ab3e84538dcc5c7a553f146e2b"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mulcom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mulcom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488b442448 4839442440 0f84fc010000 488d15136d0300 488d4dc8 e8???????? 90 }
            // n = 7, score = 100
            //   488b442448           | dec                 ecx
            //   4839442440           | mov                 esi, dword ptr [ebx + 0x40]
            //   0f84fc010000         | dec                 ecx
            //   488d15136d0300       | mov                 esp, ebx
            //   488d4dc8             | inc                 ecx
            //   e8????????           |                     
            //   90                   | pop                 esi

        $sequence_1 = { e8???????? 488d4c2450 48837c246810 480f434c2450 4c897c2438 4c897c2430 895c2428 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d4c2450           | mov                 ebx, ecx
            //   48837c246810         | dec                 eax
            //   480f434c2450         | cmp                 edx, 0x10
            //   4c897c2438           | jb                  0x1176
            //   4c897c2430           | dec                 eax
            //   895c2428             | mov                 ecx, dword ptr [ecx + 0x48]

        $sequence_2 = { 740b 488d4900 83c102 d1ea 75f9 4183f802 }
            // n = 6, score = 100
            //   740b                 | inc                 ebp
            //   488d4900             | mov                 eax, esp
            //   83c102               | xor                 edx, edx
            //   d1ea                 | dec                 eax
            //   75f9                 | mov                 dword ptr [ebp + 0x4270], eax
            //   4183f802             | dec                 esp

        $sequence_3 = { 4533c9 33c9 448d4602 41ffd5 85c0 0f85c9050000 33c0 }
            // n = 7, score = 100
            //   4533c9               | inc                 ecx
            //   33c9                 | mov                 cl, bl
            //   448d4602             | inc                 ecx
            //   41ffd5               | mov                 byte ptr [edx], cl
            //   85c0                 | dec                 ebp
            //   0f85c9050000         | mov                 eax, ebx
            //   33c0                 | inc                 ecx

        $sequence_4 = { 488b05???????? 4833c4 488985a0040000 4c8b9508050000 488d056c5f0200 0f1000 4c8bd9 }
            // n = 7, score = 100
            //   488b05????????       |                     
            //   4833c4               | lea                 edx, [0x46036]
            //   488985a0040000       | dec                 eax
            //   4c8b9508050000       | lea                 ecx, [esp + 0x30]
            //   488d056c5f0200       | dec                 esp
            //   0f1000               | mov                 eax, dword ptr [ebx + 0x10]
            //   4c8bd9               | dec                 eax

        $sequence_5 = { 85c9 7835 8b542438 85d2 782d 448b44243c 4585c0 }
            // n = 7, score = 100
            //   85c9                 | dec                 eax
            //   7835                 | lea                 ebx, [0x2e855]
            //   8b542438             | dec                 eax
            //   85d2                 | cmp                 ecx, ebx
            //   782d                 | je                  0x1fba
            //   448b44243c           | dec                 eax
            //   4585c0               | mov                 eax, 0xa0a0a0a1

        $sequence_6 = { ff15???????? 0f104588 0f1145c8 0f104d98 0f114dd8 660f6f05???????? f30f7f4598 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   0f104588             | cmovbe              ecx, edx
            //   0f1145c8             | dec                 eax
            //   0f104d98             | test                eax, eax
            //   0f114dd8             | je                  0x65b
            //   660f6f05????????     |                     
            //   f30f7f4598           | dec                 eax

        $sequence_7 = { 48c1e83f 4803d0 49ba8661188661188601 493bd2 0f84f9010000 4c8d7a01 488b4e10 }
            // n = 7, score = 100
            //   48c1e83f             | je                  0x180f
            //   4803d0               | inc                 ecx
            //   49ba8661188661188601     | cmp    ecx, dword ptr [esi + 0x10]
            //   493bd2               | jbe                 0x157c
            //   0f84f9010000         | inc                 ecx
            //   4c8d7a01             | mov                 dword ptr [esi + 0x10], ecx
            //   488b4e10             | mov                 edx, ecx

        $sequence_8 = { 488bcb e8???????? 4883ef01 75c9 488bc3 488b5c2448 4883c430 }
            // n = 7, score = 100
            //   488bcb               | dec                 eax
            //   e8????????           |                     
            //   4883ef01             | mov                 ecx, dword ptr [ebp - 0x39]
            //   75c9                 | test                eax, eax
            //   488bc3               | sete                bl
            //   488b5c2448           | dec                 eax
            //   4883c430             | lea                 ecx, [esp + 0x68]

        $sequence_9 = { 49baa1a0a0a0a0a0a0a0 4c8bf1 498bc2 488b4908 498be8 49f7e9 }
            // n = 6, score = 100
            //   49baa1a0a0a0a0a0a0a0     | ja    0x9bd
            //   4c8bf1               | movdqu              xmmword ptr [ebp - 0x40], xmm0
            //   498bc2               | dec                 eax
            //   488b4908             | add                 eax, -8
            //   498be8               | dec                 eax
            //   49f7e9               | cmp                 eax, 0x1f

    condition:
        7 of them and filesize < 867328
}
