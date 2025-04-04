rule win_atomsilo_auto {

    meta:
        id = "47fM89VHybeFMNob8EBInc"
        fingerprint = "v1_sha256_e09362cc7b2f3a6215eeee28b5549da2887bc59c3f8b5fb41ad869fd5e8818fd"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.atomsilo."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atomsilo"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4863c9 488d1506760900 33440a02 8b4c2438 ffc1 8bc9 488b542430 }
            // n = 7, score = 100
            //   4863c9               | mov                 al, 0x30
            //   488d1506760900       | dec                 eax
            //   33440a02             | lea                 ecx, [esp + 0x30]
            //   8b4c2438             | dec                 eax
            //   ffc1                 | lea                 eax, [0x5d028]
            //   8bc9                 | dec                 eax
            //   488b542430           | xor                 eax, esp

        $sequence_1 = { 488bca e8???????? 90 0fbae60c 7336 0fbaf60c 89b500010000 }
            // n = 7, score = 100
            //   488bca               | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 edi, dword ptr [esp + 0xa0]
            //   0fbae60c             | dec                 eax
            //   7336                 | mov                 esi, dword ptr [esp + 0xe0]
            //   0fbaf60c             | inc                 ecx
            //   89b500010000         | mov                 byte ptr [esi + 0xe8], 1

        $sequence_2 = { 0f84c7010000 498b4020 0fb600 2401 0f84b8010000 488d04bd00000000 488985e0000000 }
            // n = 7, score = 100
            //   0f84c7010000         | movups              xmmword ptr [ebp + 0x1f], xmm1
            //   498b4020             | inc                 ecx
            //   0fb600               | and                 esp, 0xfffffffd
            //   2401                 | dec                 ebp
            //   0f84b8010000         | test                ebp, ebp
            //   488d04bd00000000     | je                  0x7bb
            //   488985e0000000       | movups              xmm1, xmmword ptr [eax + 0x10]

        $sequence_3 = { 488b9308010000 4885d2 7415 488bfa 33c0 488b0c19 f348ab }
            // n = 7, score = 100
            //   488b9308010000       | mov                 esi, dword ptr [esp + 0x38]
            //   4885d2               | dec                 eax
            //   7415                 | add                 esp, 0x20
            //   488bfa               | pop                 edi
            //   33c0                 | ret                 
            //   488b0c19             | xor                 al, al
            //   f348ab               | dec                 eax

        $sequence_4 = { 90 488bd0 488d4e60 e8???????? 90 488b4d60 48394d58 }
            // n = 7, score = 100
            //   90                   | dec                 eax
            //   488bd0               | test                ebx, ebx
            //   488d4e60             | jne                 0x42
            //   e8????????           |                     
            //   90                   | lea                 ecx, [ebx + 8]
            //   488b4d60             | dec                 eax
            //   48394d58             | mov                 ebx, eax

        $sequence_5 = { 4053 4883ec30 488d0dc7340800 c705????????01000000 ff15???????? 488bd8 48331d???????? }
            // n = 7, score = 100
            //   4053                 | dec                 eax
            //   4883ec30             | mov                 eax, dword ptr [ecx]
            //   488d0dc7340800       | dec                 eax
            //   c705????????01000000     |     
            //   ff15????????         |                     
            //   488bd8               | mov                 ebx, edx
            //   48331d????????       |                     

        $sequence_6 = { 0f44ca 418bc4 8bd1 2bc1 83f801 77de 412bec }
            // n = 7, score = 100
            //   0f44ca               | lea                 ebx, [edx - 0x70e44324]
            //   418bc4               | xor                 ebp, dword ptr [esp + 0xc]
            //   8bd1                 | add                 ebx, ecx
            //   2bc1                 | mov                 edi, dword ptr [esp + 4]
            //   83f801               | inc                 ecx
            //   77de                 | xor                 ebp, esi
            //   412bec               | add                 ecx, ebx

        $sequence_7 = { 4889442438 488bd8 4885c0 7443 488d05a57b0300 be04000000 488903 }
            // n = 7, score = 100
            //   4889442438           | stosd               dword ptr es:[edi], eax
            //   488bd8               | dec                 eax
            //   4885c0               | mov                 dword ptr [eax], ebp
            //   7443                 | dec                 esp
            //   488d05a57b0300       | mov                 ecx, edi
            //   be04000000           | dec                 esp
            //   488903               | mov                 eax, esi

        $sequence_8 = { e8???????? 418bd4 84c0 0f94c2 488d4def e8???????? 90 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   418bd4               | mov                 byte ptr [ebp - 0x7f], 0x61
            //   84c0                 | mov                 byte ptr [ebp - 0x7e], 0x72
            //   0f94c2               | mov                 byte ptr [ebp - 0x7d], 0x2e
            //   488d4def             | mov                 byte ptr [ebp - 0x7c], 0x2d
            //   e8????????           |                     
            //   90                   | mov                 byte ptr [ebp - 0x7b], 0x3c

        $sequence_9 = { 48895608 488b5c2470 4883c430 415f 415e 415c 5f }
            // n = 7, score = 100
            //   48895608             | dec                 eax
            //   488b5c2470           | mov                 dword ptr [edi + 0x78], eax
            //   4883c430             | dec                 eax
            //   415f                 | lea                 eax, [0x80306]
            //   415e                 | dec                 eax
            //   415c                 | mov                 dword ptr [ebx], eax
            //   5f                   | dec                 eax

    condition:
        7 of them and filesize < 1785856
}
