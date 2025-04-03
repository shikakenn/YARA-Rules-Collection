rule win_clipog_auto {

    meta:
        id = "74CxsoD59Nq4Lt2PitOhLK"
        fingerprint = "v1_sha256_5f63443ad5edf1c4dcbd4a8d4fd0cdcfd536873049176b0dcfc08c2019029b24"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.clipog."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clipog"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 736a 488bfb 4c8d358e520100 83e73f 488bf3 48c1fe06 }
            // n = 6, score = 100
            //   736a                 | dec                 eax
            //   488bfb               | sub                 esp, 0x30
            //   4c8d358e520100       | dec                 eax
            //   83e73f               | mov                 eax, edx
            //   488bf3               | xor                 esi, esi
            //   48c1fe06             | dec                 eax

        $sequence_1 = { b910000000 ff15???????? 488b4b18 6685c0 740c 488d15e2e70100 e9???????? }
            // n = 7, score = 100
            //   b910000000           | movzx               eax, word ptr [ecx + edi*4 + 0x1d3f0]
            //   ff15????????         |                     
            //   488b4b18             | lea                 eax, [eax + eax*4]
            //   6685c0               | add                 eax, eax
            //   740c                 | sub                 ecx, eax
            //   488d15e2e70100       | je                  0x318
            //   e9????????           |                     

        $sequence_2 = { 488bca 4c8d05359e0100 83e13f 488bc2 48c1f806 }
            // n = 5, score = 100
            //   488bca               | dec                 eax
            //   4c8d05359e0100       | cmp                 ecx, edx
            //   83e13f               | je                  0x25f
            //   488bc2               | dec                 eax
            //   48c1f806             | mov                 dword ptr [esp + 0x60], ebx

        $sequence_3 = { 4881ecd0010000 48c7442438feffffff 48899c2410020000 488b05???????? }
            // n = 4, score = 100
            //   4881ecd0010000       | mov                 edx, edi
            //   48c7442438feffffff     | dec    eax
            //   48899c2410020000     | mov                 ecx, dword ptr [esi + 0x1810]
            //   488b05????????       |                     

        $sequence_4 = { 8d0480 03c0 8bcf 2bc8 0f841f050000 8d41ff 8b848288d40100 }
            // n = 7, score = 100
            //   8d0480               | dec                 eax
            //   03c0                 | mov                 ebx, dword ptr [esp + 0x30]
            //   8bcf                 | mov                 dword ptr [ebx + 0x50], eax
            //   2bc8                 | jmp                 0x1b6
            //   0f841f050000         | dec                 eax
            //   8d41ff               | test                esi, esi
            //   8b848288d40100       | jne                 0x17a

        $sequence_5 = { 48ffc5 ff15???????? 85c0 747d 83bc249000000000 7473 4c8d155a95feff }
            // n = 7, score = 100
            //   48ffc5               | dec                 eax
            //   ff15????????         |                     
            //   85c0                 | lea                 edx, [ebx + 8]
            //   747d                 | xor                 ecx, ecx
            //   83bc249000000000     | dec                 eax
            //   7473                 | mov                 dword ptr [edx], ecx
            //   4c8d155a95feff       | dec                 eax

        $sequence_6 = { 488d158ee80100 e9???????? 488d1592e80100 e9???????? 488d1596e80100 e9???????? }
            // n = 6, score = 100
            //   488d158ee80100       | dec                 eax
            //   e9????????           |                     
            //   488d1592e80100       | cmp                 ecx, eax
            //   e9????????           |                     
            //   488d1596e80100       | dec                 eax
            //   e9????????           |                     

        $sequence_7 = { 488b41f8 483bc1 7338 482bc8 4883f908 }
            // n = 5, score = 100
            //   488b41f8             | dec                 esp
            //   483bc1               | lea                 ecx, [0x1dd36]
            //   7338                 | inc                 ebp
            //   482bc8               | xor                 eax, eax
            //   4883f908             | xor                 edx, edx

        $sequence_8 = { 488bea 488bf1 4885d2 7515 4533f6 4c8931 488b6c2478 }
            // n = 7, score = 100
            //   488bea               | mov                 dword ptr [edi + 0x10], 0
            //   488bf1               | dec                 eax
            //   4885d2               | cmp                 dword ptr [edi + 0x18], 0x10
            //   7515                 | dec                 eax
            //   4533f6               | mov                 eax, dword ptr [edi + 0x18]
            //   4c8931               | dec                 eax
            //   488b6c2478           | cmp                 eax, ebp

        $sequence_9 = { 7457 48837b1808 48897310 7243 488b0b eb41 4883ff08 }
            // n = 7, score = 100
            //   7457                 | mov                 ecx, dword ptr [esp + 0x78]
            //   48837b1808           | dec                 eax
            //   48897310             | cmp                 eax, ebx
            //   7243                 | jbe                 0xa0
            //   488b0b               | int3                
            //   eb41                 | jb                  0xfa
            //   4883ff08             | dec                 eax

    condition:
        7 of them and filesize < 372736
}
