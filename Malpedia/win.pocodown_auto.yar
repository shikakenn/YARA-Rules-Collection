rule win_pocodown_auto {

    meta:
        id = "5GCe1vwA5spbQiXxbwRu23"
        fingerprint = "v1_sha256_0c989d45fa577d150beb78b93b7b2b3b8b608ef00eacc1f315d54d3fff02abed"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.pocodown."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pocodown"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ffe1 8b44243c 8bcb 8bd3 39450c 0f94c1 413bcb }
            // n = 7, score = 200
            //   ffe1                 | mov                 dword ptr [esp + 0x30], eax
            //   8b44243c             | dec                 eax
            //   8bcb                 | test                eax, eax
            //   8bd3                 | je                  0x70a
            //   39450c               | mov                 ecx, 0x10
            //   0f94c1               | dec                 eax
            //   413bcb               | mov                 edi, eax

        $sequence_1 = { eb1b 488b542448 488b4c2430 e8???????? e9???????? 488b442430 eb13 }
            // n = 7, score = 200
            //   eb1b                 | lea                 ecx, [ebp - 0x30]
            //   488b542448           | dec                 eax
            //   488b4c2430           | mov                 edx, ebx
            //   e8????????           |                     
            //   e9????????           |                     
            //   488b442430           | dec                 eax
            //   eb13                 | lea                 edx, [0x258868]

        $sequence_2 = { e8???????? 4533c0 488d542430 488d4c2450 e8???????? 488d4c2450 e8???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   4533c0               | dec                 eax
            //   488d542430           | mov                 ebx, ecx
            //   488d4c2450           | cmp                 byte ptr [ecx + 8], 0
            //   e8????????           |                     
            //   488d4c2450           | jne                 0x1330
            //   e8????????           |                     

        $sequence_3 = { eb02 8bd6 f6c202 7408 49ffc2 493bc0 75dc }
            // n = 7, score = 200
            //   eb02                 | dec                 eax
            //   8bd6                 | mov                 ecx, dword ptr [esp + 0x20]
            //   f6c202               | dec                 eax
            //   7408                 | mov                 dword ptr [ecx + 0x18], eax
            //   49ffc2               | dec                 eax
            //   493bc0               | mov                 eax, dword ptr [esp + 0x20]
            //   75dc                 | dec                 eax

        $sequence_4 = { c744242002000000 e9???????? 33c0 83f801 0f844f010000 48b80000000001000000 4839442450 }
            // n = 7, score = 200
            //   c744242002000000     | mov                 ecx, 0x128
            //   e9????????           |                     
            //   33c0                 | dec                 eax
            //   83f801               | mov                 dword ptr [esp + 0x20], eax
            //   0f844f010000         | dec                 eax
            //   48b80000000001000000     | cmp    dword ptr [esp + 0x20], 0
            //   4839442450           | jne                 0x149f

        $sequence_5 = { eb38 8b842480000000 89442420 4c8b4c2458 488b442478 4c8b4020 488d15f0bf1e00 }
            // n = 7, score = 200
            //   eb38                 | test                eax, eax
            //   8b842480000000       | dec                 eax
            //   89442420             | mov                 dword ptr [esp + 0xc8], 0xf
            //   4c8b4c2458           | dec                 esp
            //   488b442478           | mov                 dword ptr [esp + 0xc0], esi
            //   4c8b4020             | mov                 byte ptr [esp + 0xb0], 0
            //   488d15f0bf1e00       | dec                 eax

        $sequence_6 = { e8???????? 482be0 488b442450 4883781000 740c 488b442450 4883781800 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   482be0               | inc                 ecx
            //   488b442450           | movups              xmmword ptr [ebp], xmm0
            //   4883781000           | dec                 eax
            //   740c                 | cmp                 dword ptr [ebp - 0x29], 0x10
            //   488b442450           | jb                  0x11c9
            //   4883781800           | mov                 byte ptr [ebp - 0x61], 1

        $sequence_7 = { ff5010 85c0 7507 33c0 e9???????? 488b442460 488b4008 }
            // n = 7, score = 200
            //   ff5010               | dec                 eax
            //   85c0                 | mov                 dword ptr [esp + 0x20], ecx
            //   7507                 | mov                 ecx, dword ptr [esp + 0x70]
            //   33c0                 | add                 ecx, eax
            //   e9????????           |                     
            //   488b442460           | mov                 eax, ecx
            //   488b4008             | mov                 dword ptr [esp + 0x70], eax

        $sequence_8 = { e8???????? 33c0 e9???????? 486344244c 488b4c2438 4803c8 488bc1 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   33c0                 | mov                 eax, ebx
            //   e9????????           |                     
            //   486344244c           | dec                 eax
            //   488b4c2438           | sub                 eax, edx
            //   4803c8               | test                al, 1
            //   488bc1               | je                  0xb3d

        $sequence_9 = { e8???????? 85c0 7505 e9???????? 837c243841 7e05 e9???????? }
            // n = 7, score = 200
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7505                 | cwde                
            //   e9????????           |                     
            //   837c243841           | dec                 eax
            //   7e05                 | mov                 edx, eax
            //   e9????????           |                     

    condition:
        7 of them and filesize < 6703104
}
