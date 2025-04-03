rule win_touchmove_auto {

    meta:
        id = "6JIuPE1nvUMve7QTr6j6Kh"
        fingerprint = "v1_sha256_519a7e3bd048a6a0769391087a62b1ec389f7202cc576a740e9eb0fb3d43844d"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.touchmove."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.touchmove"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 41b800040000 488d8c2452010000 e8???????? 4c8d442448 488d152df90000 }
            // n = 5, score = 100
            //   41b800040000         | movdqa              xmmword ptr [ebp + 0x2220], xmm5
            //   488d8c2452010000     | mov                 byte ptr [ebp + 0x2232], 0
            //   e8????????           |                     
            //   4c8d442448           | dec                 eax
            //   488d152df90000       | lea                 ecx, [ebp + 0xa20]

        $sequence_1 = { 488d157af70000 488d8d90000000 e8???????? 4c8d8590000000 33d2 33c9 }
            // n = 6, score = 100
            //   488d157af70000       | lea                 ecx, [esp + 0x152]
            //   488d8d90000000       | mov                 word ptr [ebp + 0x4d90], si
            //   e8????????           |                     
            //   4c8d8590000000       | xor                 edx, edx
            //   33d2                 | inc                 ecx
            //   33c9                 | mov                 eax, 0x400

        $sequence_2 = { 7528 48833d????????00 741e 488d0d499f0000 e8???????? 85c0 }
            // n = 6, score = 100
            //   7528                 | dec                 eax
            //   48833d????????00     |                     
            //   741e                 | mov                 eax, edx
            //   488d0d499f0000       | and                 edx, 0x1f
            //   e8????????           |                     
            //   85c0                 | jae                 0x99c

        $sequence_3 = { 41b8ee000000 488d8d92430000 e8???????? c6858044000000 33d2 41b8ff000000 488d8d81440000 }
            // n = 7, score = 100
            //   41b8ee000000         | inc                 ecx
            //   488d8d92430000       | test                byte ptr [edi + eax + 8], 0x40
            //   e8????????           |                     
            //   c6858044000000       | je                  0xd89
            //   33d2                 | inc                 ecx
            //   41b8ff000000         | cmp                 byte ptr [ebp], 0x1a
            //   488d8d81440000       | je                  0x6bb

        $sequence_4 = { ff15???????? 488d442450 4889442420 458bce 4533c0 488d9580410000 48c7c102000080 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488d442450           | mov                 ecx, dword ptr [esi + 0xb8]
            //   4889442420           | dec                 esp
            //   458bce               | lea                 esp, [0xfd4f]
            //   4533c0               | lock dec            dword ptr [ecx]
            //   488d9580410000       | jne                 0x720
            //   48c7c102000080       | inc                 esp

        $sequence_5 = { 0f8514010000 4c8d2d36cd0000 41b804010000 668935???????? 498bd5 ff15???????? 418d7c24e7 }
            // n = 7, score = 100
            //   0f8514010000         | mov                 ecx, ebx
            //   4c8d2d36cd0000       | dec                 eax
            //   41b804010000         | mov                 ecx, ebx
            //   668935????????       |                     
            //   498bd5               | dec                 eax
            //   ff15????????         |                     
            //   418d7c24e7           | lea                 edx, [ebp + 0x520]

        $sequence_6 = { 48833d????????00 0f844d040000 48833d????????00 0f843f040000 }
            // n = 4, score = 100
            //   48833d????????00     |                     
            //   0f844d040000         | inc                 ecx
            //   48833d????????00     |                     
            //   0f843f040000         | mov                 ecx, 4

        $sequence_7 = { 833d????????00 7505 e8???????? 488d3d40e00000 41b804010000 }
            // n = 5, score = 100
            //   833d????????00       |                     
            //   7505                 | dec                 eax
            //   e8????????           |                     
            //   488d3d40e00000       | and                 dword ptr [esp + 0x30], 0
            //   41b804010000         | and                 dword ptr [esp + 0x28], 0

        $sequence_8 = { 488bfb 488bf3 48c1fe05 4c8d25bebd0000 83e71f 486bff58 }
            // n = 6, score = 100
            //   488bfb               | inc                 ecx
            //   488bf3               | mov                 eax, 0x98
            //   48c1fe05             | dec                 ecx
            //   4c8d25bebd0000       | mov                 esi, ecx
            //   83e71f               | dec                 ebp
            //   486bff58             | mov                 ebp, esi

        $sequence_9 = { 8bc8 e8???????? ebc9 488bcb 488bc3 488d1597e40000 48c1f805 }
            // n = 7, score = 100
            //   8bc8                 | inc                 ecx
            //   e8????????           |                     
            //   ebc9                 | pop                 edi
            //   488bcb               | xor                 eax, eax
            //   488bc3               | dec                 eax
            //   488d1597e40000       | or                  ecx, 0xffffffff
            //   48c1f805             | dec                 eax

    condition:
        7 of them and filesize < 224256
}
