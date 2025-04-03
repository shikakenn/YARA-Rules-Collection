rule win_mechanical_auto {

    meta:
        id = "QXHrAlg9ftPmSIiuzqZPk"
        fingerprint = "v1_sha256_94b14ca845d1ee4d0c436cd1fe538aa0afa038eac7ee0713fa70a64141fc5c86"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mechanical."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mechanical"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488d0d7a500000 ff15???????? 4885c0 488be8 }
            // n = 4, score = 200
            //   488d0d7a500000       | mov                 eax, esp
            //   ff15????????         |                     
            //   4885c0               | nop                 
            //   488be8               | dec                 eax

        $sequence_1 = { 033485c0e54200 8b45e4 8b00 8906 }
            // n = 4, score = 200
            //   033485c0e54200       | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]
            //   8b00                 | mov                 eax, dword ptr [eax]
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_2 = { 03c7 3bca 72ed 5f }
            // n = 4, score = 200
            //   03c7                 | add                 eax, edi
            //   3bca                 | cmp                 ecx, edx
            //   72ed                 | jb                  0xffffffef
            //   5f                   | pop                 edi

        $sequence_3 = { 4983c001 84c9 7409 4983c101 }
            // n = 4, score = 200
            //   4983c001             | xor                 eax, eax
            //   84c9                 | dec                 eax
            //   7409                 | mov                 edi, dword ptr [esp + 0x168]
            //   4983c101             | dec                 eax

        $sequence_4 = { 0401 3cbe 8844240b 76e2 }
            // n = 4, score = 200
            //   0401                 | add                 al, 1
            //   3cbe                 | cmp                 al, 0xbe
            //   8844240b             | mov                 byte ptr [esp + 0xb], al
            //   76e2                 | jbe                 0xffffffe4

        $sequence_5 = { 03c1 1bc9 0bc1 59 e9???????? e8???????? ff742404 }
            // n = 7, score = 200
            //   03c1                 | add                 eax, ecx
            //   1bc9                 | sbb                 ecx, ecx
            //   0bc1                 | or                  eax, ecx
            //   59                   | pop                 ecx
            //   e9????????           |                     
            //   e8????????           |                     
            //   ff742404             | push                dword ptr [esp + 4]

        $sequence_6 = { 90 0100 e392 0100 c88f0100 }
            // n = 5, score = 200
            //   90                   | ja                  0xc
            //   0100                 | add                 al, 0x20
            //   e392                 | inc                 ecx
            //   0100                 | mov                 eax, 1
            //   c88f0100             | mov                 byte ptr [edx], al

        $sequence_7 = { 84c0 0f8409000000 4983c001 4885c9 75e8 4585c0 0f84d0010000 }
            // n = 7, score = 200
            //   84c0                 | lea                 ecx, [0x507a]
            //   0f8409000000         | dec                 eax
            //   4983c001             | test                eax, eax
            //   4885c9               | dec                 eax
            //   75e8                 | mov                 ebp, eax
            //   4585c0               | test                al, al
            //   0f84d0010000         | je                  0xf

        $sequence_8 = { 3c5a 770a 0420 41b801000000 8802 }
            // n = 5, score = 200
            //   3c5a                 | dec                 ecx
            //   770a                 | add                 eax, 1
            //   0420                 | dec                 eax
            //   41b801000000         | test                ecx, ecx
            //   8802                 | jne                 0xfffffff7

        $sequence_9 = { 75ed 488d8c2460210000 4d8bc4 6690 }
            // n = 4, score = 200
            //   75ed                 | jne                 0xffffffef
            //   488d8c2460210000     | dec                 eax
            //   4d8bc4               | lea                 ecx, [esp + 0x2160]
            //   6690                 | dec                 ebp

        $sequence_10 = { 030495c0e54200 eb05 b8???????? f6400420 }
            // n = 4, score = 200
            //   030495c0e54200       | add                 eax, dword ptr [edx*4 + 0x42e5c0]
            //   eb05                 | jmp                 7
            //   b8????????           |                     
            //   f6400420             | test                byte ptr [eax + 4], 0x20

        $sequence_11 = { 00686c 42 0023 d18a0688078a }
            // n = 4, score = 200
            //   00686c               | add                 byte ptr [eax + 0x6c], ch
            //   42                   | inc                 edx
            //   0023                 | add                 byte ptr [ebx], ah
            //   d18a0688078a         | ror                 dword ptr [edx - 0x75f877fa], 1

        $sequence_12 = { 33c0 488bbc2468010000 488b9c2460010000 488b8c2430010000 }
            // n = 4, score = 200
            //   33c0                 | inc                 ebp
            //   488bbc2468010000     | test                eax, eax
            //   488b9c2460010000     | je                  0x1d9
            //   488b8c2430010000     | cmp                 al, 0x5a

        $sequence_13 = { 4885c9 75ec 4585c0 0f84bd010000 }
            // n = 4, score = 200
            //   4885c9               | mov                 ebx, dword ptr [esp + 0x160]
            //   75ec                 | dec                 eax
            //   4585c0               | mov                 ecx, dword ptr [esp + 0x130]
            //   0f84bd010000         | nop                 

        $sequence_14 = { 03ce c6840c3801000000 8d8424a05c0000 33f6 }
            // n = 4, score = 200
            //   03ce                 | add                 ecx, esi
            //   c6840c3801000000     | mov                 byte ptr [esp + ecx + 0x138], 0
            //   8d8424a05c0000       | lea                 eax, [esp + 0x5ca0]
            //   33f6                 | xor                 esi, esi

        $sequence_15 = { 033485c0e54200 c745e401000000 33db 395e08 }
            // n = 4, score = 200
            //   033485c0e54200       | add                 esi, dword ptr [eax*4 + 0x42e5c0]
            //   c745e401000000       | mov                 dword ptr [ebp - 0x1c], 1
            //   33db                 | xor                 ebx, ebx
            //   395e08               | cmp                 dword ptr [esi + 8], ebx

    condition:
        7 of them and filesize < 434176
}
