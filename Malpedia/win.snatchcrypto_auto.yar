rule win_snatchcrypto_auto {

    meta:
        id = "2HYQO1io4125GBsCkOlMHr"
        fingerprint = "v1_sha256_df174efff90118ed4513d3543230102fa070bff240e3fca742525b945490dabd"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.snatchcrypto."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snatchcrypto"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 413ac5 740d 3c03 7514 80be9102000000 750b f6c180 }
            // n = 7, score = 200
            //   413ac5               | dec                 eax
            //   740d                 | lea                 edx, [0x2756d]
            //   3c03                 | inc                 ecx
            //   7514                 | mov                 eax, 0xfc
            //   80be9102000000       | inc                 esp
            //   750b                 | mov                 ecx, ebx
            //   f6c180               | dec                 ecx

        $sequence_1 = { 0100 d3da 0100 4bdb01 0038 db01 0096db010096 }
            // n = 7, score = 200
            //   0100                 | mov                 ecx, ebx
            //   d3da                 | mov                 byte ptr [ebx + 0x950], 0
            //   0100                 | dec                 eax
            //   4bdb01               | mov                 ecx, dword ptr [ebx + 0x160]
            //   0038                 | dec                 eax
            //   db01                 | mov                 dword ptr [ebx + 0x170], edi
            //   0096db010096         | dec                 eax

        $sequence_2 = { 4c8d25e5930300 41c70701000000 e9???????? 498b95b8000000 488d0dc3930300 41b805000000 e8???????? }
            // n = 7, score = 200
            //   4c8d25e5930300       | mov                 dword ptr [esp + 0x2ab0], eax
            //   41c70701000000       | dec                 eax
            //   e9????????           |                     
            //   498b95b8000000       | sub                 esp, eax
            //   488d0dc3930300       | dec                 eax
            //   41b805000000         | mov                 dword ptr [esp + 0x38], 0xfffffffe
            //   e8????????           |                     

        $sequence_3 = { 7821 0f1f840000000000 4533c9 488d542420 488bcb 458d4120 ff15???????? }
            // n = 7, score = 200
            //   7821                 | dec                 eax
            //   0f1f840000000000     | mov                 dword ptr [esp + 8], ebx
            //   4533c9               | push                edi
            //   488d542420           | dec                 eax
            //   488bcb               | sub                 esp, 0x20
            //   458d4120             | dec                 eax
            //   ff15????????         |                     

        $sequence_4 = { e9???????? 488bd3 498bcd e8???????? 85c0 7414 488d15669d0300 }
            // n = 7, score = 200
            //   e9????????           |                     
            //   488bd3               | dec                 eax
            //   498bcd               | mov                 ecx, dword ptr [ebx + 0x130]
            //   e8????????           |                     
            //   85c0                 | mov                 dword ptr [ebx + 0x138], eax
            //   7414                 | inc                 esp
            //   488d15669d0300       | mov                 eax, dword ptr [ebx + 0x138]

        $sequence_5 = { 412bc9 4103cf 3bce 0f42f1 418bcf 482bd1 8bcd }
            // n = 7, score = 200
            //   412bc9               | mov                 dword ptr [ebx + 0x390], 1
            //   4103cf               | mov                 edx, 0xa
            //   3bce                 | dec                 eax
            //   0f42f1               | mov                 ecx, ebx
            //   418bcf               | dec                 eax
            //   482bd1               | lea                 edx, [0x2b962]
            //   8bcd                 | inc                 ecx

        $sequence_6 = { 413bc4 0f87d3000000 6685f6 0f84c5000000 41bd04000000 0f1f00 66443bee }
            // n = 7, score = 200
            //   413bc4               | dec                 eax
            //   0f87d3000000         | test                eax, eax
            //   6685f6               | je                  0x141a
            //   0f84c5000000         | dec                 esp
            //   41bd04000000         | lea                 eax, [0x21758]
            //   0f1f00               | dec                 eax
            //   66443bee             | lea                 edx, [0x26074]

        $sequence_7 = { 498d4b02 488d942450020000 482bd1 0fb701 4883c102 6689440afe 6685c0 }
            // n = 7, score = 200
            //   498d4b02             | dec                 eax
            //   488d942450020000     | lea                 ecx, [esi + 0x20]
            //   482bd1               | dec                 esp
            //   0fb701               | mov                 ebx, eax
            //   4883c102             | dec                 eax
            //   6689440afe           | mov                 dword ptr [ebp], eax
            //   6685c0               | dec                 eax

        $sequence_8 = { 753f 488b5f08 4883c708 4885db 75e4 488d157dd30300 4d8bc4 }
            // n = 7, score = 200
            //   753f                 | lea                 eax, [0x284aa]
            //   488b5f08             | dec                 esp
            //   4883c708             | lea                 eax, [0x283ab]
            //   4885db               | dec                 eax
            //   75e4                 | lea                 edx, [0x28490]
            //   488d157dd30300       | dec                 esp
            //   4d8bc4               | cmove               eax, eax

        $sequence_9 = { 488bd9 4883c108 33f6 e8???????? 85c0 7413 817b3463feffff }
            // n = 7, score = 200
            //   488bd9               | dec                 eax
            //   4883c108             | mov                 ecx, ebp
            //   33f6                 | xor                 ebx, ebx
            //   e8????????           |                     
            //   85c0                 | jg                  0xfa8
            //   7413                 | xor                 eax, eax
            //   817b3463feffff       | dec                 eax

    condition:
        7 of them and filesize < 1400832
}
