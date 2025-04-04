rule win_exaramel_auto {

    meta:
        id = "2176MXMFdMVEsqw5WOBQwh"
        fingerprint = "v1_sha256_18c202b1bcb977a24c7c95e5ee5eaa9ad9563136df2ac39652d73a4b9f53b5e1"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.exaramel."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.exaramel"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8d85d8faffff 50 ff15???????? 85c0 0f84fd000000 68???????? 8d85d8faffff }
            // n = 7, score = 100
            //   8d85d8faffff         | lea                 eax, [ebp - 0x528]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f84fd000000         | je                  0x103
            //   68????????           |                     
            //   8d85d8faffff         | lea                 eax, [ebp - 0x528]

        $sequence_1 = { 8945fc 53 8b5d0c 8d85f0fdffff }
            // n = 4, score = 100
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   53                   | push                ebx
            //   8b5d0c               | mov                 ebx, dword ptr [ebp + 0xc]
            //   8d85f0fdffff         | lea                 eax, [ebp - 0x210]

        $sequence_2 = { 56 56 50 6809040000 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   56                   | push                esi
            //   50                   | push                eax
            //   6809040000           | push                0x409

        $sequence_3 = { e8???????? 83c404 c70600000000 33c0 5f 5e }
            // n = 6, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_4 = { ff2485e84e4000 668b4604 83c704 83c304 668901 83c604 e9???????? }
            // n = 7, score = 100
            //   ff2485e84e4000       | jmp                 dword ptr [eax*4 + 0x404ee8]
            //   668b4604             | mov                 ax, word ptr [esi + 4]
            //   83c704               | add                 edi, 4
            //   83c304               | add                 ebx, 4
            //   668901               | mov                 word ptr [ecx], ax
            //   83c604               | add                 esi, 4
            //   e9????????           |                     

        $sequence_5 = { 8bff 55 8bec 8b4508 57 8d3c85e0e04100 8b0f }
            // n = 7, score = 100
            //   8bff                 | mov                 edi, edi
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   57                   | push                edi
            //   8d3c85e0e04100       | lea                 edi, [eax*4 + 0x41e0e0]
            //   8b0f                 | mov                 ecx, dword ptr [edi]

        $sequence_6 = { 6a00 6a01 6800000080 894dc0 8b4d10 50 894dc4 }
            // n = 7, score = 100
            //   6a00                 | push                0
            //   6a01                 | push                1
            //   6800000080           | push                0x80000000
            //   894dc0               | mov                 dword ptr [ebp - 0x40], ecx
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   894dc4               | mov                 dword ptr [ebp - 0x3c], ecx

        $sequence_7 = { c70600000000 740a b80b000280 5e }
            // n = 4, score = 100
            //   c70600000000         | mov                 dword ptr [esi], 0
            //   740a                 | je                  0xc
            //   b80b000280           | mov                 eax, 0x8002000b
            //   5e                   | pop                 esi

        $sequence_8 = { 3bf0 8b4508 0f47f9 85ff 740d 2bf0 8a0c06 }
            // n = 7, score = 100
            //   3bf0                 | cmp                 esi, eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   0f47f9               | cmova               edi, ecx
            //   85ff                 | test                edi, edi
            //   740d                 | je                  0xf
            //   2bf0                 | sub                 esi, eax
            //   8a0c06               | mov                 cl, byte ptr [esi + eax]

        $sequence_9 = { ffb5f0fdffff ff15???????? 50 e8???????? 68???????? 8d85f4fdffff 50 }
            // n = 7, score = 100
            //   ffb5f0fdffff         | push                dword ptr [ebp - 0x210]
            //   ff15????????         |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   68????????           |                     
            //   8d85f4fdffff         | lea                 eax, [ebp - 0x20c]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 294912
}
