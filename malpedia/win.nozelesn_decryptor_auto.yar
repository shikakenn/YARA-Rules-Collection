rule win_nozelesn_decryptor_auto {

    meta:
        id = "YIW98jGt6wzCfC1eOsKI5"
        fingerprint = "v1_sha256_4edccdad4171a3a8dbbdabb59b2b49ff95bfdb30e97dda2b954d7aea22da3283"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nozelesn_decryptor."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nozelesn_decryptor"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 33c0 83c40c 668945a8 c645fc02 8d7da4 837db808 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33c0                 | xor                 eax, eax
            //   83c40c               | add                 esp, 0xc
            //   668945a8             | mov                 word ptr [ebp - 0x58], ax
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   8d7da4               | lea                 edi, [ebp - 0x5c]
            //   837db808             | cmp                 dword ptr [ebp - 0x48], 8

        $sequence_1 = { 8997c4010000 89b7c8010000 8bcf 8987cc010000 8d45f8 50 }
            // n = 6, score = 100
            //   8997c4010000         | mov                 dword ptr [edi + 0x1c4], edx
            //   89b7c8010000         | mov                 dword ptr [edi + 0x1c8], esi
            //   8bcf                 | mov                 ecx, edi
            //   8987cc010000         | mov                 dword ptr [edi + 0x1cc], eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_2 = { 6a50 50 83fa10 c645fc01 8d8558ffffff 8d75c0 0f4375c0 }
            // n = 7, score = 100
            //   6a50                 | push                0x50
            //   50                   | push                eax
            //   83fa10               | cmp                 edx, 0x10
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   8d75c0               | lea                 esi, [ebp - 0x40]
            //   0f4375c0             | cmovae              esi, dword ptr [ebp - 0x40]

        $sequence_3 = { a1???????? 33c4 89442464 56 57 8b7d08 8d442410 }
            // n = 7, score = 100
            //   a1????????           |                     
            //   33c4                 | xor                 eax, esp
            //   89442464             | mov                 dword ptr [esp + 0x64], eax
            //   56                   | push                esi
            //   57                   | push                edi
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8d442410             | lea                 eax, [esp + 0x10]

        $sequence_4 = { 8bd3 0b45e8 23c8 33ce 33f9 8b45e8 0bd0 }
            // n = 7, score = 100
            //   8bd3                 | mov                 edx, ebx
            //   0b45e8               | or                  eax, dword ptr [ebp - 0x18]
            //   23c8                 | and                 ecx, eax
            //   33ce                 | xor                 ecx, esi
            //   33f9                 | xor                 edi, ecx
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   0bd0                 | or                  edx, eax

        $sequence_5 = { 2bc2 53 83f805 7c1b ff75f0 0fb701 50 }
            // n = 7, score = 100
            //   2bc2                 | sub                 eax, edx
            //   53                   | push                ebx
            //   83f805               | cmp                 eax, 5
            //   7c1b                 | jl                  0x1d
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   0fb701               | movzx               eax, word ptr [ecx]
            //   50                   | push                eax

        $sequence_6 = { 8a45ef 0fb6f0 eb58 8d45ef 3945cc 8d45d4 757f }
            // n = 7, score = 100
            //   8a45ef               | mov                 al, byte ptr [ebp - 0x11]
            //   0fb6f0               | movzx               esi, al
            //   eb58                 | jmp                 0x5a
            //   8d45ef               | lea                 eax, [ebp - 0x11]
            //   3945cc               | cmp                 dword ptr [ebp - 0x34], eax
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   757f                 | jne                 0x81

        $sequence_7 = { 8b5df4 8bc1 8b75ec c1e007 33d0 c1cb05 33d6 }
            // n = 7, score = 100
            //   8b5df4               | mov                 ebx, dword ptr [ebp - 0xc]
            //   8bc1                 | mov                 eax, ecx
            //   8b75ec               | mov                 esi, dword ptr [ebp - 0x14]
            //   c1e007               | shl                 eax, 7
            //   33d0                 | xor                 edx, eax
            //   c1cb05               | ror                 ebx, 5
            //   33d6                 | xor                 edx, esi

        $sequence_8 = { 6a0c 8d4704 50 8d4604 50 56 8d4df8 }
            // n = 7, score = 100
            //   6a0c                 | push                0xc
            //   8d4704               | lea                 eax, [edi + 4]
            //   50                   | push                eax
            //   8d4604               | lea                 eax, [esi + 4]
            //   50                   | push                eax
            //   56                   | push                esi
            //   8d4df8               | lea                 ecx, [ebp - 8]

        $sequence_9 = { 8d8d18fdffff e8???????? 8d8d78fdffff e8???????? c745fcffffffff 8b95dcfdffff 83fa08 }
            // n = 7, score = 100
            //   8d8d18fdffff         | lea                 ecx, [ebp - 0x2e8]
            //   e8????????           |                     
            //   8d8d78fdffff         | lea                 ecx, [ebp - 0x288]
            //   e8????????           |                     
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8b95dcfdffff         | mov                 edx, dword ptr [ebp - 0x224]
            //   83fa08               | cmp                 edx, 8

    condition:
        7 of them and filesize < 1122304
}
