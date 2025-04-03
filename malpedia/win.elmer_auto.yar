rule win_elmer_auto {

    meta:
        id = "5qv1J1pHzrWMvbq0VOenbo"
        fingerprint = "v1_sha256_bab93e1a95447749d36a1ef62678268f3e0176c60b4af8b397181e40d0e275fa"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.elmer"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7cdd 8b44240c 03f7 41 83f904 8906 7cc6 }
            // n = 7, score = 100
            //   7cdd                 | jl                  0xffffffdf
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   03f7                 | add                 esi, edi
            //   41                   | inc                 ecx
            //   83f904               | cmp                 ecx, 4
            //   8906                 | mov                 dword ptr [esi], eax
            //   7cc6                 | jl                  0xffffffc8

        $sequence_1 = { 8bec 83ec08 56 8b7508 0fb7460e 0fb74e0c }
            // n = 6, score = 100
            //   8bec                 | mov                 ebp, esp
            //   83ec08               | sub                 esp, 8
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   0fb7460e             | movzx               eax, word ptr [esi + 0xe]
            //   0fb74e0c             | movzx               ecx, word ptr [esi + 0xc]

        $sequence_2 = { 7cdd 8b44240c 03f7 41 83f904 }
            // n = 5, score = 100
            //   7cdd                 | jl                  0xffffffdf
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   03f7                 | add                 esi, edi
            //   41                   | inc                 ecx
            //   83f904               | cmp                 ecx, 4

        $sequence_3 = { 8a441424 50 6a0d e8???????? }
            // n = 4, score = 100
            //   8a441424             | mov                 al, byte ptr [esp + edx + 0x24]
            //   50                   | push                eax
            //   6a0d                 | push                0xd
            //   e8????????           |                     

        $sequence_4 = { 5b 83c408 c3 51 8a44240c }
            // n = 5, score = 100
            //   5b                   | pop                 ebx
            //   83c408               | add                 esp, 8
            //   c3                   | ret                 
            //   51                   | push                ecx
            //   8a44240c             | mov                 al, byte ptr [esp + 0xc]

        $sequence_5 = { 83c104 4e 75e3 5e c3 83ec08 }
            // n = 6, score = 100
            //   83c104               | add                 ecx, 4
            //   4e                   | dec                 esi
            //   75e3                 | jne                 0xffffffe5
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   83ec08               | sub                 esp, 8

        $sequence_6 = { 7948 25ffffff7f 0fb74c060e 0fb754060c 03ca 7435 }
            // n = 6, score = 100
            //   7948                 | jns                 0x4a
            //   25ffffff7f           | and                 eax, 0x7fffffff
            //   0fb74c060e           | movzx               ecx, word ptr [esi + eax + 0xe]
            //   0fb754060c           | movzx               edx, word ptr [esi + eax + 0xc]
            //   03ca                 | add                 ecx, edx
            //   7435                 | je                  0x37

        $sequence_7 = { 32d8 46 881f 83c704 8d4efd 83f904 }
            // n = 6, score = 100
            //   32d8                 | xor                 bl, al
            //   46                   | inc                 esi
            //   881f                 | mov                 byte ptr [edi], bl
            //   83c704               | add                 edi, 4
            //   8d4efd               | lea                 ecx, [esi - 3]
            //   83f904               | cmp                 ecx, 4

        $sequence_8 = { 0fb754060c 03ca 7435 8d5c0614 }
            // n = 4, score = 100
            //   0fb754060c           | movzx               edx, word ptr [esi + eax + 0xc]
            //   03ca                 | add                 ecx, edx
            //   7435                 | je                  0x37
            //   8d5c0614             | lea                 ebx, [esi + eax + 0x14]

        $sequence_9 = { 72db 8b445708 8d7c5708 85c0 75b8 5e 5b }
            // n = 7, score = 100
            //   72db                 | jb                  0xffffffdd
            //   8b445708             | mov                 eax, dword ptr [edi + edx*2 + 8]
            //   8d7c5708             | lea                 edi, [edi + edx*2 + 8]
            //   85c0                 | test                eax, eax
            //   75b8                 | jne                 0xffffffba
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

    condition:
        7 of them and filesize < 156672
}
