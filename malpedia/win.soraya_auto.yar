rule win_soraya_auto {

    meta:
        id = "79UtkTQFAGmDWJ1l8o2HOX"
        fingerprint = "v1_sha256_9c021471b4a00823554f7973fdcdc5043a2447611e50ed019058643f5ab74f68"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.soraya."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soraya"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff15???????? 8d48bf 80f919 77f2 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   8d48bf               | lea                 ecx, [eax - 0x41]
            //   80f919               | cmp                 cl, 0x19
            //   77f2                 | ja                  0xfffffff4

        $sequence_1 = { 4885c0 0f84cb000000 448d432f 488d157bf3ffff 4d8bcd 488bc8 4489642420 }
            // n = 7, score = 100
            //   4885c0               | lea                 ecx, [ebx + 4]
            //   0f84cb000000         | dec                 eax
            //   448d432f             | mov                 ecx, dword ptr [esp + 0x30]
            //   488d157bf3ffff       | dec                 esp
            //   4d8bcd               | lea                 eax, [esp + 0x30]
            //   488bc8               | dec                 ecx
            //   4489642420           | inc                 eax

        $sequence_2 = { ff55d4 8b4dfc 33cb 2bcf 3bc8 }
            // n = 5, score = 100
            //   ff55d4               | call                dword ptr [ebp - 0x2c]
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   33cb                 | xor                 ecx, ebx
            //   2bcf                 | sub                 ecx, edi
            //   3bc8                 | cmp                 ecx, eax

        $sequence_3 = { 83c40c 894510 85ff 743c 81ff88130000 7334 813b504f5354 }
            // n = 7, score = 100
            //   83c40c               | add                 esp, 0xc
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   85ff                 | test                edi, edi
            //   743c                 | je                  0x3e
            //   81ff88130000         | cmp                 edi, 0x1388
            //   7334                 | jae                 0x36
            //   813b504f5354         | cmp                 dword ptr [ebx], 0x54534f50

        $sequence_4 = { 037d0c 3bc7 72cb 8b7d10 33f9 }
            // n = 5, score = 100
            //   037d0c               | add                 edi, dword ptr [ebp + 0xc]
            //   3bc7                 | cmp                 eax, edi
            //   72cb                 | jb                  0xffffffcd
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   33f9                 | xor                 edi, ecx

        $sequence_5 = { 7522 448d4b04 ff15???????? 488b4c2430 4c8d442430 }
            // n = 5, score = 100
            //   7522                 | mov                 edx, esi
            //   448d4b04             | dec                 ecx
            //   ff15????????         |                     
            //   488b4c2430           | mov                 ecx, edi
            //   4c8d442430           | dec                 eax

        $sequence_6 = { 8b4d94 33c6 2bc3 33c1 a900100000 }
            // n = 5, score = 100
            //   8b4d94               | mov                 ecx, dword ptr [ebp - 0x6c]
            //   33c6                 | xor                 eax, esi
            //   2bc3                 | sub                 eax, ebx
            //   33c1                 | xor                 eax, ecx
            //   a900100000           | test                eax, 0x1000

        $sequence_7 = { 488bcb ff15???????? 488d4dd0 ff15???????? 488b0d???????? 488364242000 488d5150 }
            // n = 7, score = 100
            //   488bcb               | lea                 eax, [ebx + 0x2f]
            //   ff15????????         |                     
            //   488d4dd0             | dec                 eax
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   488364242000         | lea                 edx, [0xfffff37b]
            //   488d5150             | dec                 ebp

        $sequence_8 = { f7f9 0fb6c2 d1e8 c21000 55 8bec }
            // n = 6, score = 100
            //   f7f9                 | idiv                ecx
            //   0fb6c2               | movzx               eax, dl
            //   d1e8                 | shr                 eax, 1
            //   c21000               | ret                 0x10
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_9 = { 897dfc 8b07 03c3 50 ff55f0 }
            // n = 5, score = 100
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   03c3                 | add                 eax, ebx
            //   50                   | push                eax
            //   ff55f0               | call                dword ptr [ebp - 0x10]

        $sequence_10 = { c3 b401 c3 e8???????? }
            // n = 4, score = 100
            //   c3                   | ret                 
            //   b401                 | mov                 ah, 1
            //   c3                   | ret                 
            //   e8????????           |                     

        $sequence_11 = { 49ffc0 413bd2 72db 418bd6 3bcb 72c8 4c891d???????? }
            // n = 7, score = 100
            //   49ffc0               | mov                 ecx, ebp
            //   413bd2               | mov                 edx, dword ptr [eax + esi + 0x50]
            //   72db                 | dec                 eax
            //   418bd6               | arpl                word ptr [edx + esi + 0x3c], ax
            //   3bcb                 | jne                 0x24
            //   72c8                 | inc                 esp
            //   4c891d????????       |                     

        $sequence_12 = { 498d4e40 4d2bc6 0fb701 6641398408a0010000 7530 ffc2 }
            // n = 6, score = 100
            //   498d4e40             | inc                 ecx
            //   4d2bc6               | cmp                 edx, edx
            //   0fb701               | jb                  0xffffffdd
            //   6641398408a0010000     | inc    ecx
            //   7530                 | mov                 edx, esi
            //   ffc2                 | cmp                 ecx, ebx

        $sequence_13 = { 0f8577ffffff 33c0 5f 5e 5b c9 }
            // n = 6, score = 100
            //   0f8577ffffff         | jne                 0xffffff7d
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c9                   | leave               

        $sequence_14 = { 8365f800 8365fc00 8d42b1 85c0 746c 53 56 }
            // n = 7, score = 100
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8d42b1               | lea                 eax, [edx - 0x4f]
            //   85c0                 | test                eax, eax
            //   746c                 | je                  0x6e
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_15 = { 8d45d8 50 e8???????? 8b45fc 8b4df4 }
            // n = 5, score = 100
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]

        $sequence_16 = { 0f8573020000 8b5d1c 837d3000 7502 8bdf 8b7d2c a1???????? }
            // n = 7, score = 100
            //   0f8573020000         | jne                 0x279
            //   8b5d1c               | mov                 ebx, dword ptr [ebp + 0x1c]
            //   837d3000             | cmp                 dword ptr [ebp + 0x30], 0
            //   7502                 | jne                 4
            //   8bdf                 | mov                 ebx, edi
            //   8b7d2c               | mov                 edi, dword ptr [ebp + 0x2c]
            //   a1????????           |                     

        $sequence_17 = { 4c03eb 448be6 4803c2 48898424c8020000 39741d18 }
            // n = 5, score = 100
            //   4c03eb               | dec                 esp
            //   448be6               | add                 ebp, ebx
            //   4803c2               | inc                 esp
            //   48898424c8020000     | mov                 esp, esi
            //   39741d18             | dec                 eax

        $sequence_18 = { 8b4dd4 894dd0 8b4dd8 894dd4 }
            // n = 4, score = 100
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   894dd4               | mov                 dword ptr [ebp - 0x2c], ecx

        $sequence_19 = { 85c0 750b ff75fc ff15???????? eb1d 33c0 }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   750b                 | jne                 0xd
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   eb1d                 | jmp                 0x1f
            //   33c0                 | xor                 eax, eax

        $sequence_20 = { 488bd6 498bcf ff15???????? 488bcd e9???????? 8b543050 486344323c }
            // n = 7, score = 100
            //   488bd6               | add                 eax, edx
            //   498bcf               | dec                 eax
            //   ff15????????         |                     
            //   488bcd               | mov                 dword ptr [esp + 0x2c8], eax
            //   e9????????           |                     
            //   8b543050             | cmp                 dword ptr [ebp + ebx + 0x18], esi
            //   486344323c           | dec                 eax

        $sequence_21 = { 40 eb05 c1d30b 33c0 5f 5e }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   eb05                 | jmp                 7
            //   c1d30b               | rcl                 ebx, 0xb
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_22 = { 8d0c8b 66397102 7537 0fb709 bf1f600000 }
            // n = 5, score = 100
            //   8d0c8b               | lea                 ecx, [ebx + ecx*4]
            //   66397102             | cmp                 word ptr [ecx + 2], si
            //   7537                 | jne                 0x39
            //   0fb709               | movzx               ecx, word ptr [ecx]
            //   bf1f600000           | mov                 edi, 0x601f

    condition:
        7 of them and filesize < 188416
}
