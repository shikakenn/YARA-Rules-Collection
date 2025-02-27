rule win_typehash_auto {

    meta:
        id = "2xqu9KwfwzTStLGgndAYtU"
        fingerprint = "v1_sha256_9451e6a97a0b537ea280e22049617c90fd5aa93257a4b129bfda6427a2eb4eeb"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.typehash."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.typehash"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83e11f 8b0485e03d4100 8d04c8 eb05 b8???????? f6400420 740d }
            // n = 7, score = 100
            //   83e11f               | and                 ecx, 0x1f
            //   8b0485e03d4100       | mov                 eax, dword ptr [eax*4 + 0x413de0]
            //   8d04c8               | lea                 eax, [eax + ecx*8]
            //   eb05                 | jmp                 7
            //   b8????????           |                     
            //   f6400420             | test                byte ptr [eax + 4], 0x20
            //   740d                 | je                  0xf

        $sequence_1 = { c3 8bc8 83e01f c1f905 8b0c8de03d4100 8a44c104 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8de03d4100       | mov                 ecx, dword ptr [ecx*4 + 0x413de0]
            //   8a44c104             | mov                 al, byte ptr [ecx + eax*8 + 4]

        $sequence_2 = { e8???????? 6a01 8d4c2450 c68424cc00000001 e8???????? bf???????? }
            // n = 6, score = 100
            //   e8????????           |                     
            //   6a01                 | push                1
            //   8d4c2450             | lea                 ecx, [esp + 0x50]
            //   c68424cc00000001     | mov                 byte ptr [esp + 0xcc], 1
            //   e8????????           |                     
            //   bf????????           |                     

        $sequence_3 = { 8944240c c744241004000000 7460 8b2d???????? 8b3d???????? }
            // n = 5, score = 100
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   c744241004000000     | mov                 dword ptr [esp + 0x10], 4
            //   7460                 | je                  0x62
            //   8b2d????????         |                     
            //   8b3d????????         |                     

        $sequence_4 = { c1f805 c1e603 8d1c85e03d4100 8b0485e03d4100 03c6 8a5004 }
            // n = 6, score = 100
            //   c1f805               | sar                 eax, 5
            //   c1e603               | shl                 esi, 3
            //   8d1c85e03d4100       | lea                 ebx, [eax*4 + 0x413de0]
            //   8b0485e03d4100       | mov                 eax, dword ptr [eax*4 + 0x413de0]
            //   03c6                 | add                 eax, esi
            //   8a5004               | mov                 dl, byte ptr [eax + 4]

        $sequence_5 = { 50 51 6813000020 56 c744242000000000 c744242404000000 ffd7 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   51                   | push                ecx
            //   6813000020           | push                0x20000013
            //   56                   | push                esi
            //   c744242000000000     | mov                 dword ptr [esp + 0x20], 0
            //   c744242404000000     | mov                 dword ptr [esp + 0x24], 4
            //   ffd7                 | call                edi

        $sequence_6 = { 03c8 3bc1 7d1e 8d1440 2bc8 8d1495e8294100 832200 }
            // n = 7, score = 100
            //   03c8                 | add                 ecx, eax
            //   3bc1                 | cmp                 eax, ecx
            //   7d1e                 | jge                 0x20
            //   8d1440               | lea                 edx, [eax + eax*2]
            //   2bc8                 | sub                 ecx, eax
            //   8d1495e8294100       | lea                 edx, [edx*4 + 0x4129e8]
            //   832200               | and                 dword ptr [edx], 0

        $sequence_7 = { 3bf3 7505 be???????? 8b54242c 8b442430 8bcf 55 }
            // n = 7, score = 100
            //   3bf3                 | cmp                 esi, ebx
            //   7505                 | jne                 7
            //   be????????           |                     
            //   8b54242c             | mov                 edx, dword ptr [esp + 0x2c]
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   8bcf                 | mov                 ecx, edi
            //   55                   | push                ebp

        $sequence_8 = { 837d1805 7538 837d1000 7508 8bb6b42b4100 }
            // n = 5, score = 100
            //   837d1805             | cmp                 dword ptr [ebp + 0x18], 5
            //   7538                 | jne                 0x3a
            //   837d1000             | cmp                 dword ptr [ebp + 0x10], 0
            //   7508                 | jne                 0xa
            //   8bb6b42b4100         | mov                 esi, dword ptr [esi + 0x412bb4]

        $sequence_9 = { e8???????? 68???????? 8d45c8 c745c8e4e74000 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   68????????           |                     
            //   8d45c8               | lea                 eax, [ebp - 0x38]
            //   c745c8e4e74000       | mov                 dword ptr [ebp - 0x38], 0x40e7e4
            //   50                   | push                eax

    condition:
        7 of them and filesize < 180224
}
