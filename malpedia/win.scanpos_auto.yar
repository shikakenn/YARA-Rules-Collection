rule win_scanpos_auto {

    meta:
        id = "6QXQrUzVpkgKyziJa71FNf"
        fingerprint = "v1_sha256_a62211e1eb96c58c9bf699a15d117ca283e56d459f8aea50975f3891740e6968"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.scanpos."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scanpos"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 83c404 84db 0f85c1010000 8d75d4 b8???????? }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   84db                 | test                bl, bl
            //   0f85c1010000         | jne                 0x1c7
            //   8d75d4               | lea                 esi, [ebp - 0x2c]
            //   b8????????           |                     

        $sequence_1 = { 754b 8b74183c 3bf7 7443 8b16 }
            // n = 5, score = 200
            //   754b                 | jne                 0x4d
            //   8b74183c             | mov                 esi, dword ptr [eax + ebx + 0x3c]
            //   3bf7                 | cmp                 esi, edi
            //   7443                 | je                  0x45
            //   8b16                 | mov                 edx, dword ptr [esi]

        $sequence_2 = { 40 84c9 75f9 2bc2 8bf8 8d759c }
            // n = 6, score = 200
            //   40                   | inc                 eax
            //   84c9                 | test                cl, cl
            //   75f9                 | jne                 0xfffffffb
            //   2bc2                 | sub                 eax, edx
            //   8bf8                 | mov                 edi, eax
            //   8d759c               | lea                 esi, [ebp - 0x64]

        $sequence_3 = { b8???????? e8???????? 83781000 bf10000000 0f94c3 397de8 720c }
            // n = 7, score = 200
            //   b8????????           |                     
            //   e8????????           |                     
            //   83781000             | cmp                 dword ptr [eax + 0x10], 0
            //   bf10000000           | mov                 edi, 0x10
            //   0f94c3               | sete                bl
            //   397de8               | cmp                 dword ptr [ebp - 0x18], edi
            //   720c                 | jb                  0xe

        $sequence_4 = { 0f85ef000000 b208 8d642400 0fbec2 8a0c38 03c7 80f939 }
            // n = 7, score = 200
            //   0f85ef000000         | jne                 0xf5
            //   b208                 | mov                 dl, 8
            //   8d642400             | lea                 esp, [esp]
            //   0fbec2               | movsx               eax, dl
            //   8a0c38               | mov                 cl, byte ptr [eax + edi]
            //   03c7                 | add                 eax, edi
            //   80f939               | cmp                 cl, 0x39

        $sequence_5 = { 8975f0 c74431b0a4414100 8d4eb4 c745fc00000000 e8???????? }
            // n = 5, score = 200
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   c74431b0a4414100     | mov                 dword ptr [ecx + esi - 0x50], 0x4141a4
            //   8d4eb4               | lea                 ecx, [esi - 0x4c]
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   e8????????           |                     

        $sequence_6 = { 8b74183c 3bf7 7443 8b16 8b4204 f644300c06 7517 }
            // n = 7, score = 200
            //   8b74183c             | mov                 esi, dword ptr [eax + ebx + 0x3c]
            //   3bf7                 | cmp                 esi, edi
            //   7443                 | je                  0x45
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   f644300c06           | test                byte ptr [eax + esi + 0xc], 6
            //   7517                 | jne                 0x19

        $sequence_7 = { 68???????? 8d4df4 51 c745f430124100 }
            // n = 4, score = 200
            //   68????????           |                     
            //   8d4df4               | lea                 ecx, [ebp - 0xc]
            //   51                   | push                ecx
            //   c745f430124100       | mov                 dword ptr [ebp - 0xc], 0x411230

        $sequence_8 = { ff15???????? 8b7508 c7465c682a4100 83660800 33ff }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   c7465c682a4100       | mov                 dword ptr [esi + 0x5c], 0x412a68
            //   83660800             | and                 dword ptr [esi + 8], 0
            //   33ff                 | xor                 edi, edi

        $sequence_9 = { 83c004 57 e8???????? a1???????? 50 }
            // n = 5, score = 200
            //   83c004               | add                 eax, 4
            //   57                   | push                edi
            //   e8????????           |                     
            //   a1????????           |                     
            //   50                   | push                eax

    condition:
        7 of them and filesize < 229376
}
