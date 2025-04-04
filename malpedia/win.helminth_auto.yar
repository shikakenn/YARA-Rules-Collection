rule win_helminth_auto {

    meta:
        id = "6mUKyjJfn7RcyJUzZDVmGc"
        fingerprint = "v1_sha256_274e3eea90d2e30111a5a8cd56771457195fff91f933a3b2952878df64a83186"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.helminth."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helminth"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { a1???????? 68e8030000 8907 e8???????? }
            // n = 4, score = 300
            //   a1????????           |                     
            //   68e8030000           | push                0x3e8
            //   8907                 | mov                 dword ptr [edi], eax
            //   e8????????           |                     

        $sequence_1 = { 83e61f c1e606 8b0cbd70750110 f6440e0401 743d }
            // n = 5, score = 200
            //   83e61f               | and                 esi, 0x1f
            //   c1e606               | shl                 esi, 6
            //   8b0cbd70750110       | mov                 ecx, dword ptr [edi*4 + 0x10017570]
            //   f6440e0401           | test                byte ptr [esi + ecx + 4], 1
            //   743d                 | je                  0x3f

        $sequence_2 = { 6685c0 75f4 a1???????? 8b15???????? }
            // n = 4, score = 200
            //   6685c0               | test                ax, ax
            //   75f4                 | jne                 0xfffffff6
            //   a1????????           |                     
            //   8b15????????         |                     

        $sequence_3 = { 6689440afe 6685c0 75f0 6a00 6880000000 6a04 6a00 }
            // n = 7, score = 200
            //   6689440afe           | mov                 word ptr [edx + ecx - 2], ax
            //   6685c0               | test                ax, ax
            //   75f0                 | jne                 0xfffffff2
            //   6a00                 | push                0
            //   6880000000           | push                0x80
            //   6a04                 | push                4
            //   6a00                 | push                0

        $sequence_4 = { 33c0 5d c21000 803d????????00 56 8b7508 }
            // n = 6, score = 200
            //   33c0                 | xor                 eax, eax
            //   5d                   | pop                 ebp
            //   c21000               | ret                 0x10
            //   803d????????00       |                     
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]

        $sequence_5 = { 75f0 8bcf e8???????? e9???????? ffb5f4fdffff 8b35???????? }
            // n = 6, score = 200
            //   75f0                 | jne                 0xfffffff2
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   e9????????           |                     
            //   ffb5f4fdffff         | push                dword ptr [ebp - 0x20c]
            //   8b35????????         |                     

        $sequence_6 = { e8???????? 8bd8 83e31f 59 c1e306 031cb570750110 59 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax
            //   83e31f               | and                 ebx, 0x1f
            //   59                   | pop                 ecx
            //   c1e306               | shl                 ebx, 6
            //   031cb570750110       | add                 ebx, dword ptr [esi*4 + 0x10017570]
            //   59                   | pop                 ecx

        $sequence_7 = { 55 8bec 8b4d08 33c0 3b0cc550070110 740a 40 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33c0                 | xor                 eax, eax
            //   3b0cc550070110       | cmp                 ecx, dword ptr [eax*8 + 0x10010750]
            //   740a                 | je                  0xc
            //   40                   | inc                 eax

        $sequence_8 = { be???????? 89bd08fcffff 8bd6 e8???????? }
            // n = 4, score = 100
            //   be????????           |                     
            //   89bd08fcffff         | mov                 dword ptr [ebp - 0x3f8], edi
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     

        $sequence_9 = { 2bf1 33c9 d1fe 2bf7 8d4601 }
            // n = 5, score = 100
            //   2bf1                 | sub                 esi, ecx
            //   33c9                 | xor                 ecx, ecx
            //   d1fe                 | sar                 esi, 1
            //   2bf7                 | sub                 esi, edi
            //   8d4601               | lea                 eax, [esi + 1]

        $sequence_10 = { 83c102 663b45f8 75f4 2b4d08 d1f9 }
            // n = 5, score = 100
            //   83c102               | add                 ecx, 2
            //   663b45f8             | cmp                 ax, word ptr [ebp - 8]
            //   75f4                 | jne                 0xfffffff6
            //   2b4d08               | sub                 ecx, dword ptr [ebp + 8]
            //   d1f9                 | sar                 ecx, 1

        $sequence_11 = { 66890c16 8d5202 6685c9 75f1 8bcf e8???????? }
            // n = 6, score = 100
            //   66890c16             | mov                 word ptr [esi + edx], cx
            //   8d5202               | lea                 edx, [edx + 2]
            //   6685c9               | test                cx, cx
            //   75f1                 | jne                 0xfffffff3
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_12 = { a3???????? c3 33c0 50 6a01 }
            // n = 5, score = 100
            //   a3????????           |                     
            //   c3                   | ret                 
            //   33c0                 | xor                 eax, eax
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_13 = { 8bd6 8907 668b02 83c202 663bc1 75f5 }
            // n = 6, score = 100
            //   8bd6                 | mov                 edx, esi
            //   8907                 | mov                 dword ptr [edi], eax
            //   668b02               | mov                 ax, word ptr [edx]
            //   83c202               | add                 edx, 2
            //   663bc1               | cmp                 ax, cx
            //   75f5                 | jne                 0xfffffff7

        $sequence_14 = { 03c9 51 53 56 8934bd20f04100 }
            // n = 5, score = 100
            //   03c9                 | add                 ecx, ecx
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8934bd20f04100       | mov                 dword ptr [edi*4 + 0x41f020], esi

    condition:
        7 of them and filesize < 479232
}
