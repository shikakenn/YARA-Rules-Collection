rule win_lunchmoney_auto {

    meta:
        id = "1aEXmiCEd2R5MLEnQ2idsa"
        fingerprint = "v1_sha256_6507a60182b28ed10fdd4ed1c7e21ccd1e2f0dc103e23e1d246a1843603fe4d9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.lunchmoney."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lunchmoney"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83ec18 8bcf 54 e8???????? 8bce e8???????? 83ec18 }
            // n = 7, score = 100
            //   83ec18               | sub                 esp, 0x18
            //   8bcf                 | mov                 ecx, edi
            //   54                   | push                esp
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   83ec18               | sub                 esp, 0x18

        $sequence_1 = { 8d0c00 894dec eb38 8b45f4 8b048550914200 8d4dec 6a00 }
            // n = 7, score = 100
            //   8d0c00               | lea                 ecx, [eax + eax]
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   eb38                 | jmp                 0x3a
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b048550914200       | mov                 eax, dword ptr [eax*4 + 0x429150]
            //   8d4dec               | lea                 ecx, [ebp - 0x14]
            //   6a00                 | push                0

        $sequence_2 = { 6a01 8d4dbc e8???????? 8bb570ffffff 8dbb04010000 ba???????? 8bcf }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   8d4dbc               | lea                 ecx, [ebp - 0x44]
            //   e8????????           |                     
            //   8bb570ffffff         | mov                 esi, dword ptr [ebp - 0x90]
            //   8dbb04010000         | lea                 edi, [ebx + 0x104]
            //   ba????????           |                     
            //   8bcf                 | mov                 ecx, edi

        $sequence_3 = { 7202 8b09 8d55e4 e8???????? 8d4b24 8945d4 }
            // n = 6, score = 100
            //   7202                 | jb                  4
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   8d55e4               | lea                 edx, [ebp - 0x1c]
            //   e8????????           |                     
            //   8d4b24               | lea                 ecx, [ebx + 0x24]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax

        $sequence_4 = { 6a03 6a09 8d45bc 50 8d4b4c }
            // n = 5, score = 100
            //   6a03                 | push                3
            //   6a09                 | push                9
            //   8d45bc               | lea                 eax, [ebp - 0x44]
            //   50                   | push                eax
            //   8d4b4c               | lea                 ecx, [ebx + 0x4c]

        $sequence_5 = { 8bce 50 e8???????? 50 8d4da4 }
            // n = 5, score = 100
            //   8bce                 | mov                 ecx, esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]

        $sequence_6 = { 8bcf e8???????? 50 6a09 57 8bce }
            // n = 6, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   50                   | push                eax
            //   6a09                 | push                9
            //   57                   | push                edi
            //   8bce                 | mov                 ecx, esi

        $sequence_7 = { eb5a 56 e8???????? 59 8365fc00 8b049d50914200 }
            // n = 6, score = 100
            //   eb5a                 | jmp                 0x5c
            //   56                   | push                esi
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8b049d50914200       | mov                 eax, dword ptr [ebx*4 + 0x429150]

        $sequence_8 = { 33d2 8d4da4 385588 b800008000 0f45d0 837db808 52 }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   8d4da4               | lea                 ecx, [ebp - 0x5c]
            //   385588               | cmp                 byte ptr [ebp - 0x78], dl
            //   b800008000           | mov                 eax, 0x800000
            //   0f45d0               | cmovne              edx, eax
            //   837db808             | cmp                 dword ptr [ebp - 0x48], 8
            //   52                   | push                edx

        $sequence_9 = { 8d86f8000000 83c124 3bc8 740a 6aff 6a00 50 }
            // n = 7, score = 100
            //   8d86f8000000         | lea                 eax, [esi + 0xf8]
            //   83c124               | add                 ecx, 0x24
            //   3bc8                 | cmp                 ecx, eax
            //   740a                 | je                  0xc
            //   6aff                 | push                -1
            //   6a00                 | push                0
            //   50                   | push                eax

    condition:
        7 of them and filesize < 373760
}
