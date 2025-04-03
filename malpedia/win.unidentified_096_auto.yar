rule win_unidentified_096_auto {

    meta:
        id = "32GpvmoKyFLPyPm5dpYfZy"
        fingerprint = "v1_sha256_d9d15c86fa946b0e45aa738b5898be2be607aa89def00775e64a1c8735fb15f8"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.unidentified_096."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_096"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { eb17 b028 a2???????? eb0e }
            // n = 4, score = 100
            //   eb17                 | jmp                 0x19
            //   b028                 | mov                 al, 0x28
            //   a2????????           |                     
            //   eb0e                 | jmp                 0x10

        $sequence_1 = { b040 a2???????? eb4d b023 a2???????? eb44 b024 }
            // n = 7, score = 100
            //   b040                 | mov                 al, 0x40
            //   a2????????           |                     
            //   eb4d                 | jmp                 0x4f
            //   b023                 | mov                 al, 0x23
            //   a2????????           |                     
            //   eb44                 | jmp                 0x46
            //   b024                 | mov                 al, 0x24

        $sequence_2 = { 48 83e01e 83c060 eb15 85ff }
            // n = 5, score = 100
            //   48                   | dec                 eax
            //   83e01e               | and                 eax, 0x1e
            //   83c060               | add                 eax, 0x60
            //   eb15                 | jmp                 0x17
            //   85ff                 | test                edi, edi

        $sequence_3 = { eb5f b021 a2???????? eb56 }
            // n = 4, score = 100
            //   eb5f                 | jmp                 0x61
            //   b021                 | mov                 al, 0x21
            //   a2????????           |                     
            //   eb56                 | jmp                 0x58

        $sequence_4 = { 0f9dc0 48 83e032 83c02d }
            // n = 4, score = 100
            //   0f9dc0               | setge               al
            //   48                   | dec                 eax
            //   83e032               | and                 eax, 0x32
            //   83c02d               | add                 eax, 0x2d

        $sequence_5 = { 895108 8b400c 89410c e8???????? 83c410 }
            // n = 5, score = 100
            //   895108               | mov                 dword ptr [ecx + 8], edx
            //   8b400c               | mov                 eax, dword ptr [eax + 0xc]
            //   89410c               | mov                 dword ptr [ecx + 0xc], eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_6 = { 8bf8 8b442420 83c408 3dff000000 741d 8b4c2420 8b54241c }
            // n = 7, score = 100
            //   8bf8                 | mov                 edi, eax
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   83c408               | add                 esp, 8
            //   3dff000000           | cmp                 eax, 0xff
            //   741d                 | je                  0x1f
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]

        $sequence_7 = { 83f926 5b 0f8750010000 33d2 8a9154174000 ff24952c174000 }
            // n = 6, score = 100
            //   83f926               | cmp                 ecx, 0x26
            //   5b                   | pop                 ebx
            //   0f8750010000         | ja                  0x156
            //   33d2                 | xor                 edx, edx
            //   8a9154174000         | mov                 dl, byte ptr [ecx + 0x401754]
            //   ff24952c174000       | jmp                 dword ptr [edx*4 + 0x40172c]

        $sequence_8 = { 5d 83c44c c21000 55 }
            // n = 4, score = 100
            //   5d                   | pop                 ebp
            //   83c44c               | add                 esp, 0x4c
            //   c21000               | ret                 0x10
            //   55                   | push                ebp

        $sequence_9 = { f644240c01 7409 8ac1 2c30 a2???????? 6683f96a 723b }
            // n = 7, score = 100
            //   f644240c01           | test                byte ptr [esp + 0xc], 1
            //   7409                 | je                  0xb
            //   8ac1                 | mov                 al, cl
            //   2c30                 | sub                 al, 0x30
            //   a2????????           |                     
            //   6683f96a             | cmp                 cx, 0x6a
            //   723b                 | jb                  0x3d

    condition:
        7 of them and filesize < 25648
}
