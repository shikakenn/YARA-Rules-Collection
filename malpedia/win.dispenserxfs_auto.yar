rule win_dispenserxfs_auto {

    meta:
        id = "2gkWnqrsMUks4NUceq1rEO"
        fingerprint = "v1_sha256_0ae97d732c7fee9f1fd4b6377f2a916fed962748494ab51169af7ce6e36e4229"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dispenserxfs."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dispenserxfs"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8975c0 8975c4 8b35???????? 57 c745b430000000 c745b803000000 }
            // n = 6, score = 200
            //   8975c0               | mov                 dword ptr [ebp - 0x40], esi
            //   8975c4               | mov                 dword ptr [ebp - 0x3c], esi
            //   8b35????????         |                     
            //   57                   | push                edi
            //   c745b430000000       | mov                 dword ptr [ebp - 0x4c], 0x30
            //   c745b803000000       | mov                 dword ptr [ebp - 0x48], 3

        $sequence_1 = { 68???????? e8???????? c7042410270000 ff15???????? 6a00 }
            // n = 5, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   c7042410270000       | mov                 dword ptr [esp], 0x2710
            //   ff15????????         |                     
            //   6a00                 | push                0

        $sequence_2 = { 6a02 ff15???????? 8bf0 83feff 74ef 8d85d4fdffff c785d4fdffff2c020000 }
            // n = 7, score = 200
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   83feff               | cmp                 esi, -1
            //   74ef                 | je                  0xfffffff1
            //   8d85d4fdffff         | lea                 eax, [ebp - 0x22c]
            //   c785d4fdffff2c020000     | mov    dword ptr [ebp - 0x22c], 0x22c

        $sequence_3 = { 7c08 8d50ec e8???????? 57 ff15???????? }
            // n = 5, score = 200
            //   7c08                 | jl                  0xa
            //   8d50ec               | lea                 edx, [eax - 0x14]
            //   e8????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_4 = { 7451 33c9 33c0 8bd9 663b422e 731f 8b4230 }
            // n = 7, score = 200
            //   7451                 | je                  0x53
            //   33c9                 | xor                 ecx, ecx
            //   33c0                 | xor                 eax, eax
            //   8bd9                 | mov                 ebx, ecx
            //   663b422e             | cmp                 ax, word ptr [edx + 0x2e]
            //   731f                 | jae                 0x21
            //   8b4230               | mov                 eax, dword ptr [edx + 0x30]

        $sequence_5 = { 50 ffd6 53 6a03 58 50 8d8555ffffff }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   6a03                 | push                3
            //   58                   | pop                 eax
            //   50                   | push                eax
            //   8d8555ffffff         | lea                 eax, [ebp - 0xab]

        $sequence_6 = { 898de0feffff 89b5e4feffff 89b5e8feffff 89b5ecfeffff 89b5f0feffff 66899df6feffff }
            // n = 6, score = 200
            //   898de0feffff         | mov                 dword ptr [ebp - 0x120], ecx
            //   89b5e4feffff         | mov                 dword ptr [ebp - 0x11c], esi
            //   89b5e8feffff         | mov                 dword ptr [ebp - 0x118], esi
            //   89b5ecfeffff         | mov                 dword ptr [ebp - 0x114], esi
            //   89b5f0feffff         | mov                 dword ptr [ebp - 0x110], esi
            //   66899df6feffff       | mov                 word ptr [ebp - 0x10a], bx

        $sequence_7 = { 8945f0 0f823cffffff 8b4df4 8b45e4 }
            // n = 4, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   0f823cffffff         | jb                  0xffffff42
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b45e4               | mov                 eax, dword ptr [ebp - 0x1c]

        $sequence_8 = { 8bcf e8???????? 8d8548feffff 8bd3 50 8bcf }
            // n = 6, score = 200
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8d8548feffff         | lea                 eax, [ebp - 0x1b8]
            //   8bd3                 | mov                 edx, ebx
            //   50                   | push                eax
            //   8bcf                 | mov                 ecx, edi

        $sequence_9 = { 8d55c4 83c414 8bf2 8a02 42 }
            // n = 5, score = 200
            //   8d55c4               | lea                 edx, [ebp - 0x3c]
            //   83c414               | add                 esp, 0x14
            //   8bf2                 | mov                 esi, edx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx

    condition:
        7 of them and filesize < 114688
}
