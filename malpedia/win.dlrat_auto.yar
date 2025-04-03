rule win_dlrat_auto {

    meta:
        id = "1tO9iNlNXTl0hgS97JLpM4"
        fingerprint = "v1_sha256_fad702107ce086ed634b62a81fd30395fc9fa896e743ae2abff0224916d86383"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.dlrat."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dlrat"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 488d0d15201100 e8???????? 4889c6 488d0526e60f00 488945b8 48c745b008000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d0d15201100       | dec                 esp
            //   e8????????           |                     
            //   4889c6               | mov                 ecx, edi
            //   488d0526e60f00       | inc                 ebp
            //   488945b8             | xor                 eax, eax
            //   48c745b008000000     | mov                 edx, 0xd82

        $sequence_1 = { eb40 be08000000 488d15ac540200 448bc6 488bcf e8???????? 85c0 }
            // n = 7, score = 100
            //   eb40                 | dec                 eax
            //   be08000000           | lea                 eax, [ebx - 1]
            //   488d15ac540200       | dec                 eax
            //   448bc6               | mov                 dword ptr [ebp - 0x50], eax
            //   488bcf               | dec                 esp
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, esi

        $sequence_2 = { 4a8b14d1 41b8e00b0000 4e8b0c02 4c894df0 4d8b9188000000 498b4a18 488b5108 }
            // n = 7, score = 100
            //   4a8b14d1             | dec                 eax
            //   41b8e00b0000         | mov                 ecx, edx
            //   4e8b0c02             | and                 edx, 0x3f
            //   4c894df0             | dec                 eax
            //   4d8b9188000000       | sar                 ecx, 6
            //   498b4a18             | dec                 eax
            //   488b5108             | arpl                word ptr [ebp - 0x268], ax

        $sequence_3 = { 4c8d4e08 41b801000000 488d15a7c21500 488955b8 4c8945c0 4c894dc8 48833d????????00 }
            // n = 7, score = 100
            //   4c8d4e08             | mov                 dword ptr [ebp - 0x80], ebx
            //   41b801000000         | xor                 esi, esi
            //   488d15a7c21500       | dec                 eax
            //   488955b8             | lea                 ecx, [0x1d85cb]
            //   4c8945c0             | dec                 eax
            //   4c894dc8             | sub                 esp, 0x20
            //   48833d????????00     |                     

        $sequence_4 = { 48898528ffffff 4883bd20ffffff00 755e 8b05???????? 65488b0c2558000000 488b04c1 b9480b0000 }
            // n = 7, score = 100
            //   48898528ffffff       | dec                 eax
            //   4883bd20ffffff00     | movsd               dword ptr es:[edi], dword ptr [esi]
            //   755e                 | dec                 eax
            //   8b05????????         |                     
            //   65488b0c2558000000     | movsd    dword ptr es:[edi], dword ptr [esi]
            //   488b04c1             | dec                 eax
            //   b9480b0000           | lea                 esi, [ebp - 0xd0]

        $sequence_5 = { 4c8bcf 4531c0 ba230b0000 488d0d04260e00 e8???????? 488995e0fdffff 4c8bce }
            // n = 7, score = 100
            //   4c8bcf               | mov                 edx, dword ptr [edi + 8]
            //   4531c0               | dec                 eax
            //   ba230b0000           | mov                 eax, dword ptr [edi]
            //   488d0d04260e00       | dec                 eax
            //   e8????????           |                     
            //   488995e0fdffff       | mov                 dword ptr [ebp - 0x1d0], eax
            //   4c8bce               | dec                 eax

        $sequence_6 = { 4c8d0dec530e00 4c898d68ffffff 41ba0f000000 4c899560ffffff 4c8d8d60ffffff 488d0d8ae60e00 48898d78ffffff }
            // n = 7, score = 100
            //   4c8d0dec530e00       | dec                 esp
            //   4c898d68ffffff       | mov                 edx, dword ptr [eax]
            //   41ba0f000000         | dec                 ecx
            //   4c899560ffffff       | not                 edx
            //   4c8d8d60ffffff       | inc                 ebp
            //   488d0d8ae60e00       | movzx               eax, cl
            //   48898d78ffffff       | inc                 ebp

        $sequence_7 = { 488bcb e8???????? 4889c1 e8???????? 408a7d28 4c8d4e08 41b801000000 }
            // n = 7, score = 100
            //   488bcb               | jae                 0x1e7a
            //   e8????????           |                     
            //   4889c1               | dec                 eax
            //   e8????????           |                     
            //   408a7d28             | lea                 eax, [0xce391]
            //   4c8d4e08             | dec                 eax
            //   41b801000000         | mov                 dword ptr [ebp - 0x128], eax

        $sequence_8 = { eb02 31c9 4c8b5510 493b8aa0000000 0f8280000000 488d0d40b71400 4883ec20 }
            // n = 7, score = 100
            //   eb02                 | dec                 eax
            //   31c9                 | mov                 dword ptr [ebp - 0x50], 0x14
            //   4c8b5510             | dec                 eax
            //   493b8aa0000000       | mov                 dword ptr [ebp - 0x60], eax
            //   0f8280000000         | dec                 eax
            //   488d0d40b71400       | lea                 edx, [0xfffaf7a8]
            //   4883ec20             | dec                 eax

        $sequence_9 = { 488955b8 48c745b008000000 4c8d45b0 488d1d6f741000 48895dc8 48c745c011000000 488d55c0 }
            // n = 7, score = 100
            //   488955b8             | dec                 eax
            //   48c745b008000000     | lea                 eax, [ebp - 0x20]
            //   4c8d45b0             | dec                 eax
            //   488d1d6f741000       | mov                 dword ptr [ebp - 0x120], eax
            //   48895dc8             | dec                 eax
            //   48c745c011000000     | lea                 ebx, [0xe2c91]
            //   488d55c0             | dec                 eax

    condition:
        7 of them and filesize < 4121600
}
