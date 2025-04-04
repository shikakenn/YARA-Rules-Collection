rule win_aresloader_auto {

    meta:
        id = "5vQmbFkRDub7Mfa3YGKTfI"
        fingerprint = "v1_sha256_01346a5099a8423ed0407177afbd014d15a423ebfced07e8fa01ead0f1c12c68"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.aresloader."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aresloader"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c744241c00000000 c744241800000000 c744241410000000 c744241000000000 c744240c00000000 c744240800000000 c744240400000000 }
            // n = 7, score = 400
            //   c744241c00000000     | mov                 dword ptr [esp + 0x1c], 0
            //   c744241800000000     | mov                 dword ptr [esp + 0x18], 0
            //   c744241410000000     | mov                 dword ptr [esp + 0x14], 0x10
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   c744240c00000000     | mov                 dword ptr [esp + 0xc], 0
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0

        $sequence_1 = { 8b742430 8b7c2438 8b6c243c 85db 7435 }
            // n = 5, score = 400
            //   8b742430             | mov                 esi, dword ptr [esp + 0x30]
            //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
            //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
            //   85db                 | test                ebx, ebx
            //   7435                 | je                  0x37

        $sequence_2 = { 7831 39d8 7205 c6441eff00 }
            // n = 4, score = 400
            //   7831                 | js                  0x33
            //   39d8                 | cmp                 eax, ebx
            //   7205                 | jb                  7
            //   c6441eff00           | mov                 byte ptr [esi + ebx - 1], 0

        $sequence_3 = { 8b7c2438 8b6c243c 3d???????? 741d 896c243c 897c2438 89742434 }
            // n = 7, score = 400
            //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
            //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
            //   3d????????           |                     
            //   741d                 | je                  0x1f
            //   896c243c             | mov                 dword ptr [esp + 0x3c], ebp
            //   897c2438             | mov                 dword ptr [esp + 0x38], edi
            //   89742434             | mov                 dword ptr [esp + 0x34], esi

        $sequence_4 = { 8b742434 8b7c2438 8b6c243c 3d???????? }
            // n = 4, score = 400
            //   8b742434             | mov                 esi, dword ptr [esp + 0x34]
            //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
            //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
            //   3d????????           |                     

        $sequence_5 = { 741d 896c243c 897c2438 89742434 }
            // n = 4, score = 400
            //   741d                 | je                  0x1f
            //   896c243c             | mov                 dword ptr [esp + 0x3c], ebp
            //   897c2438             | mov                 dword ptr [esp + 0x38], edi
            //   89742434             | mov                 dword ptr [esp + 0x34], esi

        $sequence_6 = { a1???????? 8b5c2430 8b742434 8b7c2438 8b6c243c 3d???????? }
            // n = 6, score = 400
            //   a1????????           |                     
            //   8b5c2430             | mov                 ebx, dword ptr [esp + 0x30]
            //   8b742434             | mov                 esi, dword ptr [esp + 0x34]
            //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
            //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
            //   3d????????           |                     

        $sequence_7 = { 8b742434 8b7c2438 8b6c243c 3d???????? 741d 896c243c }
            // n = 6, score = 400
            //   8b742434             | mov                 esi, dword ptr [esp + 0x34]
            //   8b7c2438             | mov                 edi, dword ptr [esp + 0x38]
            //   8b6c243c             | mov                 ebp, dword ptr [esp + 0x3c]
            //   3d????????           |                     
            //   741d                 | je                  0x1f
            //   896c243c             | mov                 dword ptr [esp + 0x3c], ebp

        $sequence_8 = { 897c2408 895c2404 893424 e8???????? 85c0 7831 }
            // n = 6, score = 400
            //   897c2408             | mov                 dword ptr [esp + 8], edi
            //   895c2404             | mov                 dword ptr [esp + 4], ebx
            //   893424               | mov                 dword ptr [esp], esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7831                 | js                  0x33

        $sequence_9 = { 741d 896c243c 897c2438 89742434 895c2430 }
            // n = 5, score = 400
            //   741d                 | je                  0x1f
            //   896c243c             | mov                 dword ptr [esp + 0x3c], ebp
            //   897c2438             | mov                 dword ptr [esp + 0x38], edi
            //   89742434             | mov                 dword ptr [esp + 0x34], esi
            //   895c2430             | mov                 dword ptr [esp + 0x30], ebx

    condition:
        7 of them and filesize < 2657280
}
