rule win_mediapi_auto {

    meta:
        id = "6k7qvZvBTVcRmmUKaZJSXe"
        fingerprint = "v1_sha256_05b9f202f6ca93b9b901cbe156248c6d5653f1e57951835cd81ee0a4bf1d3fbf"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mediapi."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mediapi"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 488945e0 48837de000 7439 c745f800000000 }
            // n = 4, score = 100
            //   488945e0             | mov                 dword ptr [ebp - 8], 0
            //   48837de000           | jmp                 0x92
            //   7439                 | dec                 eax
            //   c745f800000000       | sub                 edx, eax

        $sequence_1 = { 0fb645d9 8d148500000000 0fb645da 0fb6c0 }
            // n = 4, score = 100
            //   0fb645d9             | mov                 eax, dword ptr [ebp - 0xc]
            //   8d148500000000       | dec                 eax
            //   0fb645da             | cwde                
            //   0fb6c0               | movzx               eax, byte ptr [ebp + eax - 0x23]

        $sequence_2 = { 0fb645f8 89c1 e8???????? 0fb645f8 89c1 }
            // n = 5, score = 100
            //   0fb645f8             | lea                 ecx, [edx + 1]
            //   89c1                 | mov                 dword ptr [ebp - 4], ecx
            //   e8????????           |                     
            //   0fb645f8             | movzx               eax, byte ptr [eax]
            //   89c1                 | dec                 eax

        $sequence_3 = { 4801d0 8b55fc c1e202 83c201 89d1 488b5510 4801ca }
            // n = 7, score = 100
            //   4801d0               | movzx               eax, byte ptr [ebp - 1]
            //   8b55fc               | mov                 byte ptr [edx + 1], al
            //   c1e202               | dec                 eax
            //   83c201               | mov                 eax, dword ptr [ebp + 0x10]
            //   89d1                 | movzx               eax, byte ptr [eax + 2]
            //   488b5510             | mov                 byte ptr [edx + 6], al
            //   4801ca               | dec                 eax

        $sequence_4 = { 3c2f 0f8558010000 8b45f8 8d5001 8955f8 }
            // n = 5, score = 100
            //   3c2f                 | dec                 eax
            //   0f8558010000         | mov                 eax, dword ptr [ebp + 0xdd70]
            //   8b45f8               | movzx               eax, byte ptr [eax]
            //   8d5001               | dec                 eax
            //   8955f8               | mov                 eax, dword ptr [ebp + 0xf78]

        $sequence_5 = { 89c1 e8???????? 0fb6c0 89c1 e8???????? 31c3 }
            // n = 6, score = 100
            //   89c1                 | dec                 eax
            //   e8????????           |                     
            //   0fb6c0               | mov                 dword ptr [ecx], eax
            //   89c1                 | dec                 eax
            //   e8????????           |                     
            //   31c3                 | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_6 = { 0fb645db 0fb6c0 c1f802 83e00f 01d0 }
            // n = 5, score = 100
            //   0fb645db             | dec                 eax
            //   0fb6c0               | mov                 eax, dword ptr [ebp + 0xdd70]
            //   c1f802               | dec                 ecx
            //   83e00f               | mov                 eax, edx
            //   01d0                 | mov                 eax, dword ptr [ebp + 0xdd84]

        $sequence_7 = { 3b45f8 7dac eb2e 488b45e8 488d5001 }
            // n = 5, score = 100
            //   3b45f8               | dec                 eax
            //   7dac                 | mov                 ecx, eax
            //   eb2e                 | dec                 eax
            //   488b45e8             | mov                 eax, dword ptr [ebp + 0xf48]
            //   488d5001             | dec                 eax

        $sequence_8 = { 488b7308 488b4310 4839f0 7420 488d4608 b908000000 48894308 }
            // n = 7, score = 100
            //   488b7308             | mov                 byte ptr [edx + 0xf], al
            //   488b4310             | nop                 
            //   4839f0               | movzx               eax, byte ptr [ebp + eax - 0x27]
            //   7420                 | movzx               edx, al
            //   488d4608             | mov                 eax, dword ptr [ebp - 0xc]
            //   b908000000           | dec                 eax
            //   48894308             | cwde                

        $sequence_9 = { 0fb6c0 89c1 e8???????? 0fb645fb 89c1 e8???????? 0fb6c0 }
            // n = 7, score = 100
            //   0fb6c0               | push                ebp
            //   89c1                 | dec                 eax
            //   e8????????           |                     
            //   0fb645fb             | mov                 ebp, esp
            //   89c1                 | mov                 eax, ecx
            //   e8????????           |                     
            //   0fb6c0               | mov                 byte ptr [ebp + 0x10], al

    condition:
        7 of them and filesize < 246784
}
