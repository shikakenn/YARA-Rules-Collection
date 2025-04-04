rule win_interception_auto {

    meta:
        id = "69zmE6cuiuumpYbqiqwM5q"
        fingerprint = "v1_sha256_3520af3329a4b24d818d777e1e8f70b92d9cafa69a1f58bf6db64da9ed00530f"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.interception."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.interception"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 83e61f 8d1c8520ae0010 c1e603 8b03 f644300401 7469 57 }
            // n = 7, score = 100
            //   83e61f               | and                 esi, 0x1f
            //   8d1c8520ae0010       | lea                 ebx, [eax*4 + 0x1000ae20]
            //   c1e603               | shl                 esi, 3
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   f644300401           | test                byte ptr [eax + esi + 4], 1
            //   7469                 | je                  0x6b
            //   57                   | push                edi

        $sequence_1 = { 72f1 56 8bf1 c1e603 3b96e8710010 }
            // n = 5, score = 100
            //   72f1                 | jb                  0xfffffff3
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   c1e603               | shl                 esi, 3
            //   3b96e8710010         | cmp                 edx, dword ptr [esi + 0x100071e8]

        $sequence_2 = { c1f805 83e61f 8d1c8520ae0010 c1e603 8b03 }
            // n = 5, score = 100
            //   c1f805               | sar                 eax, 5
            //   83e61f               | and                 esi, 0x1f
            //   8d1c8520ae0010       | lea                 ebx, [eax*4 + 0x1000ae20]
            //   c1e603               | shl                 esi, 3
            //   8b03                 | mov                 eax, dword ptr [ebx]

        $sequence_3 = { ffb6ec710010 8d8560ffffff 50 e8???????? 6810200100 8d8560ffffff }
            // n = 6, score = 100
            //   ffb6ec710010         | push                dword ptr [esi + 0x100071ec]
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6810200100           | push                0x12010
            //   8d8560ffffff         | lea                 eax, [ebp - 0xa0]

        $sequence_4 = { 8bd0 c1f905 83e21f 8b0c8d20ae0010 f644d10401 }
            // n = 5, score = 100
            //   8bd0                 | mov                 edx, eax
            //   c1f905               | sar                 ecx, 5
            //   83e21f               | and                 edx, 0x1f
            //   8b0c8d20ae0010       | mov                 ecx, dword ptr [ecx*4 + 0x1000ae20]
            //   f644d10401           | test                byte ptr [ecx + edx*8 + 4], 1

        $sequence_5 = { 8d3c8520ae0010 c1e603 8b07 03c6 f6400401 7437 }
            // n = 6, score = 100
            //   8d3c8520ae0010       | lea                 edi, [eax*4 + 0x1000ae20]
            //   c1e603               | shl                 esi, 3
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   03c6                 | add                 eax, esi
            //   f6400401             | test                byte ptr [eax + 4], 1
            //   7437                 | je                  0x39

        $sequence_6 = { f683c19c001004 7406 8816 46 }
            // n = 4, score = 100
            //   f683c19c001004       | test                byte ptr [ebx + 0x10009cc1], 4
            //   7406                 | je                  8
            //   8816                 | mov                 byte ptr [esi], dl
            //   46                   | inc                 esi

        $sequence_7 = { 8d542434 f3ab 66ab aa }
            // n = 4, score = 100
            //   8d542434             | lea                 edx, [esp + 0x34]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al

        $sequence_8 = { 8bc8 83e01f c1f905 8b0c8d20ae0010 8a44c104 }
            // n = 5, score = 100
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d20ae0010       | mov                 ecx, dword ptr [ecx*4 + 0x1000ae20]
            //   8a44c104             | mov                 al, byte ptr [ecx + eax*8 + 4]

        $sequence_9 = { 731c 8bc8 83e01f c1f905 8b0c8d20ae0010 f644c10401 8d04c1 }
            // n = 7, score = 100
            //   731c                 | jae                 0x1e
            //   8bc8                 | mov                 ecx, eax
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d20ae0010       | mov                 ecx, dword ptr [ecx*4 + 0x1000ae20]
            //   f644c10401           | test                byte ptr [ecx + eax*8 + 4], 1
            //   8d04c1               | lea                 eax, [ecx + eax*8]

    condition:
        7 of them and filesize < 98304
}
