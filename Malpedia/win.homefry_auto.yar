rule win_homefry_auto {

    meta:
        id = "1qnTbonmjfdd6z6vNrEmCK"
        fingerprint = "v1_sha256_7ca7431c5f68652158a7da10d411e05a72b05761bc09d487931a01e83f98c509"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.homefry."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.homefry"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 4863d5 4803d0 488b05???????? 488917 48630a }
            // n = 6, score = 100
            //   e8????????           |                     
            //   4863d5               | jne                 0x2e7
            //   4803d0               | movzx               eax, byte ptr [edx]
            //   488b05????????       |                     
            //   488917               | dec                 eax
            //   48630a               | lea                 edx, [edx + 1]

        $sequence_1 = { 740f 8bcf 4803cd 7408 488bd6 }
            // n = 5, score = 100
            //   740f                 | dec                 eax
            //   8bcf                 | add                 ecx, eax
            //   4803cd               | dec                 eax
            //   7408                 | add                 ebx, ecx
            //   488bd6               | mov                 dword ptr [ebx], ebp

        $sequence_2 = { 740f 8bcf 4803cd 7408 }
            // n = 4, score = 100
            //   740f                 | mov                 ebx, dword ptr [esp + 0x68]
            //   8bcf                 | dec                 eax
            //   4803cd               | mov                 ecx, edi
            //   7408                 | dec                 eax

        $sequence_3 = { 0f880a010000 488b0d???????? 488d842480000000 458d4e04 488b09 4c8d442470 }
            // n = 6, score = 100
            //   0f880a010000         | mov                 ebx, dword ptr [esp + 0x30]
            //   488b0d????????       |                     
            //   488d842480000000     | test                al, al
            //   458d4e04             | je                  0xa95
            //   488b09               | mov                 ecx, edi
            //   4c8d442470           | dec                 eax

        $sequence_4 = { c705????????94000000 ff15???????? 33d2 8d4a02 ff15???????? 488bd8 }
            // n = 6, score = 100
            //   c705????????94000000     |     
            //   ff15????????         |                     
            //   33d2                 | nop                 word ptr [eax + eax]
            //   8d4a02               | dec                 eax
            //   ff15????????         |                     
            //   488bd8               | mov                 ecx, dword ptr [ebp + 0x300]

        $sequence_5 = { e8???????? 84c0 0f8418010000 48833d????????00 48899c24a0000000 4889b424a8000000 7471 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   84c0                 | dec                 eax
            //   0f8418010000         | mov                 dword ptr [esp + 0xa8], esi
            //   48833d????????00     |                     
            //   48899c24a0000000     | dec                 eax
            //   4889b424a8000000     | mov                 dword ptr [esp + 0xb0], edi
            //   7471                 | dec                 esp

        $sequence_6 = { ff15???????? 488bcb ff15???????? 4881c420040000 }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   488bcb               | mov                 edi, eax
            //   ff15????????         |                     
            //   4881c420040000       | dec                 eax

        $sequence_7 = { 486305???????? 4c890d???????? 48630c18 4c03c3 40883a }
            // n = 5, score = 100
            //   486305????????       |                     
            //   4c890d????????       |                     
            //   48630c18             | add                 edx, 0x50
            //   4c03c3               | dec                 esp
            //   40883a               | mov                 eax, edi

        $sequence_8 = { e8???????? eb05 e8???????? 84c0 7511 488d0ddd180000 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   eb05                 | jne                 0x113
            //   e8????????           |                     
            //   84c0                 | mov                 ecx, dword ptr [ebx + ebp + 4]
            //   7511                 | cmp                 dword ptr [esi + 4], ecx
            //   488d0ddd180000       | dec                 eax

        $sequence_9 = { 483bdd 72d0 488bcf ff15???????? 33c0 488b5c2430 488b6c2438 }
            // n = 7, score = 100
            //   483bdd               | sub                 esp, 0x20
            //   72d0                 | dec                 eax
            //   488bcf               | mov                 edi, edx
            //   ff15????????         |                     
            //   33c0                 | dec                 eax
            //   488b5c2430           | mov                 esi, ecx
            //   488b6c2438           | movzx               eax, word ptr [ecx + 0x22]

    condition:
        7 of them and filesize < 65536
}
