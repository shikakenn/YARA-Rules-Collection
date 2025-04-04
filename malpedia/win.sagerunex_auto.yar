rule win_sagerunex_auto {

    meta:
        id = "BzUeGkbENkyOMr4p6cIsY"
        fingerprint = "v1_sha256_dff18f54b10b1df23611f9090ec75c66093dde952c82cc96492b8dbdbdc0e627"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sagerunex."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sagerunex"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { e8???????? 488d83dcd70000 41b932000000 4c8bc6 33d2 33c9 c744242832000000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d83dcd70000       | pop                 edi
            //   41b932000000         | xor                 eax, eax
            //   4c8bc6               | dec                 eax
            //   33d2                 | mov                 ecx, dword ptr [ebp + 0x3770]
            //   33c9                 | dec                 eax
            //   c744242832000000     | xor                 ecx, esp

        $sequence_1 = { c1c802 33c8 8bc3 23c7 0bf0 8d040a 8b0c24 }
            // n = 7, score = 100
            //   c1c802               | inc                 ecx
            //   33c8                 | mov                 ecx, esi
            //   8bc3                 | rep stosd           dword ptr es:[edi], eax
            //   23c7                 | dec                 esp
            //   0bf0                 | lea                 eax, [0x32c16]
            //   8d040a               | dec                 eax
            //   8b0c24               | lea                 ecx, [esp + 0x70]

        $sequence_2 = { 49c1ea08 443378f4 48c1e910 440fb6c1 418bcb 478ba48650510400 48c1e908 }
            // n = 7, score = 100
            //   49c1ea08             | and                 esp, 0x3f
            //   443378f4             | mov                 dword ptr [esp + 0x20], eax
            //   48c1e910             | mov                 eax, dword ptr [esp + 0x20]
            //   440fb6c1             | test                eax, eax
            //   418bcb               | je                  0x99c
            //   478ba48650510400     | add                 ebx, eax
            //   48c1e908             | cmp                 ebx, edi

        $sequence_3 = { 448d6304 66894670 4d8bef 498bcd e8???????? 4883f832 }
            // n = 6, score = 100
            //   448d6304             | lea                 ecx, [esi - 8]
            //   66894670             | dec                 ebp
            //   4d8bef               | mov                 ecx, ebp
            //   498bcd               | ja                  0xdbb
            //   e8????????           |                     
            //   4883f832             | dec                 eax

        $sequence_4 = { 448bc6 ba12000000 e8???????? 33f6 eb52 488d542430 e8???????? }
            // n = 7, score = 100
            //   448bc6               | dec                 eax
            //   ba12000000           | lea                 ecx, [ebp + 0x90]
            //   e8????????           |                     
            //   33f6                 | mov                 byte ptr [ecx], al
            //   eb52                 | inc                 eax
            //   488d542430           | dec                 eax
            //   e8????????           |                     

        $sequence_5 = { 8bc5 81c19979825a 4123c2 034c240c 03d9 }
            // n = 5, score = 100
            //   8bc5                 | mov                 dword ptr [ebp], ecx
            //   81c19979825a         | dec                 eax
            //   4123c2               | mov                 dword ptr [ebp + 0x18], ecx
            //   034c240c             | dec                 eax
            //   03d9                 | mov                 dword ptr [ebp + 0x78], ecx

        $sequence_6 = { 498b4e10 e8???????? 49896e08 4d896610 33d2 498bce e8???????? }
            // n = 7, score = 100
            //   498b4e10             | mov                 eax, edx
            //   e8????????           |                     
            //   49896e08             | dec                 eax
            //   4d896610             | shr                 eax, 0x38
            //   33d2                 | mov                 byte ptr [esp + 0x25], al
            //   498bce               | mov                 eax, edx
            //   e8????????           |                     

        $sequence_7 = { 0fb6480f 440fb60c19 0fb6480e 0fb61419 0fb6480d 41c1e108 4433ca }
            // n = 7, score = 100
            //   0fb6480f             | inc                 ecx
            //   440fb60c19           | push                edi
            //   0fb6480e             | dec                 eax
            //   0fb61419             | lea                 ebp, [eax - 0x558]
            //   0fb6480d             | dec                 eax
            //   41c1e108             | mov                 dword ptr [eax + 0x18], esi
            //   4433ca               | dec                 eax

        $sequence_8 = { 4c8d4728 4c8d4f10 488bd6 488bce 4889442420 e8???????? 85c0 }
            // n = 7, score = 100
            //   4c8d4728             | jne                 0x1ecb
            //   4c8d4f10             | dec                 eax
            //   488bd6               | sub                 ecx, 8
            //   488bce               | dec                 eax
            //   4889442420           | dec                 edx
            //   e8????????           |                     
            //   85c0                 | jne                 0x1ebc

        $sequence_9 = { 488d542470 4c8bc0 458bcf ff15???????? 85c0 0f84a3000000 0fb7c6 }
            // n = 7, score = 100
            //   488d542470           | mov                 edi, ebx
            //   4c8bc0               | dec                 eax
            //   458bcf               | sar                 edi, 5
            //   ff15????????         |                     
            //   85c0                 | dec                 esp
            //   0f84a3000000         | lea                 esp, [0x1c5f8]
            //   0fb7c6               | and                 eax, 0x1f

    condition:
        7 of them and filesize < 619520
}
