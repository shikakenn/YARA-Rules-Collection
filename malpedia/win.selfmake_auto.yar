rule win_selfmake_auto {

    meta:
        id = "6vxyll8GIJ6t3kZnvFvGCA"
        fingerprint = "v1_sha256_93ed4fceea8c314a1c4a918011ab44630046aab19d1594880ab759bf63042ba9"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.selfmake."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.selfmake"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b17 8b4208 8bcf ffd0 33c9 8844241b c74424540f000000 }
            // n = 7, score = 400
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8b4208               | mov                 eax, dword ptr [edx + 8]
            //   8bcf                 | mov                 ecx, edi
            //   ffd0                 | call                eax
            //   33c9                 | xor                 ecx, ecx
            //   8844241b             | mov                 byte ptr [esp + 0x1b], al
            //   c74424540f000000     | mov                 dword ptr [esp + 0x54], 0xf

        $sequence_1 = { 99 83e203 03c2 46 c1f802 83c104 3bf0 }
            // n = 7, score = 400
            //   99                   | cdq                 
            //   83e203               | and                 edx, 3
            //   03c2                 | add                 eax, edx
            //   46                   | inc                 esi
            //   c1f802               | sar                 eax, 2
            //   83c104               | add                 ecx, 4
            //   3bf0                 | cmp                 esi, eax

        $sequence_2 = { 89442439 8944243d 89442441 89442445 6689442449 }
            // n = 5, score = 400
            //   89442439             | mov                 dword ptr [esp + 0x39], eax
            //   8944243d             | mov                 dword ptr [esp + 0x3d], eax
            //   89442441             | mov                 dword ptr [esp + 0x41], eax
            //   89442445             | mov                 dword ptr [esp + 0x45], eax
            //   6689442449           | mov                 word ptr [esp + 0x49], ax

        $sequence_3 = { 8b542414 8a02 8b5c246c 8bf3 3c7f }
            // n = 5, score = 400
            //   8b542414             | mov                 edx, dword ptr [esp + 0x14]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8b5c246c             | mov                 ebx, dword ptr [esp + 0x6c]
            //   8bf3                 | mov                 esi, ebx
            //   3c7f                 | cmp                 al, 0x7f

        $sequence_4 = { 8d342f 83f804 7214 8b16 3b11 }
            // n = 5, score = 400
            //   8d342f               | lea                 esi, [edi + ebp]
            //   83f804               | cmp                 eax, 4
            //   7214                 | jb                  0x16
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   3b11                 | cmp                 edx, dword ptr [ecx]

        $sequence_5 = { 68???????? e8???????? 83c040 50 e8???????? 83c408 e8???????? }
            // n = 7, score = 400
            //   68????????           |                     
            //   e8????????           |                     
            //   83c040               | add                 eax, 0x40
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   e8????????           |                     

        $sequence_6 = { 8b5608 8b4254 8b4e14 8b561c 50 51 52 }
            // n = 7, score = 400
            //   8b5608               | mov                 edx, dword ptr [esi + 8]
            //   8b4254               | mov                 eax, dword ptr [edx + 0x54]
            //   8b4e14               | mov                 ecx, dword ptr [esi + 0x14]
            //   8b561c               | mov                 edx, dword ptr [esi + 0x1c]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_7 = { 8b442450 7304 8d442450 8b550c }
            // n = 4, score = 400
            //   8b442450             | mov                 eax, dword ptr [esp + 0x50]
            //   7304                 | jae                 6
            //   8d442450             | lea                 eax, [esp + 0x50]
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_8 = { 8a4c1001 884dec 8b55ec 81e2ff000000 83e207 83fa05 }
            // n = 6, score = 400
            //   8a4c1001             | mov                 cl, byte ptr [eax + edx + 1]
            //   884dec               | mov                 byte ptr [ebp - 0x14], cl
            //   8b55ec               | mov                 edx, dword ptr [ebp - 0x14]
            //   81e2ff000000         | and                 edx, 0xff
            //   83e207               | and                 edx, 7
            //   83fa05               | cmp                 edx, 5

        $sequence_9 = { 51 50 e8???????? 8bf8 8a4500 }
            // n = 5, score = 400
            //   51                   | push                ecx
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8a4500               | mov                 al, byte ptr [ebp]

    condition:
        7 of them and filesize < 932864
}
