rule win_payloadbin_auto {

    meta:
        id = "4LXQ4pV97XNWk8np3qmaZP"
        fingerprint = "v1_sha256_800c1bff3826d8d61dac146dc7e96bbf271b1fb2a9cc74c55e98e32d0540be8c"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.payloadbin."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.payloadbin"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 4158 9d 4158 e8???????? 680269e26f 6811373c52 66450fb3db }
            // n = 7, score = 100
            //   4158                 | arpl                cx, cx
            //   9d                   | dec                 ebp
            //   4158                 | mov                 eax, edi
            //   e8????????           |                     
            //   680269e26f           | dec                 eax
            //   6811373c52           | cdq                 
            //   66450fb3db           | mov                 edx, ebx

        $sequence_1 = { 83f803 e9???????? 0f8526010000 488bcb e9???????? ff15???????? }
            // n = 6, score = 100
            //   83f803               | cmc                 
            //   e9????????           |                     
            //   0f8526010000         | inc                 cx
            //   488bcb               | add                 edi, edx
            //   e9????????           |                     
            //   ff15????????         |                     

        $sequence_2 = { 68eb3a8171 55 68396f8656 6819276b5f 682109a155 4c8b6c2438 48c7442438404fa1db }
            // n = 7, score = 100
            //   68eb3a8171           | push                ecx
            //   55                   | dec                 esp
            //   68396f8656           | movzx               ecx, bx
            //   6819276b5f           | inc                 ebp
            //   682109a155           | xchg                ecx, ecx
            //   4c8b6c2438           | push                ebp
            //   48c7442438404fa1db     | inc    bp

        $sequence_3 = { 52 0f94842418000000 488b942418000000 480fbfd2 80bc1418f0ffffe7 }
            // n = 5, score = 100
            //   52                   | inc                 ax
            //   0f94842418000000     | movzx               ebx, ch
            //   488b942418000000     | sub                 edx, edx
            //   480fbfd2             | not                 ebx
            //   80bc1418f0ffffe7     | dec                 esp

        $sequence_4 = { 4c8d8424a0000000 488bd5 b95d493af4 e8???????? 413bc7 0f85e1000000 8b942498000000 }
            // n = 7, score = 100
            //   4c8d8424a0000000     | dec                 ecx
            //   488bd5               | test                dh, bh
            //   b95d493af4           | dec                 eax
            //   e8????????           |                     
            //   413bc7               | sub                 eax, 1
            //   0f85e1000000         | js                  0xa10
            //   8b942498000000       | cmp                 dword ptr [edi + eax*4], 0

        $sequence_5 = { 488d8c2450020000 2bd2 4d0fb7c7 6641b8b54c 450fbfc7 }
            // n = 5, score = 100
            //   488d8c2450020000     | stc                 
            //   2bd2                 | inc                 ebp
            //   4d0fb7c7             | test                ah, ch
            //   6641b8b54c           | cmc                 
            //   450fbfc7             | dec                 eax

        $sequence_6 = { 448b542500 f5 4433d7 4084cc 4181c20c7cff4d 41c1c202 f8 }
            // n = 7, score = 100
            //   448b542500           | dec                 ecx
            //   f5                   | cmp                 ecx, ebp
            //   4433d7               | je                  0x233
            //   4084cc               | dec                 esp
            //   4181c20c7cff4d       | lea                 esp, [esp + 0x40]
            //   41c1c202             | dec                 eax
            //   f8                   | mov                 esi, ebx

        $sequence_7 = { 8d56d4 fa 158935079e 9e 4657 250543b1d9 f661fd }
            // n = 7, score = 100
            //   8d56d4               | mov                 dword ptr [esp + 8], ebx
            //   fa                   | inc                 cx
            //   158935079e           | rol                 ebx, 0x53
            //   9e                   | dec                 eax
            //   4657                 | mov                 ebx, edx
            //   250543b1d9           | jge                 0x40b
            //   f661fd               | cmc                 

        $sequence_8 = { 9c 49bc5c58ad71e53eea3c 4180ec5e f8 4881842408000000e258ecff 685b136c32 }
            // n = 6, score = 100
            //   9c                   | bswap               cx
            //   49bc5c58ad71e53eea3c     | dec    eax
            //   4180ec5e             | mov                 ecx, edi
            //   f8                   | inc                 sp
            //   4881842408000000e258ecff     | mov    dword ptr [edi + ebp*2], edi
            //   685b136c32           | mov                 ebx, 8

        $sequence_9 = { 4180fd52 4983c004 3bc8 e9???????? 0f860a000000 b801000000 e9???????? }
            // n = 7, score = 100
            //   4180fd52             | inc                 ecx
            //   4983c004             | inc                 ebx
            //   3bc8                 | dec                 ebx
            //   e9????????           |                     
            //   0f860a000000         | dec                 eax
            //   b801000000           | sub                 eax, 1
            //   e9????????           |                     

    condition:
        7 of them and filesize < 3761152
}
