rule win_bahamut_auto {

    meta:
        id = "5g9EBLD56ViQbi6GiYoyr7"
        fingerprint = "v1_sha256_2b0e934393eac7935aaebcfb139355267dc0fa29ed5c713ace9f7618f661d4db"
        version = "1"
        date = "2018-11-23"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator 0.1a"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bahamut"
        malpedia_version = "20180607"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 00e9 0300 0000 0008 }
            // n = 4, score = 1000
            //   00e9                 | add                 cl, ch
            //   0300                 | add                 eax, dword ptr [eax]
            //   0000                 | add                 byte ptr [eax], al
            //   0008                 | add                 byte ptr [eax], cl

        $sequence_1 = { 0003 10c6 0d8b0f5901 e900000000 }
            // n = 4, score = 1000
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf

        $sequence_2 = { 10c6 0d8b0f5901 e900000000 0003 }
            // n = 4, score = 1000
            //   10c6                 | adc                 dh, al
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf
            //   0003                 | add                 byte ptr [ebx], al

        $sequence_3 = { 0d8b0f5901 e900000000 0003 10c6 }
            // n = 4, score = 1000
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al

        $sequence_4 = { 10c6 0d8b0f5901 e900000000 0003 10c6 }
            // n = 5, score = 1000
            //   10c6                 | adc                 dh, al
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al

        $sequence_5 = { 0003 10c6 0d8b0f5901 e900000000 0003 }
            // n = 5, score = 1000
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf
            //   0003                 | add                 byte ptr [ebx], al

        $sequence_6 = { 0003 10c6 0d8b0f5901 e900000000 0003 10c6 }
            // n = 6, score = 1000
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al
            //   0d8b0f5901           | or                  eax, 0x1590f8b
            //   e900000000           | jmp                 0xd51fdf
            //   0003                 | add                 byte ptr [ebx], al
            //   10c6                 | adc                 dh, al

    condition:
        7 of them
}
