/*
    Yara Rule Set
    Author: Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud
    Date: 2015-12-09
   Reference = http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family
    Identifier: Derusbi Dez 2015
*/

rule derusbi_kernel
{
    meta:
        id = "5Br67RIyMPSdXy0KKeAlYo"
        fingerprint = "v1_sha256_872e3d41de5d804eb9ed1b65a86c045519706229b762e4b190ed43882a79fc93"
        version = "1.0"
        date = "2015-12-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        description = "Derusbi Driver version"
        category = "INFO"

    strings:
        $token1 = "$$$--Hello"
        $token2 = "Wrod--$$$"
        $cfg = "XXXXXXXXXXXXXXX"
        $class = ".?AVPCC_BASEMOD@@"
        $MZ = "MZ"
    condition:
        $MZ at 0 and $token1 and $token2 and $cfg and $class
}

rule derusbi_linux
{
    meta:
        id = "PQxk8fhrV79sr7bRHKPn7"
        fingerprint = "v1_sha256_68d5af17b33d1aa0388516e5d2a1ad29c22dc04451e232dfbdf1ef0714baeb10"
        version = "1.0"
        date = "2015-12-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
        description = "Derusbi Server Linux version"
        category = "INFO"

    strings:
        $PS1 = "PS1=RK# \\u@\\h:\\w \\$"
        $cmd = "unset LS_OPTIONS;uname -a"
        $pname = "[diskio]"
        $rkfile = "/tmp/.secure"
        $ELF = "\x7fELF"
    condition:
        $ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}

/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-12-15
    Identifier: Derusbi Dez 2015
*/

rule Derusbi_Kernel_Driver_WD_UDFS {
    meta:
        id = "71AZrfJrBkFDEq2YNJCFot"
        fingerprint = "v1_sha256_00865c8f3feb41dee4eaaebca59ea7f2d1b46f63bf17a0f458c24b0ff67d0912"
        version = "1.0"
        score = 80
        date = "2015-12-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Derusbi Kernel Driver"
        category = "INFO"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
        hash1 = "1b449121300b0188ff9f6a8c399fb818d0cf53fd36cf012e6908a2665a27f016"
        hash2 = "50174311e524b97ea5cb4f3ea571dd477d1f0eee06cd3ed73af39a15f3e6484a"
        hash3 = "6cdb65dbfb2c236b6d149fd9836cb484d0608ea082cf5bd88edde31ad11a0d58"
        hash4 = "e27fb16dce7fff714f4b05f2cef53e1919a34d7ec0e595f2eaa155861a213e59"

    strings:
      $x1 = "\\\\.\\pipe\\usbpcex%d" fullword wide
      $x2 = "\\\\.\\pipe\\usbpcg%d" fullword wide
      $x3 = "\\??\\pipe\\usbpcex%d" fullword wide
        $x4 = "\\??\\pipe\\usbpcg%d" fullword wide
      $x5 = "$$$--Hello" fullword ascii
      $x6 = "Wrod--$$$" fullword ascii

        $s1 = "\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide
        $s2 = "Update.dll" fullword ascii
        $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI" fullword wide
        $s4 = "\\Driver\\nsiproxy" fullword wide
        $s5 = "HOST: %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and
      (
         2 of ($x*) or all of ($s*)
      )
}

rule Derusbi_Code_Signing_Cert {
    meta:
        id = "3uQqHyWoeft3vuSTJozXL0"
        fingerprint = "v1_sha256_dae976a4896a4f6b6a1b415582db84f3da5aac03bf4079f75e11c790dcf23900"
        version = "1.0"
        score = 40
        date = "2015-12-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an executable signed with a certificate also used for Derusbi Trojan - suspicious"
        category = "INFO"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"

   strings:
      $s1 = "Fuqing Dawu Technology Co.,Ltd.0" fullword ascii
      $s2 = "XL Games Co.,Ltd.0" fullword ascii
      $s3 = "Wemade Entertainment co.,Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule XOR_4byte_Key {
    meta:
        id = "7bHUE7jEi53CTWGY79DYGZ"
        fingerprint = "v1_sha256_61cbdac3fd9a486d85261234698f33aa04d505b32dfec731de6fc61d103bf609"
        version = "1.0"
        score = 60
        date = "2015-12-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
        category = "INFO"
        reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"

   strings:
      /* Op Code */
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 }
      /*
      test    ecx, ecx
      jz      short loc_590170
      xor     [esi], eax
      add     [esi], ebx
      add     esi, 4
      dec     ecx
      jmp     short loc_590162
      */
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and all of them
}
