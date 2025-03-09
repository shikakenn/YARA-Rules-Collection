import "pe"

rule IndiaWhiskey
{
    meta:
        id = "7GW9UioAfqeR378pwls8N"
        fingerprint = "v1_sha256_50b6ab00018e4b021e34bec236e56c11406cbf50211cdf6a1d9225359e19a47d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "0c729deec341267c5a9a2271f20266ac3b0775d70436c7770ddc20605088f3b4"
        Description = "Winsec Installer"

    strings:
    /*
        // Service installation code
        FF 15 68 30 40 00  call    ds:wsprintfA
        83 C4 18           add     esp, 18h
        8D 85 FC FE FF FF  lea     eax, [ebp+var_104]
        56                 push    esi
        56                 push    esi
        56                 push    esi
        56                 push    esi
        56                 push    esi
        50                 push    eax
        6A 01              push    1
        // some variants have these two lines added
        5E                 pop     esi
        56                 push    esi

        6A 02              push    2
        68 20 01 00 00     push    120h
        68 FF 01 0F 00     push    0F01FFh
        FF 75 0C           push    [ebp+arg_4]
        FF 75 08           push    [ebp+arg_0]
        
        // some variants have the next line as a push {reg} or push {stack var}
        53                 push    ebx
        //or
        FF 75 FC           push    [ebp+var_4]

        FF 15 E4 49 40 00  call    CreateServiceA
    */

    $a = {
            FF 15 [4] 
            83 C4 18 
            8D [5] 
            5? 
            5? 
            5? 
            5? 
            5? 
            5? 
            6A 01
            [0-2] 
            6A 02 
            68 20 01 00 00 
            68 FF 01 0F 00 
            FF 75 ?? 
            FF 75 ?? 
            (5? | FF 75 ??)
            FF 15 
        }

    condition:
        $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
}
