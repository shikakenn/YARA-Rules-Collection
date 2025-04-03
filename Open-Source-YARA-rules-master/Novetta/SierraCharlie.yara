import "pe"

rule SierraCharlie
{
    meta:
        id = "6ztsJ41aA6mSqQ9vztPqH6"
        fingerprint = "v1_sha256_1a67184325ecd225b2350ac90409668cc2e170bfbc2ce7979a341b614371aa09"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"
        Source = "f4750e1d82b08318bdc1eb6d3399dee52750250f7959a5e4f83245449f399698.bin"

    strings:
    /*
        8B 0D 50 A7 56 00  mov     ecx, DnsFree
        81 F6 8C 3F 7C 5E  xor     esi, 5E7C3F8Ch
        6A 01              push    1               ; _DWORD
        50                 push    eax             ; _DWORD
        85 C9              test    ecx, ecx
        74 3A              jz      short loc_40580B
        FF D1              call    ecx ; DnsFree
    */

    $dnsResolve = {
            8B 0D 50 A7 56 00 
            81 F6 8C 3F 7C 5E 
            6A 01 
            50 
            85 C9 
            74 3A 
            FF D1 
        }
        
    $file1 = "wmplog21t.sqm"
    $file2 = "wmplog15r.sqm"
    $file3 = "wmplog09c.sqm"
        

    condition:
        $dnsResolve in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset + pe.sections[pe.section_index(".text")].raw_data_size))
        or 2 of ($file*)
}
