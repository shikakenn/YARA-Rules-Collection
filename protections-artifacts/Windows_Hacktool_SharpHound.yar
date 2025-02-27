rule Windows_Hacktool_SharpHound_5adf9d6d {
    meta:
        id = "4VI0RS8pTtXIDx7wM26yfX"
        fingerprint = "v1_sha256_2c9f38187866985109a42ffdf8940b5d195aadd3815b2de952b190d4b0b95c3c"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpHound"
        reference_sample = "1f74ed6e61880d19e53cde5b0d67a0507bfda0be661860300dcb0f20ea9a45f4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid0 = "A517A8DE-5834-411D-ABDA-2D0E1766539C" ascii wide nocase
        $guid1 = "90A6822C-4336-433D-923F-F54CE66BA98F" ascii wide nocase
        $print_str0 = "Initializing SharpHound at {time} on {date}" ascii wide
        $print_str1 = "SharpHound completed {Number} loops! Zip file written to {Filename}" ascii wide
        $print_str2 = "[-] Removed DCOM Collection" ascii wide
    condition:
        $guid0 or $guid1 or all of ($print_str*)
}

