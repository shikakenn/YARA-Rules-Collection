/*

   Generic Cloaking

   Florian Roth
   BSK Consulting GmbH

    License: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
    Copyright and related rights waived via https://creativecommons.org/licenses/by-nc-sa/4.0/

*/

rule EXE_cloaked_as_TXT {
    meta:
        id = "5uHn68wJDpsakw2f0Lbuu2"
        fingerprint = "v1_sha256_185c3579d979bc810d47b2d1ea9e182acbc6d618e27355356ca9f2778617d23a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Executable with TXT extension"
        category = "INFO"

    condition:
        uint16(0) == 0x5a4d 					// Executable
        and filename matches /\.txt$/is   // TXT extension (case insensitive)
}

rule EXE_extension_cloaking {
    meta:
        id = "2peGFbWTY7Laqvvbi3OyU4"
        fingerprint = "v1_sha256_dd3d5d3b14124ae97effe9ee771f5655a3aa64cfe1239d1b2c6a339362818c85"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Executable showing different extension (Windows default 'hide known extension')"
        category = "INFO"

    condition:
        filename matches /\.txt\.exe$/is or	// Special file extensions
        filename matches /\.pdf\.exe$/is		// Special file extensions
}

rule Cloaked_RAR_File {
    meta:
        id = "1CAPMih4uImMiRLNmUx4BE"
        fingerprint = "v1_sha256_c34269a647b608fa6f61f44bc34eec1207646cf5a7646fe07bf1aad27a256846"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "RAR file cloaked by a different extension"
        category = "INFO"

    condition:
        uint32be(0) == 0x52617221							// RAR File Magic Header
        and not filename matches /(rarnew.dat|\.rar)$/is	// not the .RAR extension
        and not filepath contains "Recycle" 				// not a deleted RAR file in recycler
}

rule Base64_encoded_Executable {
    meta:
        id = "5I4Y278MAKW9XdU63AD9Ps"
        fingerprint = "v1_sha256_6ea4f98e0e209e689007e75bb66d202f343d8022d257758fefa78359b0ffd657"
        version = "1.0"
        score = 40
        date = "2015-05-28"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an base64 encoded executable (often embedded)"
        category = "INFO"

    strings:
        $s1 = "TVpTAQEAAAAEAAAA//8AALgAAAA" // 14 samples in goodware archive
        $s2 = "TVoAAAAAAAAAAAAAAAAAAAAAAAA" // 26 samples in goodware archive
        $s3 = "TVqAAAEAAAAEABAAAAAAAAAAAAA" // 75 samples in goodware archive
        $s4 = "TVpQAAIAAAAEAA8A//8AALgAAAA" // 168 samples in goodware archive
        $s5 = "TVqQAAMAAAAEAAAA//8AALgAAAA" // 28,529 samples in goodware archive
    condition:
        1 of them and not filepath contains "Thunderbird"
}

rule Binary_Drop_Certutil {
    meta:
        id = "4M64lkC1zvQsnoD36qEM2V"
        fingerprint = "v1_sha256_3e2b62442b5da6ab887e1eb03cdd44932651fa51ce11e87e6fc29015e708d2f3"
        version = "1.0"
        score = 70
        date = "2015-07-15"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Drop binary as base64 encoded cert trick"
        category = "INFO"
        reference = "https://goo.gl/9DNn8q"

    strings:
        $s0 = "echo -----BEGIN CERTIFICATE----- >" ascii
        $s1 = "echo -----END CERTIFICATE----- >>" ascii
        $s2 = "certutil -decode " ascii
    condition:
        filesize < 10KB and all of them
}

rule StegoKatz {
    meta:
        id = "3pU03HxZNZ5JWR7IHqcVDB"
        fingerprint = "v1_sha256_091b07220d2a89822aa382edcecf5869d463e375747cc41f52417e66ccf0e2da"
        version = "1.0"
        score = 70
        date = "2015-09-11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Encoded Mimikatz in other file types"
        category = "INFO"
        reference = "https://goo.gl/jWPBBY"

    strings:
        $s1 = "VC92Ny9TSXZMNk5jLy8vOUlqUTFVRlFNQTZMLysvdjlJaTh2L0ZUNXJBUUJJaTFRa1NFaUx6K2hWSS8vL1NJME44bklCQU9pZC92Ny9USTJjSkpBQUFBQXp3RW1MV3hCSmkyc1lTWXR6S0VtTDQxL0R6TXhNaTl4SmlWc0lUWWxMSUUySlF4aFZWbGRCVkVGVlFWWkJWMGlCN1BBQUFBQklnMlFrYUFDNE1BQUFBRW1MNkVTTmNPQ0pSQ1JnaVVRa1pFbU5RN0JKaTlsTWpRWFBGQU1BU0ls" ascii
        $s2 = "Rpd3ovN3FlalVtNklLQ0xNNGtOV1BiY0VOVHROT0Zud25CWGN0WS9BcEdMR28rK01OWm85Nm9xMlNnY1U5aTgrSTBvNkFob1FOTzRHQWdtUElEVmlqald0Tk90b2FmN01ESWJUQkF5T0pYbTB4bFVHRTBZWEFWOXVoNHBkQnRrS0VFWWVBSEE2TDFzU0c5a2ZFTEc3QWd4WTBYY1l3ZzB6QUFXS09JZE9wQVhEK3lnS3lsR3B5Q1ljR1NJdFNseGZKWUlVVkNFdEZPVjRJUldERUl1QXpKZ2pCQWdsd0Va" ascii
    condition:
        filesize < 1000KB and 1 of them
}
