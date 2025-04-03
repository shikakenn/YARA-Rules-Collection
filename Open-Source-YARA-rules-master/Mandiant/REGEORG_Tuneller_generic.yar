rule REGEORG_Tuneller_generic

{

    meta:
        id = "4dGCkPUdq1O5JzbXNE3gJS"
        fingerprint = "v1_sha256_1657928875c3cd2d5bf774929b0497d78f0211b321f8a4138cc9b8c80b9f99d6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        reference = "https://www.mandiant.com/resources/unc3524-eye-spy-email"
        date_created = "2021-12-20"
        date_modified = "2021-12-20"
        md5 = "ba22992ce835dadcd06bff4ab7b162f9"

    strings:

        $s1 = "System.Net.IPEndPoint"

        $s2 = "Response.AddHeader"

        $s3 = "Request.InputStream.Read"

        $s4 = "Request.Headers.Get"

        $s5 = "Response.Write"

        $s6 = "System.Buffer.BlockCopy"

        $s7 = "Response.BinaryWrite"

        $s8 = "SocketException soex"

    condition:

        filesize < 1MB and 7 of them

}

