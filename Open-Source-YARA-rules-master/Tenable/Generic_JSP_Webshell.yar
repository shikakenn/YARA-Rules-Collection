rule generic_jsp
{
    meta:
        id = "7b239M2d4Wr6x0EJlCGRN"
        fingerprint = "v1_sha256_3a175d68a6e69b351c423a3b3e02bf15b7c733668002613d76edff0bd2af0270"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Generic JSP"
        category = "INFO"
        hash = "6517e4c8f19243298949711b48ae2eb0b6c764235534ab29603288bc5fa2e158"
        family = "JSP Backdoor"
        filetype = "JSP"

    strings:
        $exec = /Runtime.getRuntime\(\).exec\(request.getParameter\(\"[a-zA-Z0-9]+\"\)\);/ ascii

    condition:
        all of them
}
