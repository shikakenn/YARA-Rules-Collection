rule PDF_EMBEDDED_DOCM

{
    meta:
        id = "kpiESF6T7zTUDOvICfMzp"
        fingerprint = "v1_sha256_3a92efac52d7a9f265a454770910c39b4e2813eed83825abab048b10b14ae4d5"
        version = "1.0"
        modified = "May 11, 2017"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Brian Carter"
        description = "Find pdf files that have an embedded docm with openaction"
        category = "INFO"

    strings:
        $magic = { 25 50 44 46 2d }

        $txt1 = "EmbeddedFile"
        $txt2 = "docm)"
        $txt3 = "JavaScript" nocase

    condition:
        $magic at 0 and all of ($txt*)

}
