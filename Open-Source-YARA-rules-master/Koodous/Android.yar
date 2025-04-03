rule Android
{
    meta:
        id = "7B42psak7cZbSgP44cGawn"
        fingerprint = "v1_sha256_441e7530a74aacc0479cf57b25a8336217abfd5729accdb6daed63ec7e970705"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "This is a generic detaction for ANY Android application."
        category = "INFO"
        filetype = "apk"

    strings:
        $Header = "PK"
        $b = "assets"
        $c = "META-INF"
        $d = "AndroidManifest.xml"
        $e = "classes.dex"

    condition:
        all of them
}
