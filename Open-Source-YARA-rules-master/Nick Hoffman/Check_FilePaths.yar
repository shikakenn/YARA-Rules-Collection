import "pe"
rule Check_FilePaths
{
    meta:
        id = "6aaHQyodbjKI5AX0YM3k8E"
        fingerprint = "v1_sha256_e57506f937e1d8f39f1487e4e6ab86fa770fd31231273512d78bcb3a2f65de73"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Checks for filepaths containing popular sandbox names"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    strings: 
        $path1 = "SANDBOX" wide ascii
        $path2 = "\\SAMPLE" wide ascii
        $path3 = "\\VIRUS" wide ascii
    condition:
        all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}
