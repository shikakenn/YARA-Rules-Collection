import "pe"
rule Check_Debugger
{
    meta:
        id = "3dCIGp9uxtVXHEDtVA2Jxx"
        fingerprint = "v1_sha256_40ea29c3e45363b559c64e9e6b13fad01ea2f2d5e01cb7604b6af5af8eabbe3d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Nick Hoffman"
        Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
        Sample = "de1af0e97e94859d372be7fcf3a5daa5"

    condition:
        pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and 
        pe.imports("kernel32.dll","IsDebuggerPresent")
}
