import "pe"

rule sus_pe_free_without_allocation: TESTING SUSPICIOUS TA0005 T1027 T1027_007 {
    meta:
        id = "5k3TdDhXUxr17xYtSHZZ0E"
        fingerprint = "v1_sha256_d3bd072c72361c80ca93f51547490f8ca18b4b6ca8874c509ad91147b7473a28"
        version = "1.1"
        date = "2023-05-13"
        modified = "2023-05-13"
        status = "TESTING"
        sharing = "TLP:WHITE"
        source = "THIEBAUT.DEV"
        author = "Maxime THIEBAUT (@0xThiebaut)"
        description = "Detects an executable importing functions to free memory without importing allocation functions, often indicative of dynamic import resolution"
        category = "INFO"
        mitre_att = "T1027.007"
        first_imported = "2023-05-13"

    condition:
        pe.number_of_imports <= 3   // Restrict to low-import executables
        and (pe.imports("kernel32.dll", "VirtualFree") or pe.imports("kernel32.dll", "VirtualFreeEx"))
        and not (
            pe.imports("gdi32.dll")
            or pe.imports("kernel32.dll", "VirtualAlloc")
            or pe.imports("kernel32.dll", "VirtualAlloc2")
            or pe.imports("kernel32.dll", "VirtualAlloc2FromApp")
            or pe.imports("kernel32.dll", "VirtualAllocEx")
            or pe.imports("kernel32.dll", "VirtualAllocExNuma")
            or pe.imports("kernel32.dll", "VirtualAllocFromApp")
        )
}
