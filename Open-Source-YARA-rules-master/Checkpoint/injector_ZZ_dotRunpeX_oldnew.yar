rule injector_ZZ_dotRunpeX_oldnew {
    meta:
        id = "2zenolwGz21Cvds7gIyhVG"
        fingerprint = "v1_sha256_c6ae0b4fb6cae16ae8d71e238f7753e0eadd23820507616fa2331375f4403052"
        version = "1.0"
        date = "2022-10-30"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jiri Vinopal (jiriv)"
        description = "Detects new and old version of dotRunpeX - configurable .NET injector"
        category = "INFO"
        report = "HTTPS://RESEARCH.CHECKPOINT.COM/2023/DOTRUNPEX-DEMYSTIFYING-NEW-VIRTUALIZED-NET-INJECTOR-USED-IN-THE-WILD/"
        hash1_New = "373a86e36f7e808a1db263b4b49d2428df4a13686da7d77edba7a6dd63790232"
        hash2_New = "41ea8f9a9f2a7aeb086dedf8e5855b0409f31e7793cbba615ca0498e47a72636"
        hash3_New = "5e3588e8ddebd61c2bd6dab4b87f601bd6a4857b33eb281cb5059c29cfe62b80"
        hash4_New = "8c451b84d9579b625a7821ad7ddcb87bdd665a9e6619eaecf6ab93cd190cf504"
        hash5_New = "8fa81f6341b342afa40b7dc76dd6e0a1874583d12ea04acf839251cb5ca61591"
        hash6_New = "cd4c821e329ec1f7bfe7ecd39a6020867348b722e8c84a05c7eb32f8d5a2f4db"
        hash7_New = "fa8a67642514b69731c2ce6d9e980e2a9c9e409b3947f2c9909d81f6eac81452"
        hash8_New = "eb2e2ac0f5f51d90fe90b63c3c385af155b2fee30bc3dc6309776b90c21320f5"
        hash1_Old = "1e7614f757d40a2f5e2f4bd5597d04878768a9c01aa5f9f23d6c87660f7f0fbc"
        hash2_Old = "317e6817bba0f54e1547dd9acf24ee17a4cda1b97328cc69dc1ec16e11c258fc"
        hash3_Old = "65cac67ed2a084beff373d6aba6f914b8cba0caceda254a857def1df12f5154b"
        hash4_Old = "68ae2ee5ed7e793c1a49cbf1b0dd7f5a3de9cb783b51b0953880994a79037326"
        hash5_Old = "81763d8e3b42d07d76b0a74eda4e759981971635d62072c8da91251fc849b91e"

    strings:
    // Used ImplMap imports (PInvoke) 
        $implmap1 = "VirtualAllocEx"
        $implmap2 = "CreateProcess"
        $implmap3 = "CreateRemoteThread"
        $implmap4 = "Wow64SetThreadContext"
        $implmap5 = "Wow64GetThreadContext"
        $implmap6 = "RtlInitUnicodeString"
        $implmap7 = "NtLoadDriver"
        $implmap8 = "LoadLibrary"
        $implmap9 = "VirtualProtect"
        $implmap10 = "AdjustTokenPrivileges"
        $implmap11 = "GetProcAddress"
        $modulerefKernel1 = "Kernel32"
        $modulerefKernel2 = "kernel32"
        $modulerefNtdll1 = "Ntdll"
        $modulerefNtdll2 = "ntdll"

        $regPath = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TaskKill" wide // Registry path for installing Sysinternals Procexp driver
        $rsrcName = "BIDEN_HARRIS_PERFECT_ASSHOLE" wide
        $koiVM1 = "KoiVM"
        $koiVM2 = "#Koi"
    condition:
        uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550 and ($regPath or $rsrcName or 1 of ($koiVM*)) and
        9 of ($implmap*) and 1 of ($modulerefKernel*) and 1 of ($modulerefNtdll*) 
}
