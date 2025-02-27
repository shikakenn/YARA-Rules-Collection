rule Linux_Rootkit_Jynx_c470eaff {
    meta:
        id = "2b6a2DYZ7NRagNUGGdMUBQ"
        fingerprint = "v1_sha256_02d1ec1670089a3d9743e57a8dd504f57cea897eca0f896c129fd4f30f24e700"
        version = "1.0"
        date = "2024-11-14"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.Jynx"
        reference_sample = "79c2ae1a95b44f3df42d669cb44db606d2088c5c393e7de5af875f255865ecb4"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $hook1 = "old_access"
        $hook2 = "old_lxstat"
        $hook3 = "old_open"
        $hook4 = "old_rmdir"
        $hook5 = "old_unlink"
        $hook6 = "old_xstat"
        $hook7 = "old_fopen"
        $hook8 = "old_opendir"
        $hook9 = "old_readdir"
        $hook10 = "forge_proc_net_tcp"
        $hook11 = "forge_proc_cpu"
    condition:
        4 of ($hook*)
}

