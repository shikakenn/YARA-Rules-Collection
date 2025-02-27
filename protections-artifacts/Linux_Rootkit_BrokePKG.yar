rule Linux_Rootkit_BrokePKG_7b7d4581 {
    meta:
        id = "6zwJ8fJAETWylarL5gZBNo"
        fingerprint = "v1_sha256_a4e5916fa0ca6b07fcbb6f970abb0212a970cf723b906e605c18e620efc501dc"
        version = "1.0"
        date = "2024-11-13"
        modified = "2024-11-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Rootkit.BrokePKG"
        reference_sample = "97c5e011c7315a05c470eef4032030e461ec2a596513703beedeec0b0c6ed2da"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $license1 = "author=R3tr074"
        $license2 = "name=brokepkg"
        $license3 = "description=Rootkit"
        $license4 = "license=GPL"
        $str1 = "brokepkg"
        $str2 = "brokepkg: module revealed"
        $str3 = "brokepkg: hidden module"
        $str4 = "brokepkg: given away root"
        $str5 = "brokepkg unloaded, my work has completed"
        $str6 = "br0k3_n0w_h1dd3n"
        $hook1 = "nf_inet_hooks"
        $hook2 = "ftrace_hook"
        $hook3 = "hook_getdents"
        $hook4 = "hook_kill"
        $hook5 = "hook_tcp4_seq_show"
        $hook6 = "hook_tcp6_seq_show"
        $hook7 = "orig_tcp6_seq_show"
        $hook8 = "orig_tcp4_seq_show"
        $hook9 = "orig_kill"
        $hook10 = "orig_getdents"
    condition:
        3 of ($license*) or 2 of ($str*) or 4 of ($hook*)
}

