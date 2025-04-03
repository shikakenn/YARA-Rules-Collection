rule apt_nix_elf_derusbi_kernelModule
{
    meta:
        id = "4LxgzQgSsSafPrqEOWRZfG"
        fingerprint = "v1_sha256_b7f24956c0829dad04e546b9ff4137a63de8537286dd9b0f624aa1107efe2494"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fidelis Cybersecurity"
        description = "NA"
        category = "INFO"
        reference = "https://www.fidelissecurity.com/resources/turbo-campaign-featuring-derusbi-64-bit-linux"

    strings:
        $ = "__this_module"   
        $ = "init_module"      
        $ = "unhide_pid"       
        $ = "is_hidden_pid"    
        $ = "clear_hidden_pid" 
        $ = "hide_pid"
        $ = "license"
        $ = "description"
        $ = "srcversion="
        $ = "depends="
        $ = "vermagic="
        $ = "current_task"
        $ = "sock_release"
        $ = "module_layout"
        $ = "init_uts_ns"
        $ = "init_net"
        $ = "init_task"
        $ = "filp_open"
        $ = "__netlink_kernel_create"
        $ = "kfree_skb"

    condition:
        (uint32(0) == 0x4464c457f) and (all of them)
}
