/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) 
    and open to any user or organization, as long as you use it under this license.
*/

rule dropperMapin
{
    meta:
        id = "1RLmsSwQ9v80hv8BTr0pzf"
        fingerprint = "v1_sha256_c32a5f804f8b87d5f6e93b3f8d3686ee99ad32713e5ce907797d510813743bb6"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "HTTPS://KOODOUS.COM/"
        author = "https://twitter.com/plutec_net"
        description = "This rule detects mapin dropper files"
        category = "INFO"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
        sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"

    strings:
        $a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
        $b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
        $c = "device_admin"

    condition:
        all of them
}


rule Mapin
{
    meta:
        id = "kWNpn2MIM9QE4z38QVqxS"
        fingerprint = "v1_sha256_b0cb23b6e46f2bcfd74aeb9d732c465937be347400b6a1256a42f8e6c2b432dc"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "HTTPS://KOODOUS.COM/"
        author = "https://twitter.com/plutec_net"
        description = "Mapin trojan, not for droppers"
        category = "INFO"
        reference = "http://www.welivesecurity.com/2015/09/22/android-trojan-drops-in-despite-googles-bouncer/"
        sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

    strings:
        $a = "138675150963" //GCM id
        $b = "res/xml/device_admin.xml"
        $c = "Device registered: regId ="
        

    condition:
        all of them
        
}
