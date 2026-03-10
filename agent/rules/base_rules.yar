rule Suspicious_Discovery_Commands {
    strings:
        $s1 = "whoami" ascii wide
        $s2 = "net group \"Domain Admins\"" ascii wide
        $s3 = "nltest /domain_trusts" ascii wide
    condition:
        any of them
}

rule Generic_Ransomware_Strings {
    strings:
        $r1 = "Your files have been encrypted" ascii wide
        $r2 = "all your files are encrypted" ascii wide
        $r3 = "RECOVER_FILES.txt" ascii wide
        $r4 = ".lockbit" ascii wide
    condition:
        2 of them
}

rule Webshell_Pattern {
    strings:
        $w1 = "eval(base64_decode" ascii wide
        $w2 = "system($_GET[" ascii wide
    condition:
        any of them
}
