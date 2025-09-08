rule Honeypot_Tampering
{
    meta:
        description = "Detecta alteração em honeypots poraoX.txt"
        author = "Porão"

    strings:
        $s1 = "porao0.txt"
        $s2 = "porao1.txt"
        $s3 = "porao" nocase

    condition:
        any of ($s*)
}