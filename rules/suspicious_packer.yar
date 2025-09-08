rule Suspicious_Packer
{
    meta:
        description = "Detecta executáveis compactados com UPX/MPRESS"
        author = "Porão"

    strings:
        $p1 = "UPX!"
        $p2 = "MPRESS1"

    condition:
        any of ($p*)
}