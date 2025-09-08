rule Ransomware_Generic_Strings
{
    meta:
        description = "Strings comuns em ransomwares"
        author = "Porão"

    strings:
        $a1 = "Bitcoin" nocase
        $a2 = "RSA-2048"
        $a3 = "AES-256"
        $a4 = "All your files"
        $a5 = "Encrypted files"

    condition:
        2 of ($a*)
}