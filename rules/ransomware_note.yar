rule Ransomware_Note
{
    meta:
        description = "Detecta notas de resgate comuns de ransomwares"
        author = "imps"
        reference = "on_created -> busca por decrypt/restore/recover"

    strings:
        $s1 = "decrypt"
        $s2 = "restore"
        $s3 = "recover"
        $s4 = "your files have been encrypted" nocase

    condition:
        any of ($s*)
}