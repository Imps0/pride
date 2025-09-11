rule Ransomware_REvil
{
  meta:
    description = "Detect REvil/Sodinokibi ransomware"
    author = "imps"
    date = "2025-09-10"

  strings:
    $ext1 = ".REvil" nocase
    $ext2 = ".Sodinokibi" nocase
    $note1 = "REvil" nocase
    $note2 = "Sodinokibi" nocase
    $note3 = "All your files are encrypted" nocase

  condition:
    any of ($ext*) or 2 of ($note*)
}
