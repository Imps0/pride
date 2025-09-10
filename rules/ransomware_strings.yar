rule Ransomware_Notes_Keywords {
  meta:
    author = "audit"
    date = "2025-09-10"
    description = "Detect common ransomware note / keywords"
  strings:
    $a = "decrypt" nocase
    $b = "restore" nocase
    $c = "recover" nocase
    $d = "contact" nocase
    $e = "readme" nocase
    $f = "how to restore" nocase
  condition:
    3 of them
}
