rule Ransomware_Ryuk
{
  meta:
    description = "Detect Ryuk ransomware"
    author = "Porao"
    date = "2025-09-10"

  strings:
    $ext = ".ryk" nocase
    $note1 = "RyukReadMe.txt" nocase
    $note2 = "Your network has been penetrated" nocase
    $note3 = "Do not rename encrypted files" nocase

  condition:
    any of ($ext, $note1, $note2, $note3)
}
