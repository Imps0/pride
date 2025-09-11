rule Ransomware_Maze
{
  meta:
    description = "Detect Maze ransomware"
    author = "imps"
    date = "2025-09-10"

  strings:
    $ext = ".maze" nocase
    $note1 = "DECRYPT-FILES.txt" nocase
    $note2 = "Your files are encrypted" nocase
    $note3 = "MAZE" nocase

  condition:
    any of ($ext, $note1, $note2, $note3)
}
