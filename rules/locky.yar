rule Ransomware_Locky
{
  meta:
    description = "Detect Locky ransomware"
    author = "imps"
    date = "2025-09-10"

  strings:
    $ext1 = ".locky" nocase
    $ext2 = ".zepto" nocase
    $ext3 = ".odin" nocase
    $note1 = "_Locky_recover_instructions.txt" nocase
    $note2 = "!!! IMPORTANT INFORMATION !!!" nocase

  condition:
    any of ($ext*) or any of ($note*)
}
