rule Wannacry_like {
  meta:
    author = "imps"
    date = "2025-09-10"
    description = "Detect strings and ransom-note patterns related to WannaCry-like samples"
  strings:
    $s1 = "WanaDecryptor"
    $s2 = "WannaDecryptor"
    $s3 = "WanaCrypt0r"
    $s4 = "WNCRY"
    $note = "Please readme" nocase
    $ext = ".WNCRY" nocase
  condition:
    any of ($s1, $s2, $s3, $s4) or $note or $ext
}
