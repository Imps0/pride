rule Honeypot_Tamper {
  meta:
    author = "audit"
    date = "2025-09-10"
    description = "Detect tampering of the honeypot files created by the tool"
  strings:
    $hp = "arquivo feito para detectar o ransomware" nocase
    $por = ".porao" nocase
  condition:
    $hp or $por
}
