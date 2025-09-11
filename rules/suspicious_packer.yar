rule Suspicious_Packer {
  meta:
    author = "imps"
    date = "2025-09-10"
    description = "Detect common packer signatures (UPX, etc.) - may indicate obfuscated malware"
  strings:
    $upx1 = "UPX!" ascii
    $upx2 = "UPX0" ascii
    $themida = "Themida" ascii
    $aspack = "ASPack" ascii
  condition:
    any of ($upx1, $upx2, $themida, $aspack)
}
