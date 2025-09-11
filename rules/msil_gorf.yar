rule MSIL_Gorf_family
{
  meta:
    author = "imps"
    date = "2025-09-10"
    description = "Signatures heuristic para detectar executáveis .NET (MSIL) com indicadores de ransomware (Gorf-like)."

  strings:
    // Indicadores .NET / MSIL metadata
    $mscorlib = "mscorlib" nocase
    $system_io = "System.IO" nocase
    $crypto_ns = "System.Security.Cryptography" nocase
    $aes = "AesCryptoServiceProvider" nocase
    $rijndael = "RijndaelManaged" nocase
    $encrypt_method = "Encrypt" nocase
    $writeallbytes = "WriteAllBytes" nocase
    $directory_getfiles = "Directory.GetFiles" nocase
    $file_move = "File.Move" nocase
    $vssadm = "vssadmin" nocase
    // strings de notas / extensões associadas
    $rnote = "recover" nocase
    $extwn = ".gorf" nocase

    // possíveis artefatos de obfuscação .NET (confuserex, dotfuscator)
    $confuser = "Confuser" nocase
    $dotf = "Dotfuscator" nocase

  condition:
    // regra heurística: arquivo .NET (mscorlib ou System.IO) + ao menos 2 indicadores de criptografia/IO ou nota/extensão
    (any of ($mscorlib, $system_io)) and ( 2 of ($crypto_ns, $aes, $rijndael, $encrypt_method, $writeallbytes, $directory_getfiles, $file_move, $vssadm, $rnote, $extwn) )
    or any of ($confuser, $dotf)
}
