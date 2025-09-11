# ==============================
# Script de instalação do Sysmon com configuração anti-ransomware
# ==============================

# 1. Criar pasta base
$sysmonDir = "C:\Sysmon"
if (!(Test-Path $sysmonDir)) {
    New-Item -Path $sysmonDir -ItemType Directory | Out-Null
    Write-Host "[OK] Pasta $sysmonDir criada"
} else {
    Write-Host "[INFO] Pasta $sysmonDir já existe"
}

# 2. Baixar Sysmon do site oficial
$zipPath = "$sysmonDir\Sysmon.zip"
$downloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"

Write-Host "[INFO] Baixando Sysmon..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

# 3. Extrair arquivos
Write-Host "[INFO] Extraindo Sysmon..."
Expand-Archive -Path $zipPath -DestinationPath $sysmonDir -Force

# 4. Criar arquivo sysmon_config.xml com regras anti-ransomware
$configPath = "$sysmonDir\sysmon_config.xml"
@"
<Sysmon schemaversion="4.70">
  <EventFiltering>

    <!-- Monitorar criação de processos perigosos -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">vssadmin delete shadows</CommandLine>
      <CommandLine condition="contains">wbadmin delete</CommandLine>
      <CommandLine condition="contains">bcdedit</CommandLine>
      <CommandLine condition="contains">wmic shadowcopy</CommandLine>
      <CommandLine condition="contains">powershell -enc</CommandLine>
      <CommandLine condition="contains">powershell -encodedcommand</CommandLine>
      <CommandLine condition="contains">cscript</CommandLine>
      <CommandLine condition="contains">wscript</CommandLine>
    </ProcessCreate>

    <!-- Monitorar carregamento de DLLs críticas do .NET (MSIL/Ransomware) -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">clr.dll</ImageLoaded>
      <ImageLoaded condition="contains">mscorlib.dll</ImageLoaded>
    </ImageLoad>

    <!-- Monitorar criação de arquivos suspeitos (notas de resgate) -->
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">README.txt</TargetFilename>
      <TargetFilename condition="end with">HOW_TO_DECRYPT.txt</TargetFilename>
      <TargetFilename condition="contains">RECOVER</TargetFilename>
    </FileCreate>

  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $configPath -Encoding utf8

Write-Host "[OK] sysmon_config.xml criado em $configPath"

# 5. Instalar Sysmon com configuração
$sysmonExe = Join-Path $sysmonDir "Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Write-Host "[INFO] Instalando Sysmon como serviço..."
    Start-Process -FilePath $sysmonExe -ArgumentList "-i `"$configPath`" -accepteula" -Verb RunAs -Wait
    Write-Host "[OK] Sysmon instalado e configurado!"
} else {
    Write-Host "[ERRO] Sysmon64.exe não encontrado após extração."
}
