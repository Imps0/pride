# 🛡️ PoraoRansomwareDetect

Ferramenta em Python para **detecção e resposta a ransomwares/malwares em Windows**.  
Ela combina **Machine Learning**, **regras YARA**, **consultas a banco externo (MalwareBazaar)** e **técnicas defensivas automáticas**.

---

## 🚀 Funcionalidades

- **Detecção comportamental**  
  Classificador de Machine Learning (Decision Tree) avalia eventos de arquivos (criação, modificação, deleção, movimento, edição de honeypots).

- **Assinaturas YARA**  
  Detecta ransomwares conhecidos, packers suspeitos e tentativas de alteração nos honeypots.

- **Consultas em base externa (MalwareBazaar)**  
  Verifica hashes SHA256 de executáveis contra banco público de malware.

- **Medidas defensivas automáticas**
  - Criação de honeypots (.porao*.txt).  
  - Criação e proteção de backups (shadow copies).  
  - Encerramento de processos suspeitos.  
  - Quarentena de binários detectados.  
  - Restrição de permissões em pastas críticas.  
  - Registro no Windows para execução automática na inicialização.

---

## ⚠️ Aviso Importante

- Esta ferramenta é **experimental e educacional**.  
- **Não substitui antivírus/EDR**.  
- Teste apenas em **ambientes isolados (VM)**.  
- Um ransomware real pode causar dano **antes da detecção**.  
- Recomendado usar junto com: patch de segurança atualizado, antivírus profissional, firewall e backups offline.

---

## 📋 Pré-requisitos

### 1. Python
- Windows 10 ou 11  
- Python **3.8 até 3.11** (Python 3.12+ pode causar problemas de compatibilidade)  
- Download: [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)  
- Durante a instalação marque **“Add Python to PATH”**



### 2. Dependências Python
Na raiz do projeto existe o arquivo `requirements.txt`.  
Para instalar tudo de uma vez (abra PowerShell **como Administrador**):

powershell
cd "C:\Users\seuuser\Downloads\pride"
pip install -r requirements.txt

Set-ExecutionPolicy RemoteSigned -Scope Process -Force
.\setup-sysmon.ps1

Execute:
python porao.py

O programa irá:

Criar honeypots.
Criar e proteger backup (protected_backup).
Monitorar a pasta Downloads do usuário.
Encerrar processos suspeitos e quarentenar binários.
Exibir alertas de YARA ou MalwareBazaar.

Para parar, pressione CTRL + C.

🔧 Comandos Auxiliares

Liberar backup protegido:
python destravar.py

Ver shadow copies criadas:
vssadmin list shadows

Ver usuários do sistema:
wmic useraccount get name
