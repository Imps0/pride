# PoraoRansomwareDetect

## Sobre a Ferramenta

Ferramenta em Python feita para **detectar e reagir a atividades suspeitas de ransomware e malware** em máquinas Windows, utilizando:

- **Machine Learning (árvore de decisão)** para analisar comportamento de arquivos.
- **YARA rules** para detectar padrões conhecidos de ransomware e packers maliciosos.
- **Consultas ao MalwareBazaar** via hash (SHA256) para verificar se o arquivo é conhecido.
- **Medidas defensivas automáticas**:
  - Criação de honeypots para atrair ransomwares.
  - Encerramento de processos suspeitos.
  - Criação e proteção de backups (`shadow copy`).
  - Restrição de permissões de acesso a pastas sensíveis.
  - Registro no Windows para iniciar junto com o sistema.

⚠️ **Compatibilidade:** este sistema foi projetado para **Windows**.  
Não funciona em Linux/macOS, pois depende de `wmic`, `icacls`, `winreg` e outros componentes do Windows.

---

## Como Executar

1. Instale as dependências (Python 3.8+):

pip install -r requirements.txt

2.Execute como Administrador (necessário para manipular permissões, shadow copies e registro):

python porao.py
