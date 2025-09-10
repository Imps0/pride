import hashlib
import requests
import os
import traceback
from yara_scanner import YaraScanner

# carrega regras (pasta rules/)
yara_scanner = YaraScanner("rules")

class Hash:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def gerar_hash(self) -> str:
        sha256 = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

class ColetaDados:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.url = "https://mb-api.abuse.ch/api/v1/"
        self.malware = False
        self.malware_info = {}
        self.error = None

    def dataBase_Search(self, sha256: str):
        try:
            data = {"query": "get_info", "hash": sha256}
            resp = requests.post(self.url, data=data, timeout=10)
            resp.raise_for_status()
            j = resp.json()
            status = j.get("query_status", "")
            if status in ("hash_not_found", "illegal_hash"):
                self.malware = False
                return
            entry = j.get("data", [{}])[0]
            self.malware_info["signature"] = entry.get("signature")
            self.malware_info["sha256"] = entry.get("sha256_hash")
            self.malware_info["locate"] = self.filepath
            self.malware = True
        except Exception as e:
            self.error = str(e)
            self.malware = False

class DetectorMalware:
    """
    Inicialize com o caminho do arquivo: DetectorMalware("C:\\path\\file.exe")
    O construtor roda verificações YARA + hash no MalwareBazaar e imprime resultados.
    Não lança exceções fatais.
    """
    def __init__(self, src_path: str):
        self.src_path = src_path
        self.yara_matches = []
        self.sha256 = None
        self.mb_info = None
        try:
            if not os.path.exists(self.src_path):
                print(f"[DetectorMalware] arquivo não existe: {self.src_path}")
                return
            self._run_checks()
        except Exception:
            print(f"[DetectorMalware] Erro geral ao processar {self.src_path}:\n{traceback.format_exc()}")

    def _run_checks(self):
        # 1) YARA
        try:
            if yara_scanner and hasattr(yara_scanner, "scan_file"):
                matches = yara_scanner.scan_file(self.src_path)
                if matches:
                    self.yara_matches = matches
                    print(f"[YARA] ALERTA! {self.src_path} corresponde às regras: {matches}")
        except Exception as e:
            print(f"[YARA] Erro ao escanear {self.src_path}: {e}")

        # 2) Hash + MalwareBazaar
        try:
            self.sha256 = Hash(self.src_path).gerar_hash()
            coleta = ColetaDados(self.src_path)
            coleta.dataBase_Search(self.sha256)
            if coleta.malware:
                self.mb_info = coleta.malware_info
                print(self._format_mb_info(self.mb_info))
            else:
                if not self.yara_matches:
                    print(f"\n[DetectorMalware] Não foi detectado nenhum Malware em {self.src_path}.\n")
        except Exception as e:
            print(f"[DetectorMalware] Erro ao gerar hash/consultar DB para {self.src_path}: {e}")

    def _format_mb_info(self, info: dict) -> str:
        return (
            f'\nFoi encontrado um Malware!\n{"-"*30}\n'
            f'Signature: {info.get("signature")}\n'
            f'SHA256: {info.get("sha256")}\n'
            f'Locate: {info.get("locate")}\n{"-"*30}\n'
        )
