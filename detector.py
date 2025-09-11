import hashlib
import re
import pefile
import math
import subprocess
import shutil
import requests
import os
import traceback
from yara_scanner import YaraScanner

QUARANTINE_DIR = os.path.join(
    os.path.expanduser("~"), "Downloads", "protected_backup", "quarantine"
)

# Inicializa scanner YARA
yara_scanner = YaraScanner("rules")


# ==============================
# Funções auxiliares
# ==============================
def quarantine_file(path, quarantine_dir=QUARANTINE_DIR):
    """Move arquivo para quarentena e restringe permissões"""
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        dest = os.path.join(quarantine_dir, os.path.basename(path))
        shutil.move(path, dest)
        subprocess.run(f'icacls "{quarantine_dir}" /inheritance:r', shell=True)
        print(f"[quarantine] {path} movido para {dest}")
        return dest
    except Exception as e:
        print(f"[quarantine] erro: {e}")
        return None


def file_entropy(path, blocksize=65536):
    """Calcula entropia de um arquivo"""
    try:
        with open(path, "rb") as f:
            freq = [0] * 256
            total = 0
            while True:
                block = f.read(blocksize)
                if not block:
                    break
                total += len(block)
                for b in block:
                    freq[b] += 1
            if total == 0:
                return 0.0
            entropy = 0.0
            for c in freq:
                if c == 0:
                    continue
                p = c / total
                entropy -= p * math.log2(p)
            return entropy
    except Exception:
        return 0.0


def is_dotnet_assembly(path):
    """Detecta se o executável é um assembly .NET (CLR header)"""
    try:
        pe = pefile.PE(path)
        com_desc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  # CLR directory
        return com_desc.VirtualAddress != 0 and com_desc.Size != 0
    except Exception:
        return False


def extract_strings(path, min_len=4):
    """Extrai strings ASCII e UTF-16LE de um arquivo"""
    strings = set()
    try:
        with open(path, "rb") as f:
            data = f.read()
        # ASCII
        ascii_regex = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
        for m in ascii_regex.findall(data):
            try:
                strings.add(m.decode("utf-8", errors="ignore"))
            except:
                strings.add(m.decode("latin-1", errors="ignore"))
        # UTF-16LE
        utf16_regex = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)
        for m in utf16_regex.findall(data):
            try:
                strings.add(m.decode("utf-16le", errors="ignore"))
            except:
                pass
    except Exception:
        pass
    return list(strings)


def section_entropy(data):
    """Calcula entropia de um bloco de bytes (section do PE)"""
    freq = [0] * 256
    total = len(data)
    for b in data:
        freq[b] += 1
    entropy = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


# ==============================
# Detector original (YARA + hash lookup)
# ==============================
def DetectorMalware(path):
    """Executa YARA scan e consulta MalwareBazaar"""
    try:
        # YARA scan
        matches = yara_scanner.scan_file(path)
        if matches:
            print(f"[YARA] {path} corresponde às regras: {matches}")
            quarantine_file(path)

        # Hash lookup MalwareBazaar
        import hashlib

        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": file_hash},
            timeout=10,
        )

        if resp and resp.status_code == 200 and "malware" in resp.text.lower():
            print(f"[MalwareBazaar] {path} encontrado na base como malware!")
            quarantine_file(path)

    except Exception as e:
        print(f"[DetectorMalware erro] {e}")


# ==============================
# Detector heurístico MSIL/Gorf
# ==============================
def detect_and_respond_msil(path, proc_info=None):
    """Detecta padrões de ransomware MSIL/Gorf"""
    try:
        is_dotnet = is_dotnet_assembly(path)
        strs = extract_strings(path, min_len=4)
        joined = " ".join(s.lower() for s in strs)

        has_crypto = any(
            k in joined
            for k in [
                "aescrypt",
                "rijndael",
                "crypt",
                "encrypt",
                "cryptencrypt",
                "cryptservice",
            ]
        )
        has_dotnet_main = any(
            k in joined
            for k in [
                "mscorlib",
                "system.io",
                "system.security.cryptography",
                "writeallbytes",
                "directory.getfiles",
                "file.move",
                "vssadmin",
            ]
        )
        has_note = any(
            k in joined for k in ["recover", "decrypt", "readme", "how to recover"]
        )
        obfuscator = any(
            k in joined for k in ["confuser", "dotfuscator", "obfus", "packer"]
        )

        ent = file_entropy(path) if os.path.getsize(path) > 4096 else 0.0

        # Score heurístico
        score = 0
        if is_dotnet:
            score += 2
        if has_crypto:
            score += 2
        if has_dotnet_main:
            score += 1
        if has_note:
            score += 2
        if obfuscator:
            score += 2
        if ent > 7.2:
            score += 2

        if score >= 4:
            print(f"[MSIL DETECT] {path} score={score} entropy={ent:.2f}")
            quarantine_file(path)
            return True
        else:
            print(f"[MSIL CHECK] {path} score={score} entropy={ent:.2f}")
            return False
    except Exception as e:
        print(f"[detect_and_respond_msil erro] {e}")
        return False


# ==============================
# Detector heurístico Trojan:Win32/Vigorf.A
# ==============================
def check_vigorf(path):
    """Detecta heurísticas associadas ao Trojan:Win32/Vigorf.A"""
    score = 0
    try:
        pe = pefile.PE(path)

        # 1. Section entropy
        for s in pe.sections:
            ent = section_entropy(s.get_data())
            if ent > 7.2:  # section altamente comprimida/cifrada
                score += 2

        # 2. Imports suspeitos
        suspicious = [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetThreadContext",
            "NtUnmapViewOfSection",
        ]
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and any(
                        api.lower() in imp.name.decode(errors="ignore").lower()
                        for api in suspicious
                    ):
                        score += 2

        # 3. Packers comuns
        with open(path, "rb") as f:
            data = f.read()
        if any(sig in data for sig in [b"UPX!", b"ASPack", b"MPRESS", b"Themida", b"PETITE"]):
            score += 2

        if score >= 4:
            print(f"[VIGORF DETECT] {path} score={score}")
            quarantine_file(path)
            return True
        else:
            print(f"[VIGORF CHECK] {path} score={score}")
            return False
    except Exception as e:
        print(f"[check_vigorf erro] {e}")
        return False