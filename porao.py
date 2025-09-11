# porao.py (versão melhorada)
from comportamento import avaliar
from detector import DetectorMalware, detect_and_respond_msil, check_vigorf
import win32evtlog
import win32evtlogutil
import os
import pathlib
import psutil
import time
import subprocess
import regex as re
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import RegistroAdd as registry
from collections import deque

# Globals
data_list = []
users_list = []
username = os.getlogin()
change_type = [0, 0, 0, 0, 0]  # created, modified, moved, deleted, edits (honeypot)
ult_processos = []
time_since_last_change = 100
last_shadow_backup = 0

# Event rate detection: timestamps (secs) of file events
event_timestamps = deque(maxlen=5000)
# Thresholds (ajustáveis)
EVENT_WINDOW_SECONDS = 5
EVENTS_THRESHOLD = 150  # se >150 eventos em 5s, sinaliza possivel ransomware

# Whitelist de processos (nomes) que não devem ser terminados
WHITELIST_PROCS = {"OneDrive.exe", "Dropbox.exe", "GoogleDriveFS.exe", "GoogleDrive.exe",
                   "MsMpEng.exe", "explorer.exe", "System", "svchost.exe", "chrome.exe", "msedge.exe"}

protected_backup = f"C:\\Users\\{username}\\Downloads\\protected_backup"
quarantine_dir = os.path.join(protected_backup, "quarantine")

import threading

def monitor_sysmon():
    """
    Monitora eventos do Sysmon (Event Viewer) e reage a comandos suspeitos.
    """
    server = "localhost"
    log_type = "Microsoft-Windows-Sysmon/Operational"

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        print(f"[Sysmon] Falha ao abrir log: {e}")
        return

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    offset = 0

    print("[Sysmon] Monitorando eventos em tempo real...")

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, offset)
        if not events:
            time.sleep(2)
            continue

        for event in events:
            try:
                if not event.StringInserts:
                    continue

                message = " ".join(str(s) for s in event.StringInserts if s)

                # Comandos perigosos típicos de ransomware
                alert_patterns = [
                    "vssadmin delete shadows",
                    "wbadmin delete",
                    "bcdedit",
                    "wmic shadowcopy",
                    "powershell -enc",
                    "powershell -encodedcommand",
                ]

                if any(pat.lower() in message.lower() for pat in alert_patterns):
                    print(f"[Sysmon ALERTA] Comando suspeito detectado: {message}")

                    # Se possível, encerrar processo suspeito
                    pid = None
                    try:
                        # Alguns eventos trazem PID no StringInserts
                        for s in event.StringInserts:
                            if s and s.isdigit():
                                pid = int(s)
                                break
                    except:
                        pass

                    if pid:
                        encerrar_proctree(pid)
                        print(f"[Sysmon] Processo {pid} encerrado.")
                    else:
                        print("[Sysmon] Não foi possível identificar o PID.")
            except Exception as e:
                print(f"[Sysmon erro] {e}")

def encerrar_proctree():
    global ult_processos
    print("Possível Ransomware detectado! Encerrando processos suspeitos.")
    pids = []
    for pid in reversed(ult_processos):
        if pid != os.getpid():
            pids.append(pid)
    if not pids:
        return
    pid_args = " ".join(f"/PID {p}" for p in pids)
    try:
        subprocess.run(f"taskkill {pid_args} /F /T", shell=True)
        print(f"taskkill executado para PIDs: {pids}")
    except Exception as e:
        print(f"Erro ao taskkill: {e}")
    ult_processos.clear()

def extrair_extensao(file: str):
    extensions = [".exe", ".dll", ".ps1", ".vbs", ".bat", ".cmd", ".js", ".scr", ".pif"]
    file_extension = pathlib.Path(file).suffix
    return file_extension.lower() in extensions

def start_protection():
    global users_list
    global username
    try:
        procname = psutil.Process(os.getpid()).name()
        subprocess.run(f'wmic process where name="{procname}" CALL setpriority "above normal"', shell=True)
    except Exception:
        pass
    os.makedirs(protected_backup, exist_ok=True)
    os.makedirs(quarantine_dir, exist_ok=True)
    # Tentar proteção do vssadmin (NOTA: isto é frágil — ver seção de melhorias)
    try:
        subprocess.run(f'takeown /F C:\\Windows\\System32\\vssadmin.exe', shell=True)
        subprocess.run(f'icacls C:\\Windows\\System32\\vssadmin.exe /grant "{username}":F', shell=True)
        subprocess.run(f'ren C:\\Windows\\System32\\vssadmin.exe adminvss.exe', shell=True)
    except Exception:
        pass
    # coletar usuários
    get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True)
    users = get_users.stdout.decode()
    users = re.split(r"\W|Name|\r|\n", users)
    for user in list(users):
        user = user.strip()
        if user == '':
            continue
        users_list.append(user)

def honeypot():
    # cria vários arquivos honeypot na pasta corrente
    for x in range(1, 50):
        fname = os.path.join(os.getcwd(), f".porao{x}.txt")
        try:
            with open(fname, "w", encoding="utf-8") as file:
                file.write("arquivo feito para detectar o ransomware")
        except Exception:
            pass

def securing_files(folder):
    global users_list
    for user in users_list:
        try:
            subprocess.run(f'icacls "{folder}" /deny "{user}":R', shell=True)
        except Exception:
            pass

def destravar(folder):
    global users_list
    for user in users_list:
        try:
            subprocess.run(f'icacls "{folder}" /grant "{user}":R', shell=True)
        except Exception:
            pass

def shadow_copy():
    global last_shadow_backup
    global username
    now = time.time()
    try:
        if last_shadow_backup == 0:
            subprocess.run(f'xcopy "C:\\Users\\{username}\\Downloads" "{protected_backup}" /Y /E', shell=True)
            subprocess.run("wmic shadowcopy delete", shell=True)
            subprocess.run("wmic shadowcopy call create Volume='C:\\'", shell=True)
            last_shadow_backup = time.time()
            securing_files(protected_backup)
        elif now - last_shadow_backup >= 5400:  # 1h30
            subprocess.run("wmic shadowcopy delete", shell=True)
            subprocess.run("wmic shadowcopy call create Volume='C:\\'", shell=True)
            last_shadow_backup = time.time()
    except Exception:
        pass

def novos_processos():
    global ult_processos
    try:
        current_pids = []
        now = int(time.time())
        for process in psutil.process_iter(attrs=['pid', 'create_time']):
            try:
                processtime = abs(process.info['create_time'] - now)
                if processtime < 61:
                    if process.info['pid'] not in ult_processos:
                        ult_processos.append(process.info['pid'])
                else:
                    if process.info['pid'] in ult_processos:
                        ult_processos.remove(process.info['pid'])
                current_pids.append(process.info['pid'])
            except Exception:
                continue
    except Exception:
        pass

def quarantine_file(filepath):
    try:
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir, exist_ok=True)
        base = os.path.basename(filepath)
        dest = os.path.join(quarantine_dir, base)
        # mover arquivo para quarentena
        shutil.move(filepath, dest)
        # restringir acesso à pasta de quarentena (exige admin)
        try:
            subprocess.run(f'icacls "{quarantine_dir}" /inheritance:r', shell=True)
            subprocess.run(f'icacls "{quarantine_dir}" /grant:r "{username}":(F)', shell=True)
        except Exception:
            pass
        print(f"[Quarantine] {filepath} -> {dest}")
    except Exception as e:
        print(f"[Quarantine] erro ao quarentenar {filepath}: {e}")

def check_process_cmdlines_for_vss_delete():
    suspicious_cmds = [
        "vssadmin delete shadows", 
        "wbadmin delete", 
        "wbadmin stop backup", 
        "vssadmin.exe delete shadows", 
        "wmic shadowcopy delete"
    ]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = proc.info.get('name') or ""
            if name in WHITELIST_PROCS:
                continue
            cmdline = proc.info.get('cmdline') or []
            if not cmdline:
                continue
            cmd = " ".join(cmdline)
            for pattern in suspicious_cmds:
                if pattern.lower() in cmd.lower():
                    print(f"[ALERTA CMDLINE] processo {name} ({proc.info['pid']}) executou: {cmd}")
                    try:
                        proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                    return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def check_event_rate_and_respond():
    # calcula eventos no intervalo definido
    now = time.time()
    cutoff = now - EVENT_WINDOW_SECONDS
    # limpar timestamps antigos (deque retém maxlen; fazemos manualmente)
    while event_timestamps and event_timestamps[0] < cutoff:
        event_timestamps.popleft()
    if len(event_timestamps) > EVENTS_THRESHOLD:
        print(f"[RATE] Eventos {len(event_timestamps)} em {EVENT_WINDOW_SECONDS}s -> possível ransomware")
        try:
            encerrar_proctree()
            # tentar quarentenar arquivos exe/dll recentes (simples heurística)
            # iterate last N events stored in data_list
            for e in list(data_list[-100:]):
                try:
                    path = e[1]
                    if os.path.exists(path) and extrair_extensao(path):
                        quarantine_file(path)
                except Exception:
                    pass
        except Exception:
            pass
        # reset counters
        data_list.clear()
        event_timestamps.clear()
        return True
    return False

class MonitorFolder(FileSystemEventHandler):
    def on_any_event(self, event):
        global data_list, change_type
        # registra timestamp do evento
        event_timestamps.append(time.time())
        data_list.append((time.time(), event.src_path, event.event_type))
        # se honeypot tocado
        if "porao" in event.src_path:
            change_type[4] += 1
        # checa classificador
        if avaliar(change_type[0], change_type[1], change_type[2], change_type[3], change_type[4]):
            encerrar_proctree()

    def on_created(self, event):
        global change_type
        change_type[0] += 1
        event_timestamps.append(time.time())
        if "decrypt" in event.src_path.lower() or "restore" in event.src_path.lower() or "recover" in event.src_path.lower():
            print("Possível Ransomware detectado, arquivos de recuperação sendo criados.")
            try:
                encerrar_proctree()
            except:
                pass

    def on_deleted(self, event):
        global change_type
        change_type[3] += 1

    def on_modified(self, event):
        global change_type
        change_type[1] += 1

        if extrair_extensao(event.src_path):
            # Primeiro, rodamos o detector original (YARA + MalwareBazaar)
            try:
                DetectorMalware(event.src_path)
            except Exception as e:
                print(f"[DetectorMalware erro] {e}")

            # Detector heurístico MSIL/Gorf
            try:
                detect_and_respond_msil(event.src_path)
            except Exception as e:
                print(f"[MSIL/Gorf erro] {e}")

            # Detector heurístico Trojan:Win32/Vigorf.A
            try:
                check_vigorf(event.src_path)
            except Exception as e:
                print(f"[Vigorf.A erro] {e}")

    def on_moved(self, event):
        global change_type
        change_type[2] += 1

if __name__ == "__main__":
    # registra para iniciar com o windows (apenas se executado como admin)
    try:
        registry.AdicionarRegistro(script=os.path.realpath(__file__), name="PoraoRansomwareDetect")
    except Exception:
        pass
    start_protection()
    shadow_copy()
    honeypot()
    # proteger backup local
    securing_files(protected_backup)
    src_path = f"C:\\Users\\{username}\\Downloads"
    event_handler = MonitorFolder()
    observer = Observer()
    observer.schedule(event_handler, path=src_path, recursive=True)
    observer.start()
    threading.Thread(target=monitor_sysmon, daemon=True).start()
    try:
        while True:
            try:
                # checa se classificador indica ameaça
                if avaliar(change_type[0], change_type[1], change_type[2], change_type[3], change_type[4]):
                    encerrar_proctree()
                shadow_copy()
                novos_processos()
                # checa linhas de comando suspeitas (vssadmin, wbadmin, etc.)
                if check_process_cmdlines_for_vss_delete():
                    encerrar_proctree()
                # checa taxa de eventos (rápidas criações/modificações)
                check_event_rate_and_respond()
                # zera counters se inatividade
                if data_list:
                    time_since_last_change = abs(int(data_list[-1][0] - time.time()))
                    if time_since_last_change > 10 or sum(change_type) > 500:
                        data_list.clear()
                        change_type = [0, 0, 0, 0, 0]
                time.sleep(1)
            except Exception:
                # não deixa loop morrer
                pass
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
