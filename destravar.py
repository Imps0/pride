import regex as re
import subprocess
import os

username = os.getlogin()
users_list = []
get_users = subprocess.run("wmic useraccount get name", capture_output=True, shell=True)
users = get_users.stdout.decode()
users = re.split(r"\W|Name|\r|\n", users)
for user in list(users):
    user = user.strip()
    if user == '':
        pass
    else:
        users_list.append(user)


def destravar(folder):
    global users_list
    for user in users_list:
        try:
            subprocess.run(f'icacls "{folder}" /grant "{user}":R', shell=True)
        except Exception as e:
            print(f"[destravar] erro ao liberar {folder} para {user}: {e}")


if __name__ == "__main__":
    destravar(f"C:\\Users\\{username}\\Downloads\\protected_backup")
