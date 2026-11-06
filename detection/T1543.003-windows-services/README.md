# T1543.003 – Create or Modify System Process: Windows Service
**Detection : sc.exe manipulating Windows services (create / config)**

| Champ | Valeur |
|---|---|
| Technique | T1543.003 |
---

## 1. Description

Les services Windows sont lancés par `services.exe` au démarrage, généralement avec les privilèges SYSTEM. Un attaquant qui crée un service (ou modifie le `binPath` d'un service existant) obtient :

- une **persistance** qui survit au redémarrage,
- une élévation de privilèges,

`sc.exe` est l'outil natif le plus simple pour cela, d'où une détection basée sur sa ligne de commande.

## 2. Attack Scenario

1. L'attaquant obtient des droits administrateur locaux, Il dépose un payload (`C:\Users\Public\svc.exe`, `C:\Windows\Temp\...`) et puis  Il crée le service : `sc.exe create <nom> binPath= "<payload>" start= auto`, enfin Il le démarre (`sc.exe start <nom>`) ou attend le reboot.
Test  : Service Installation CMD
<img width="943" height="50" alt="image" src="https://github.com/user-attachments/assets/d6ebca77-25d9-4641-9ed3-dc730ffd6086" />
<img width="670" height="47" alt="image" src="https://github.com/user-attachments/assets/5302b9c1-4cf0-4400-84a6-a607000c473b" />




## 3. Attack Artifacts

| Artefact | Détail |
|---|---|
| Processus | `sc.exe` (parent : cmd.exe / powershell.exe) avec `create` ou `config` |
| Registre | `HKLM\SYSTEM\CurrentControlSet\Services\<nom>`  |
| Fichier | Binaire payload dans un chemin inhabituel |
| Journal System | **7045** : A service was installed in the system |
| Journal Security | **4697** (si Audit Security System Extension activé) |
| Processus fils | `services.exe` → payload au démarrage du service |

```

## 4. Investigation

1. **Qui / d'où ?** `User`, `ParentImage`, `ParentCommandLine`. Un parent `cmd.exe` / `powershell.exe` / `wmiprvse.exe` / `psexesvc.exe` est plus suspect qu'un outil de déploiement connu.
2. **Quel binaire ?** Extraire le chemin de `binPath=`, vérifier l'emplacement, la signature, le hash (VirusTotal / base interne), les Sysmon EID 11 (création du fichier juste avant).
3. **Le service a-t-il démarré ?** Chercher `sc.exe start`, l'EID 7045 / 7036 et un processus fils de `services.exe` avec le même chemin.
4. **Compte d'exécution** : `LocalSystem` ou compte inhabituel ?
5. **Registre** : Sysmon 13 sur `...\Services\<nom>\ImagePath`.
6. **Contexte** : autres actions du même host/utilisateur dans les 15 minutes (dump de credentials, téléchargement, mouvement latéral).
7. **Distant ?** `sc \\hôte create` : investiguer aussi la machine cible (7045 + 4624 type 3).
8. **Remédiation** : isoler l'hôte, `sc stop` / `sc delete`, supprimer le binaire, chercher le même service / hash sur les autres machines.

## 5. False Positives

- Installeurs de logiciels et agents (EDR, VPN, backup, outils de monitoring) qui créent leurs services via `sc.exe`.
- Administrateurs qui reconfigurent des services (`sc config ... start= demand`).
- Outils de dev et de lab (Docker, drivers de test).

**Réduction du bruit** : exclure par `ParentImage` + `user` + chemin de binaire signé et connu, via la macro de filtre ou une lookup


