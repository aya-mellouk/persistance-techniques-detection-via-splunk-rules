# T1543.003 – Create or Modify System Process: Windows Service
**Detection : sc.exe manipulating Windows services (create / config)**

| Champ | Valeur |
|---|---|
| Tactiques | Persistence, Privilege Escalation |
| Technique | T1543.003 |
| Source de la règle | Splunk ESCU – *Sc exe Manipulating Windows Services* |
| Data model | Endpoint.Processes |
| Sources de logs (lab) | Sysmon EID 1, Security 4688, System 7045 / Security 4697 |

---

## 1. Description

Les services Windows sont lancés par `services.exe` au démarrage, généralement avec les privilèges SYSTEM. Un attaquant qui crée un service (ou modifie le `binPath` d'un service existant) obtient :

- une **persistance** qui survit au redémarrage,
- une exécution en **SYSTEM** (élévation de privilèges),
- un camouflage : le binaire est lancé par `services.exe`, un comportement normal.

`sc.exe` est l'outil natif le plus simple pour cela, d'où une détection basée sur sa ligne de commande.

## 2. Attack Scenario

1. L'attaquant obtient des droits administrateur locaux.
2. Il dépose un payload (`C:\Users\Public\svc.exe`, `C:\Windows\Temp\...`).
3. Il crée le service : `sc.exe create <nom> binPath= "<payload>" start= auto`
4. Il le démarre (`sc.exe start <nom>`) ou attend le reboot.
5. Variante : détourner un service existant avec `sc.exe config <svc> binPath= "<payload>"`.
6. Variante latérale : `sc.exe \\<cible> create ...`.

### Simulation (Atomic Red Team)

```powershell
Invoke-AtomicTest T1543.003 -ShowDetailsBrief
Invoke-AtomicTest T1543.003 -ShowDetails
Invoke-AtomicTest T1543.003 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1543.003 -TestNumbers 1
Invoke-AtomicTest T1543.003 -TestNumbers 1 -Cleanup
```

Test principal : *Service Installation CMD*. Commande générée (à confirmer avec `-ShowDetails` dans ton lab) :

```
sc.exe create AtomicTestService_CMD binPath= "C:\AtomicRedTeam\atomics\T1543.003\bin\AtomicService.exe"
sc.exe start AtomicTestService_CMD
```

Autres tests de la technique à rejouer : version PowerShell (`New-Service`), modification de service existant, installation distante. Ils ne sont **pas** couverts par la règle ESCU de base (voir limites).

## 3. Attack Artifacts

| Artefact | Détail |
|---|---|
| Processus | `sc.exe` (parent : cmd.exe / powershell.exe) avec `create` ou `config` |
| Registre | `HKLM\SYSTEM\CurrentControlSet\Services\<nom>` (`ImagePath`, `Start`, `Type`, `ObjectName`) |
| Fichier | Binaire payload dans un chemin inhabituel |
| Journal System | **7045** – A service was installed in the system |
| Journal Security | **4697** (si Audit Security System Extension activé) |
| Processus fils | `services.exe` → payload au démarrage du service |

## 4. Telemetry

| Source | Event | Intérêt |
|---|---|---|
| Sysmon | EID 1 – Process Create | Image, OriginalFileName, CommandLine, ParentImage, User, Hashes |
| Sysmon | EID 13 – Registry value set | Modification de `...\Services\*\ImagePath` |
| Sysmon | EID 11 – File create | Dépôt du binaire |
| Security | 4688 (+ audit ligne de commande) | Alternative à Sysmon EID 1 |
| System | 7045 | Confirmation de l'installation du service |
| PowerShell | 4104 | `New-Service`, `Set-Service` |

Champs du data model utilisés par la règle ESCU : `process_name`, `process` (ligne de commande), `original_file_name`, `parent_process*`, `process_guid`, `process_integrity_level`, `user`, `dest`.

## 5. Detection Logic

### Logique de la règle ESCU

1. **`tstats` sur `Endpoint.Processes`** : recherche rapide sur le data model accéléré. `security_content_summariesonly` n'interroge que les données déjà résumées.
2. **Filtre** : `process_name = sc.exe` ET ligne de commande contenant ` create ` ou ` config `. Ce sont les deux sous-commandes qui permettent d'ajouter un service ou de changer son exécutable.
3. **`BY`** : regroupement sur tous les champs utiles à l'investigation (parent, hash, GUID, intégrité, utilisateur).
4. **Macros de mise en forme** : `drop_dm_object_name(Processes)` retire le préfixe `Processes.`, `security_content_ctime` rend `firstTime` / `lastTime` lisibles.
5. **Macro `sc_exe_manipulating_windows_services_filter`** : vide par défaut, sert à ajouter les exclusions (faux positifs).

### Limites

- Ne filtre que sur `process_name` : un `sc.exe` renommé passe, alors que `original_file_name` est déjà collecté mais pas utilisé.
- `config` seul est large : `sc config <svc> start= disabled` est courant et légitime. Le vrai signal est `binPath`.
- Ne couvre pas `New-Service`, `Set-Service`, `reg add` sur `Services`, ni l'API directe (les 7045 / Sysmon 13 comblent ce trou).
- Dépend d'ESCU (macros) et du data model accéléré.

### Règle pour ton lab (SPL autonome, Sysmon EID 1)

À adapter : `index` et `sourcetype`.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\sc.exe" OR OriginalFileName="sc.exe")
  (CommandLine="* create *" OR (CommandLine="* config *" AND CommandLine="*binpath*"))
| eval service_action=case(like(lower(CommandLine),"% create %"),"create", like(lower(CommandLine),"% config %"),"config_binpath")
| eval remote_target=if(match(CommandLine,"(?i)sc(\.exe)?\"?\s+\\\\\\\\"),"yes","no")
| eval suspicious_path=if(match(lower(CommandLine),"(\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\public\\\\|\\\\programdata\\\\|cmd(\.exe)?\s+/c|powershell|%comspec%)"),"yes","no")
| stats min(_time) as firstTime max(_time) as lastTime values(CommandLine) as command_line
        values(ParentImage) as parent_image values(User) as user values(Hashes) as hashes
        values(service_action) as action values(remote_target) as remote values(suspicious_path) as suspicious_path
        count by host ParentCommandLine Image ProcessGuid
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

Variante fidèle à l'ESCU (si les macros ESCU sont installées) : reprendre la requête d'origine et ajouter dans la macro `sc_exe_manipulating_windows_services_filter` les exclusions de ton environnement.

### Règle complémentaire : confirmation côté System (7045)

Détecte aussi `New-Service`, `sc` distant et tout autre moyen de créer un service.

```spl
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
| eval suspicious=if(match(lower(Service_File_Name),"(\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\public\\\\|\\\\programdata\\\\|cmd(\.exe)?\s+/c|powershell|%comspec%)"),"yes","no")
| table _time host Service_Name Service_File_Name Service_Type Service_Start_Type Service_Account suspicious
```

### Règle complémentaire : modification du registre (Sysmon 13)

```spl
index=sysmon EventCode=13 TargetObject="*\\CurrentControlSet\\Services\\*\\ImagePath"
| table _time host Image TargetObject Details User
```

## 6. Investigation

1. **Qui / d'où ?** `User`, `ParentImage`, `ParentCommandLine`. Un parent `cmd.exe` / `powershell.exe` / `wmiprvse.exe` / `psexesvc.exe` est plus suspect qu'un outil de déploiement connu.
2. **Quel binaire ?** Extraire le chemin de `binPath=`, vérifier l'emplacement, la signature, le hash (VirusTotal / base interne), les Sysmon EID 11 (création du fichier juste avant).
3. **Le service a-t-il démarré ?** Chercher `sc.exe start`, l'EID 7045 / 7036 et un processus fils de `services.exe` avec le même chemin.
4. **Compte d'exécution** : `LocalSystem` ou compte inhabituel ?
5. **Registre** : Sysmon 13 sur `...\Services\<nom>\ImagePath`.
6. **Contexte** : autres actions du même host/utilisateur dans les 15 minutes (dump de credentials, téléchargement, mouvement latéral).
7. **Distant ?** `sc \\hôte create` : investiguer aussi la machine cible (7045 + 4624 type 3).
8. **Remédiation** : isoler l'hôte, `sc stop` / `sc delete`, supprimer le binaire, chercher le même service / hash sur les autres machines.

## 7. False Positives

- Installeurs de logiciels et agents (EDR, VPN, backup, outils de monitoring) qui créent leurs services via `sc.exe`.
- Scripts de déploiement / GPO / SCCM / Intune.
- Administrateurs qui reconfigurent des services (`sc config ... start= demand`).
- Outils de dev et de lab (Docker, drivers de test).

**Réduction du bruit** : exclure par `ParentImage` + `user` + chemin de binaire signé et connu, via la macro de filtre ou une lookup `allowlist_sc_services.csv`. Garder `suspicious_path=yes` et `remote_target=yes` comme critères de priorité plutôt que d'exclure complètement.

## 8. Références

- MITRE ATT&CK T1543.003
- Atomic Red Team – `atomics/T1543/003` (Atomic Red Team repo)
- Splunk Security Content – *Sc exe Manipulating Windows Services*
