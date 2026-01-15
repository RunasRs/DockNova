# DockNova 🛡️

**Docker Security Scanner & Vulnerability Assessment**

Script d'audit de sécurité et d'inventaire pour conteneurs Docker/Podman, conforme aux standards **ANSSI**, **OWASP**, **DOCKER**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ANSSI](https://img.shields.io/badge/ANSSI-Compliant-green.svg)](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker)
[![OWASP](https://img.shields.io/badge/OWASP-Compliant-green.svg)](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
[![OWASP](https://img.shields.io/badge/DOCKER-Compliant-green.svg)](https://docs.docker.com/engine/security/)

## Description

DockNova est un outil d'audit de sécurité **non-intrusif** (read-only) conçu pour analyser la configuration des conteneurs Docker/Podman en production. Il détecte **30 catégories de vulnérabilités** critiques et génère un rapport détaillé avec des recommandations de correction.

### Caractéristiques principales

- ✅ **100% conforme** aux recommandations ANSSI/OWASP/DOCKER
- ✅ **Non-intrusif** : Aucune modification des conteneurs (mode read-only)
- ✅ **Production-ready** : Conçu pour l'audit de systèmes en production
- ✅ **30 catégories** de détections de vulnérabilités
- ✅ **Support Docker & Podman**
- ✅ **Exploitation paths** : Messages détaillés avec techniques d'exploitation
- ✅ **Recommandations actionnables** : Commandes de correction fournies
- ✅ **Compatible Windows/Linux/WSL**

## Installation

```bash
git clone https://github.com/DockNova/DockNova.git
cd DockNova
chmod +x docknova.sh
```

## Utilisation

```bash
# Audit simple
./docknova.sh

# Avec WSL
wsl -d kali-linux -- bash -c "git clone https://github.com/RunasRs/DockNova.git && bash DockNova/docknova.sh"
```

## Matrice de détection des vulnérabilités

### Criticité des contrôles

| # | Vulnérabilité | Criticité | Impact | Exploitation |
|---|---------------|-----------|--------|--------------|
| 1 | **Conteneur root** | 🔴 CRITIQUE | Escalade privilèges | UID 0 = contrôle total si échappement |
| 2 | **Mode privileged** | 🔴 CRITIQUE | Échappement conteneur | Accès total aux devices + capabilities |
| 3 | **CAP_SYS_ADMIN** | 🔴 CRITIQUE | Échappement conteneur | Montage cgroups, release_agent exploit |
| 4 | **CAP_SYS_MODULE** | 🔴 CRITIQUE | Compromission kernel | Chargement modules malveillants |
| 5 | **CAP_SYS_RAWIO** | 🔴 CRITIQUE | Lecture mémoire hôte | Accès /dev/mem, dump RAM |
| 6 | **CAP_SYS_PTRACE** | 🟠 HAUTE | Injection code | Attach processus hôte |
| 7 | **CAP_SYS_BOOT** | 🔴 CRITIQUE | Déni de service | Redémarrage système |
| 8 | **Socket Docker exposé** | 🔴 CRITIQUE | Contrôle total hôte | docker run --privileged |
| 9 | **Namespace PID=host** | 🟠 HAUTE | Visibilité processus | Kill processus hôte |
| 10 | **Network=host** | 🟠 HAUTE | Bypass isolation réseau | Sniffing trafic hôte |
| 11 | **Seccomp désactivé** | 🔴 CRITIQUE | Tous syscalls autorisés | Appels système malveillants |
| 12 | **AppArmor/SELinux désactivé** | 🟠 HAUTE | Bypass MAC | Pas de confinement LSM |
| 13 | **Montages /etc, /root, /sys** | 🔴 CRITIQUE | Accès fichiers système | Modification config hôte |
| 14 | **Variables sensibles** | 🟠 HAUTE | Exposition credentials | Passwords, tokens, API keys |
| 15 | **Fichiers .env montés** | 🟠 HAUTE | Exposition secrets | Configuration sensible |
| 16 | **no-new-privileges absent** | 🟡 MOYENNE | Escalade SUID/SGID | Exploitation binaires setuid |
| 17 | **Devices /dev/sda, /dev/mem** | 🔴 CRITIQUE | Accès disque/mémoire | Lecture/écriture directe |
| 18 | **User namespace=host** | 🟠 HAUTE | Pas de remapping UID | UID 0 conteneur = UID 0 hôte |
| 19 | **Sysctls kernel/vm/fs** | 🟠 HAUTE | Modification kernel | Instabilité système |
| 20 | **Cgroups release_agent** | 🔴 CRITIQUE | Échappement conteneur | CVE-2022-0492 exploit |
| 21 | **Credentials cloud (AWS/GCP/Azure)** | 🔴 CRITIQUE | Exposition secrets cloud | Accès infrastructure cloud |
| 22 | **RAM illimitée** | 🟠 HAUTE | Déni de service | Memory exhaustion attack |
| 23 | **CPU illimité** | 🟠 HAUTE | Déni de service | CPU exhaustion attack |
| 24 | **Tag :latest** | 🟠 HAUTE | Non-déterminisme | Versions non traçables |
| 25 | **PIDs limit absent** | 🟠 HAUTE | Déni de service | Fork bomb |
| 26 | **Ulimits non configurés** | 🟡 MOYENNE | Épuisement ressources | File descriptors exhaustion |
| 27 | **Healthcheck absent** | 🟡 MOYENNE | Pas de monitoring | Services défaillants non détectés |
| 28 | **Logging désactivé** | 🟠 HAUTE | Pas de traçabilité | Aucun audit trail |
| 29 | **Log size illimité** | 🟡 MOYENNE | Saturation disque | Remplissage /var/log |
| 30 | **Kernel obsolète** | 🔴 CRITIQUE | CVE multiples | Dirty COW, etc. |

### Légende des criticités

| Niveau | Description | Action |
|--------|-------------|--------|
| 🔴 **CRITIQUE** | Faille permettant échappement conteneur ou compromission système | Correction **IMMÉDIATE** requise |
| 🟠 **HAUTE** | Risque significatif de compromission ou DoS | Correction **PRIORITAIRE** |
| 🟡 **MOYENNE** | Impact opérationnel ou risque modéré | Correction **RECOMMANDÉE** |




## Exemple de sortie

```
  ▶ ubuntu-proxy (7e4125670a58)

Audit de sécurité :
  [x] Conteneur exécuté en root (User non défini = root par défaut)
  [+] Pas de mode privilégié
  [i] Aucune capability supprimée (toutes les capabilities par défaut actives)
  [x] Socket Docker monté (risque accès ÉCRITURE)
      ├─ CRITIQUE : Escalade de privilèges & échapement de conteneur possible
      ├─ Le conteneur peut créer/modifier/supprimer des conteneurs sur l'hôte
      ├─ Permissions : srw-rw----
      ├─ Groupe : 994
      └─ Mode montage : RW=false
  [!] Docker CLI installé dans le conteneur
      ├─ Version : Docker version 28.3.3, build 980b85681696fbd95927fd8ded8f6d91bdca95b0
      └─ RISQUE CRITIQUE : Docker CLI + Socket = Contrôle total de l'hôte
  [i] Aucune option de sécurité supplémentaire (SELinux/AppArmor)
  [i] Système de fichiers racine en lecture/écriture
  [+] Aucun montage sensible détecté
  [!] Flag --security-opt=no-new-privileges non défini
  [i] User namespace par défaut (pas de remapping custom)
  [x] RAM illimitée - Risque de déni de service (DoS)
      ├─ Exploitation : Memory exhaustion attack
      └─ Correction : docker run --memory=<limit> (ex: --memory=2g)
  [x] CPU illimité - Risque de monopolisation CPU
      ├─ Exploitation : CPU exhaustion attack
      └─ Correction : docker run --cpus=<limit> (ex: --cpus=2)
  [!] Ulimits non configurés (utilise les valeurs par défaut de l'hôte)
      ├─ Risque : Épuisement des file descriptors/processus
      └─ Correction : docker run --ulimit nofile=1024:2048
  [!] Logs sans limite de taille (risque de saturation disque)
      └─ Correction : docker run --log-opt max-size=10m --log-opt max-file=3
  [i] Init process non activé (--init)
      └─ Les processus zombies ne seront pas gérés automatiquement

  [x] 7 alerte(s) de sécurité détectée(s) - RÉVISION RECOMMANDÉE



══════════════════════════════════════{ RÉSUMÉ }═══════════════════════════════════════

  ▶ Audit de Sécurité

  [+] Conteneurs analysés : 2
  ├─ Conteneurs sécurisés : 0
  └─ Conteneurs avec alertes : 2


  ▶ Problèmes détectés

  [x] 1 conteneur(s) exécuté(s) en root
  [x] 1 conteneur(s) en mode privilégié
  [x] 1 conteneur(s) avec accès au socket Docker [CRITIQUE]
  [x] 1 conteneur(s) avec variables sensibles exposées [CREDENTIALS]
  [!] 2 conteneur(s) sans flag no-new-privileges [SUID/SGID]
  [x] 1 conteneur(s) avec config risque cgroups [CONTAINER ESCAPE]
  [x] 2 conteneur(s) avec ressources ILLIMITÉES [DoS RISK]
  [x] 1 conteneur(s) avec tag :latest [NON-DETERMINISTIC]
  [!] 2 conteneur(s) sans ulimits configurés

  Total : 8 alerte(s) de sécurité


════════════════════════════{ RECOMMANDATIONS DE SÉCURITÉ }════════════════════════════

  [CRITIQUE] Vecteurs d'échappement de conteneur détectés :
      ├─ docker run --security-opt=no-new-privileges
      ├─ docker run --cap-drop=ALL --cap-add=<MINIMAL_CAPS>
      ├─ docker run --read-only (système de fichiers racine en lecture seule)
      └─ Éviter --privileged et le montage du socket Docker

  [HAUTE] Conteneurs exécutés en root :
      ├─ Ajouter 'USER <non-root>' dans le Dockerfile
      └─ docker run --user <uid>:<gid>

  [HAUTE] Ressources illimitées (DoS) :
      ├─ Risque de déni de service par épuisement RAM/CPU
      ├─ docker run --memory=2g --memory-swap=2g
      └─ docker run --cpus=2 --cpu-shares=1024

  [HAUTE] Tag :latest utilisé :
      ├─ Déploiements non reproductibles, versions non traçables
      ├─ Utiliser des tags versionnés spécifiques
      └─ Exemple : nginx:1.21.6 au lieu de nginx:latest

  [CRITIQUE] Configuration à risque pour manipulation cgroups :
      ├─ Risque d'échappement de conteneur via release_agent (CVE-2022-0492)
      ├─ Supprimer CAP_SYS_ADMIN : docker run --cap-drop=SYS_ADMIN
      ├─ Activer AppArmor/SELinux : docker run --security-opt apparmor=docker-default
      └─ Ne PAS utiliser --privileged

  [INFO] Ressources utiles :
      ├─ ANSSI - Recommandations Docker : https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker
      ├─ OWASP Docker Security : https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
      └─ Docker Security Best Practices : https://docs.docker.com/engine/security/

```


## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles détections
- Améliorer la documentation


## ⚠️ Avertissement

Cet outil est conçu pour l'audit de sécurité légitime. L'utilisation sans autorisation appropriée peut être illégale. L'auteur n'est pas responsable de l'utilisation abusive de cet outil.

---

**Made with ❤️ for the security community**
