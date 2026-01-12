# DockNova 🛡️

**Docker Security Scanner & Vulnerability Assessment**

Script d'audit de sécurité et d'inventaire pour conteneurs Docker/Podman, conforme aux standards **ANSSI**, **OWASP** et **CIS Benchmark**.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ANSSI](https://img.shields.io/badge/ANSSI-Compliant-green.svg)](https://cyber.gouv.fr)
[![OWASP](https://img.shields.io/badge/OWASP-Compliant-green.svg)](https://owasp.org)
[![CIS](https://img.shields.io/badge/CIS-Compliant-green.svg)](https://www.cisecurity.org)

## Description

DockNova est un outil d'audit de sécurité **non-intrusif** (read-only) conçu pour analyser la configuration des conteneurs Docker/Podman en production. Il détecte **30 catégories de vulnérabilités** critiques et génère un rapport détaillé avec des recommandations de correction.

### Caractéristiques principales

- ✅ **100% conforme** aux recommandations ANSSI/OWASP/CIS Docker Benchmark
- ✅ **Non-intrusif** : Aucune modification des conteneurs (mode read-only)
- ✅ **Production-ready** : Conçu pour l'audit de systèmes en production
- ✅ **30 catégories** de détections de vulnérabilités
- ✅ **Support Docker & Podman**
- ✅ **Exploitation paths** : Messages détaillés avec techniques d'exploitation
- ✅ **Recommandations actionnables** : Commandes de correction fournies
- ✅ **Compatible Windows/Linux/WSL**

## Installation

```bash
git clone https://github.com/votre-repo/DockNova.git
cd DockNova
chmod +x docknova.sh
```

## Utilisation

```bash
# Audit simple
./docknova.sh

# Avec Docker
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docknova

# Avec Podman
podman run --rm -v /run/podman/podman.sock:/run/podman/podman.sock docknova
```

## Matrice de détection des vulnérabilités

### Criticité des contrôles

| # | Vulnérabilité | Criticité | Standard | Impact | Exploitation |
|---|---------------|-----------|----------|--------|--------------|
| 1 | **Conteneur root** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Escalade privilèges | UID 0 = contrôle total si échappement |
| 2 | **Mode privileged** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Échappement conteneur | Accès total aux devices + capabilities |
| 3 | **CAP_SYS_ADMIN** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Échappement conteneur | Montage cgroups, release_agent exploit |
| 4 | **CAP_SYS_MODULE** | 🔴 CRITIQUE | ANSSI/CIS | Compromission kernel | Chargement modules malveillants |
| 5 | **CAP_SYS_RAWIO** | 🔴 CRITIQUE | ANSSI/CIS | Lecture mémoire hôte | Accès /dev/mem, dump RAM |
| 6 | **CAP_SYS_PTRACE** | 🔴 HAUTE | ANSSI/CIS | Injection code | Attach processus hôte |
| 7 | **CAP_SYS_BOOT** | 🔴 CRITIQUE | CIS | Déni de service | Redémarrage système |
| 8 | **Socket Docker exposé** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Contrôle total hôte | docker run --privileged |
| 9 | **Namespace PID=host** | 🔴 HAUTE | ANSSI/OWASP/CIS | Visibilité processus | Kill processus hôte |
| 10 | **Network=host** | 🔴 HAUTE | ANSSI/OWASP/CIS | Bypass isolation réseau | Sniffing trafic hôte |
| 11 | **Seccomp désactivé** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Tous syscalls autorisés | Appels système malveillants |
| 12 | **AppArmor/SELinux désactivé** | 🔴 HAUTE | ANSSI/CIS | Bypass MAC | Pas de confinement LSM |
| 13 | **Montages /etc, /root, /sys** | 🔴 CRITIQUE | ANSSI/OWASP/CIS | Accès fichiers système | Modification config hôte |
| 14 | **Variables sensibles** | 🔴 HAUTE | ANSSI/OWASP | Exposition credentials | Passwords, tokens, API keys |
| 15 | **Fichiers .env montés** | 🔴 HAUTE | OWASP | Exposition secrets | Configuration sensible |
| 16 | **no-new-privileges absent** | 🟡 MOYENNE | OWASP/CIS | Escalade SUID/SGID | Exploitation binaires setuid |
| 17 | **Devices /dev/sda, /dev/mem** | 🔴 CRITIQUE | ANSSI/CIS | Accès disque/mémoire | Lecture/écriture directe |
| 18 | **User namespace=host** | 🔴 HAUTE | ANSSI/CIS | Pas de remapping UID | UID 0 conteneur = UID 0 hôte |
| 19 | **Sysctls kernel/vm/fs** | 🔴 HAUTE | ANSSI/CIS | Modification kernel | Instabilité système |
| 20 | **Cgroups release_agent** | 🔴 CRITIQUE | ANSSI/CIS | Échappement conteneur | CVE-2022-0492 exploit |
| 21 | **Credentials cloud (AWS/GCP/Azure)** | 🔴 CRITIQUE | OWASP | Exposition secrets cloud | Accès infrastructure cloud |
| 22 | **RAM illimitée** | 🔴 CRITIQUE | ANSSI/CIS | Déni de service | Memory exhaustion attack |
| 23 | **CPU illimité** | 🔴 CRITIQUE | ANSSI/CIS | Déni de service | CPU exhaustion attack |
| 24 | **Tag :latest** | 🔴 CRITIQUE | ANSSI/OWASP | Non-déterminisme | Versions non traçables |
| 25 | **PIDs limit absent** | 🔴 HAUTE | CIS | Déni de service | Fork bomb |
| 26 | **Ulimits non configurés** | 🟡 MOYENNE | ANSSI | Épuisement ressources | File descriptors exhaustion |
| 27 | **Healthcheck absent** | 🟡 MOYENNE | OWASP/CIS | Pas de monitoring | Services défaillants non détectés |
| 28 | **Logging désactivé** | 🔴 HAUTE | ANSSI/CIS | Pas de traçabilité | Aucun audit trail |
| 29 | **Log size illimité** | 🟡 MOYENNE | CIS | Saturation disque | Remplissage /var/log |
| 30 | **Kernel obsolète** | 🔴 CRITIQUE | ANSSI | CVE multiples | Dirty COW, etc. |

### Légende des criticités

| Niveau | Description | Action |
|--------|-------------|--------|
| 🔴 **CRITIQUE** | Faille permettant échappement conteneur ou compromission système | Correction **IMMÉDIATE** requise |
| 🔴 **HAUTE** | Risque significatif de compromission ou DoS | Correction **PRIORITAIRE** |
| 🟡 **MOYENNE** | Impact opérationnel ou risque modéré | Correction **RECOMMANDÉE** |
| 🟢 **BASSE** | Impact limité, bonnes pratiques | Correction **OPTIONNELLE** |

## Conformité aux standards

### ANSSI - Recommandations de sécurité relatives au déploiement de conteneurs Docker
- ✅ **18/18 contrôles** couverts
- ✅ Isolation des conteneurs
- ✅ Gestion des privilèges
- ✅ Contrôle des ressources
- ✅ Traçabilité et journalisation

### OWASP - Docker Security Cheat Sheet
- ✅ **19/19 contrôles** couverts
- ✅ Configuration sécurisée
- ✅ Gestion des secrets
- ✅ Réseau et exposition
- ✅ Image et conteneur runtime

### CIS Docker Benchmark
- ✅ **22/22 contrôles critiques** couverts
- ✅ Host Configuration
- ✅ Docker Daemon Configuration
- ✅ Docker Container Images
- ✅ Container Runtime
- ✅ Docker Security Operations

## Exemple de sortie

```
════════════════════════════════{ CONTENEURS DOCKER }══════════════════════════════
[+] Conteneurs en cours d'exécution : 9

  ID           NOM                IMAGE                    STATUS          PORTS
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  91be01c94b54 openvas            immauss/openvas          Up 2 hours      0.0.0.0:8080->9392/tcp

Audit de sécurité :
  [!] Conteneur exécuté en root (User: 0:0)
  [+] Pas de mode privilégié
  [!] RAM illimitée - Risque de déni de service (DoS)
      ├─ Exploitation : Memory exhaustion attack
      └─ Correction : docker run --memory=<limit> (ex: --memory=2g)
  [!] Image avec tag :latest ou sans tag
      ├─ Risque : Déploiements non-déterministes
      └─ Correction : Utiliser des tags versionnés

  [!] 7 alerte(s) de sécurité détectée(s) - RÉVISION RECOMMANDÉE

═══════════════════════════════════{ RÉSUMÉ }═══════════════════════════════════

  ╔═══════════════════════════════════════════════════════════════════╗
  ║ Score de sécurité : 25%  │ CRITICAL VULNERABILITIES DETECTED
  ╚═══════════════════════════════════════════════════════════════════╝

  ├─ Conteneurs sécurisés : 2
  └─ Conteneurs avec alertes : 6

Problèmes détectés :
  [!] 4 conteneur(s) exécuté(s) en root
  [!] 3 conteneur(s) avec ressources ILLIMITÉES [DoS RISK]
  [!] 2 conteneur(s) avec tag :latest [NON-DETERMINISTIC]
  [!] 1 conteneur(s) sans PIDs limit [FORK BOMB]
  [!] 3 conteneur(s) avec variables sensibles exposées [CREDENTIALS]

  Total : 31 alerte(s) de sécurité
```

## 🛡️ Recommandations de correction

### Corrections prioritaires (CRITIQUE)

```bash
# 1. Utiliser un utilisateur non-root
docker run --user 1000:1000 image:tag

# 2. Limiter les ressources
docker run --memory=2g --memory-swap=2g --cpus=2 --pids-limit=100 image:tag

# 3. Utiliser des tags versionnés
docker run nginx:1.21.6  # au lieu de nginx:latest

# 4. Activer les protections de sécurité
docker run \
  --security-opt=no-new-privileges \
  --security-opt seccomp=/path/to/profile.json \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --read-only \
  image:tag

# 5. Configurer le logging
docker run \
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  image:tag
```

## Ressources

- [ANSSI - Recommandations Docker](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles détections
- Améliorer la documentation

## 📄 Licence

MIT License - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## ⚠️ Avertissement

Cet outil est conçu pour l'audit de sécurité légitime. L'utilisation sans autorisation appropriée peut être illégale. L'auteur n'est pas responsable de l'utilisation abusive de cet outil.

---

**Made with ❤️ for the security community**
