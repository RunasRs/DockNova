#!/usr/bin/env bash

# =============================================================================
# DockNova - Inventaire Docker Professionnel
# Version: 2.0 (Inventaire uniquement)
# =============================================================================

# Hardening du script
set -uo pipefail  # Pas de -e car les fonctions check retournent 1 intentionnellement
IFS=$'\n\t'

# Gestion des signaux
trap 'echo -e "\n${LRED}[!] Script interrompu${NC}" >&2; exit 130' INT TERM

# =============================================================================
# CONFIGURATION ET CONSTANTES
# =============================================================================

# Couleurs (readonly pour éviter modification)
readonly RED='\033[0;31m'
readonly LRED='\033[1;31m'
readonly GREEN='\033[0;32m'
readonly LGREEN='\033[1;32m'
readonly YELLOW='\033[0;33m'
readonly LYELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly LBLUE='\033[1;34m'
readonly CYAN='\033[0;36m'
readonly LCYAN='\033[1;36m'
readonly MAGENTA='\033[0;35m'
readonly LMAGENTA='\033[1;35m'
readonly DGRAY='\033[1;30m'
readonly NC='\033[0m'

# Configuration
readonly VERSION="2.0"
readonly SCRIPT_NAME="DockNova Inventaire"

# Options de ligne de commande
VERBOSE=false
CI_MODE=false
FAIL_THRESHOLD=50  # Score minimum pour exit 0 en mode CI

# Pas de cache - utilisation directe de docker inspect --format (pas de dépendance)

# Statistiques globales
declare -A SECURITY_STATS=(
    [total_issues]=0
    [containers_with_root]=0
    [containers_privileged]=0
    [containers_with_docker_socket]=0
    [containers_with_host_pid]=0
    [containers_with_host_network]=0
    [containers_with_sensitive_mounts]=0
    [containers_with_sensitive_vars]=0
    [containers_secure]=0
    [containers_with_dangerous_caps]=0
    [containers_without_no_new_privs]=0
    [containers_with_dangerous_devices]=0
    [containers_with_cgroup_access]=0
    [containers_with_cloud_creds]=0
    [containers_with_seccomp_disabled]=0
    [containers_with_unlimited_resources]=0
    [containers_with_latest_tag]=0
    [containers_without_pids_limit]=0
    [containers_without_ulimits]=0
    [containers_without_healthcheck]=0
    [containers_with_no_logging]=0
    [containers_with_vulnerable_kernel]=0
)

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

# Logging amélioré
log_debug() {
    [[ "$VERBOSE" == "true" ]] && echo -e "${DGRAY}[DEBUG]${NC} $*" >&2
}

log_info() {
    echo -e "${LBLUE}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${LYELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${LRED}[ERROR]${NC} $*" >&2
}

log_success() {
    echo -e "${LGREEN}[OK]${NC} $*"
}

# Affichage de l'aide
show_help() {
    cat << EOF
${LGREEN}${SCRIPT_NAME}${NC} v${VERSION} - Inventaire Docker Professionnel

${LBLUE}USAGE:${NC}
    $(basename "$0") [OPTIONS]

${LBLUE}OPTIONS:${NC}
    -h, --help              Afficher cette aide
    -v, --verbose           Mode verbeux avec debug
    -c, --ci                Mode CI/CD (exit code basé sur le score)
    -t, --threshold SCORE   Score minimum en mode CI (défaut: 50)
    --no-color              Désactiver les couleurs

${LBLUE}EXEMPLES:${NC}
    $(basename "$0")                          # Audit standard
    $(basename "$0") -v                       # Mode verbeux
    $(basename "$0") -c -t 80                 # Mode CI avec seuil 80%

${LBLUE}RÉFÉRENCES:${NC}
    - CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
    - ANSSI Docker: https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

${LBLUE}NOTE:${NC}
    - Aucune dépendance externe requise (pas de jq, pas de parallel)
    - Utilise uniquement Bash et Docker/Podman standards

EOF
}

# =============================================================================
# DÉTECTION ET VALIDATION
# =============================================================================

# Variable globale pour la commande Docker/Podman
DOCKER_CMD=""

detect_container_engine() {
    if command -v docker &> /dev/null && docker info &> /dev/null 2>&1; then
        DOCKER_CMD="docker"
        log_debug "Docker détecté et accessible"
        return 0
    fi
    
    if command -v podman &> /dev/null && podman info &> /dev/null 2>&1; then
        DOCKER_CMD="podman"
        log_debug "Podman détecté et accessible"
        return 0
    fi
    
    log_error "Docker ou Podman n'est pas accessible"
    log_error "Vérifiez que le service est démarré et que vous avez les permissions"
    return 1
}

# Validation d'un ID de conteneur (sécurité contre injection)
validate_container_id() {
    local cid="$1"
    if [[ ! "$cid" =~ ^[a-f0-9]{12,64}$ ]]; then
        log_error "ID de conteneur invalide: $cid"
        return 1
    fi
    return 0
}

# =============================================================================
# EXTRACTION DE DONNÉES
# =============================================================================

# Extraction de champ avec docker inspect --format (pas de dépendance jq)
get_container_field() {
    local cid="$1"
    local format="$2"
    "$DOCKER_CMD" inspect --format="$format" "$cid" 2>/dev/null || echo ""
}

# =============================================================================
# FONCTIONS D'AFFICHAGE
# =============================================================================

truncate_text() {
    local text="$1"
    local max_len="${2:-50}"
    if [[ ${#text} -gt $max_len ]]; then
        echo "${text:0:$((max_len-3))}..."
    else
        echo "$text"
    fi
}

print_section() {
    local title="$1"
    local total_width=120
    local title_length=${#title}
    local lines_space=$((total_width - title_length - 4))
    local left_width=$((lines_space / 2))
    local right_width=$((lines_space - left_width))
    
    local left_line=$(printf '═%.0s' $(seq 1 "$left_width"))
    local right_line=$(printf '═%.0s' $(seq 1 "$right_width"))
    
    echo ""
    echo -e "${LBLUE}${left_line}{ ${LGREEN}$title${NC} ${LBLUE}}${right_line}${NC}"
}

print_subsection() {
    local subtitle="$1"
    echo ""
    echo -e "  ${LCYAN}┌──────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${LCYAN}│${NC} ${LBLUE}$subtitle${NC}"
    echo -e "  ${LCYAN}└──────────────────────────────────────────────────────────────────────┘${NC}"
}

# =============================================================================
# DÉTECTION DE DONNÉES SENSIBLES
# =============================================================================

detect_sensitive_data() {
    local text="$1"
    local found_secrets=()
    
    # Patterns pour secrets (amélioration avec regex plus strictes)
    local patterns=(
        '(password|passwd|pwd|pass|secret|token|api[_-]?key|auth|credential|private[_-]?key)='
        'AWS_SECRET_ACCESS_KEY='
        'GITHUB_TOKEN='
        'SLACK_TOKEN='
        'DATABASE_URL='
    )
    
    for pattern in "${patterns[@]}"; do
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "$pattern"; then
                found_secrets+=("$line")
            fi
        done <<< "$text"
    done
    
    if [[ ${#found_secrets[@]} -gt 0 ]]; then
        printf '%s\n' "${found_secrets[@]}"
        return 0
    fi
    return 1
}

# =============================================================================
# FONCTION DE VÉRIFICATION DE SÉCURITÉ COMPLÈTE (DÉSACTIVÉE DANS INVENTAIRE)
# =============================================================================

# Fonction désactivée - voir docknova_securite.sh pour l'audit de sécurité
check_security() {
    return 0
    local cid="$1"
    local name="$2"
    local warnings=0
    
    # Récupération des informations de sécurité
    local user=$(get_container_field "$cid" '{{.Config.User}}')
    local privileged=$(get_container_field "$cid" '{{.HostConfig.Privileged}}')
    local cap_add=$(get_container_field "$cid" '{{.HostConfig.CapAdd}}')
    local cap_drop=$(get_container_field "$cid" '{{.HostConfig.CapDrop}}')
    local volumes=$(get_container_field "$cid" '{{json .Mounts}}')
    local readonly_rootfs=$(get_container_field "$cid" '{{.HostConfig.ReadonlyRootfs}}')
    local pid_mode=$(get_container_field "$cid" '{{.HostConfig.PidMode}}')
    local ipc_mode=$(get_container_field "$cid" '{{.HostConfig.IpcMode}}')
    local network_mode=$(get_container_field "$cid" '{{.HostConfig.NetworkMode}}')
    local security_opt=$(get_container_field "$cid" '{{.HostConfig.SecurityOpt}}')
    
    echo "Audit de sécurité :"
    
    # 1. Utilisateur
    local uid_only="${user%%:*}"
    if [[ -z "$user" || "$uid_only" == "0" || "$user" == "root" || "$user" == "0:0" ]]; then
        if [[ -n "$user" ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Conteneur exécuté en root (User: $user)${NC}"
        else
            echo -e "  ${LRED}[!]${NC} ${LRED}Conteneur exécuté en root (User non défini = root par défaut)${NC}"
        fi
        ((warnings++))
    else
        echo -e "  ${LGREEN}[+]${NC} Utilisateur non-root : $user (UID: $uid_only)"
    fi
    
    # 2. Mode privilégié
    if [[ "$privileged" == "true" ]]; then
        echo -e "  ${LRED}[!]${NC} Conteneur en mode privilégié"
        ((warnings++))
    else
        echo -e "  ${LGREEN}[+]${NC} Pas de mode privilégié"
    fi
    
    # 3. Capabilities - Détection avancée
    local dangerous_caps_found=false
    if [[ "$cap_add" != "[]" && "$cap_add" != "<no value>" && "$cap_add" != "null" ]]; then
        if echo "$cap_add" | grep -qiE "SYS_ADMIN|ALL"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Capability SYS_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Montage de cgroups, accès /dev, échappement de conteneur${NC}"
            echo -e "      ${DGRAY}├─${NC} Permet de monter des systèmes de fichiers arbitraires"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount -t cgroup -o rdma cgroup /tmp/cg && echo > /tmp/cg/release_agent${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_PTRACE"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_PTRACE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Injection de code dans les processus de l'hôte${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet d'utiliser ptrace() pour attacher et modifier des processus${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_MODULE"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Capability SYS_MODULE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Chargement de modules kernel malveillants${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : insmod /tmp/rootkit.ko${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_RAWIO"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_RAWIO ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Accès direct à la mémoire physique et I/O${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet d'accéder à /dev/mem et /dev/kmem pour lire la RAM de l'hôte${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "DAC_OVERRIDE|DAC_READ_SEARCH"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability DAC_OVERRIDE/DAC_READ_SEARCH ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Bypass des permissions de fichiers"
            echo -e "      ${DGRAY}└─${NC} Permet de lire/écrire des fichiers sans vérification des permissions"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "NET_ADMIN"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability NET_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Configuration réseau, sniffing, spoofing"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet de créer des interfaces réseau, modifier les routes, iptables${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "NET_RAW"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability NET_RAW ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Création de paquets réseau raw (ARP spoofing, MitM)"
            echo -e "      ${DGRAY}└─${NC} Permet d'utiliser des raw sockets pour le sniffing et le spoofing"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_BOOT"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_BOOT ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Redémarrage du système hôte${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : reboot ou shutdown -r now${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_TIME"; then
            echo -e "  ${YELLOW}[!]${NC} Capability SYS_TIME ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Modification de l'horloge système"
            echo -e "      ${DGRAY}└─${NC} Peut affecter les certificats, logs, et synchronisation"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_CHROOT"; then
            echo -e "  ${YELLOW}[!]${NC} Capability SYS_CHROOT ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Échappement via chroot"
            echo -e "      ${DGRAY}└─${NC} Combiné avec d'autres caps, peut faciliter l'échappement"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "MKNOD"; then
            echo -e "  ${YELLOW}[!]${NC} Capability MKNOD ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Création de périphériques bloc/caractères"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mknod /tmp/sda b 8 0${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        
        if [[ "$dangerous_caps_found" == "false" ]]; then
            echo -e "  ${YELLOW}[!]${NC} Capabilities ajoutées : $cap_add"
            ((warnings++))
        fi
    fi
    
    if [[ "$cap_drop" != "[]" && "$cap_drop" != "<no value>" && "$cap_drop" != "null" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Capabilities supprimées : $cap_drop"
    else
        echo -e "  ${LBLUE}[i]${NC} Aucune capability supprimée (toutes les capabilities par défaut actives)"
    fi
    
    # 4. Socket Docker/Podman - Détection avancée et complète
    local docker_socket_found=false
    local socket_mode=""
    
    # 4.1. Vérifier si le socket Docker est monté comme volume
    if echo "$volumes" | grep -q "/var/run/docker.sock"; then
        socket_mode=$(get_container_field "$cid" '{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.RW}}{{end}}{{end}}')
        
        local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        local socket_group=$($DOCKER_CMD exec "$cid" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$4}'" 2>/dev/null)
        
        if [[ "$socket_mode" == "true" ]] || echo "$socket_perms" | grep -q "rw"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Socket Docker monté (risque accès ÉCRITURE)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Escalade de privilèges & échapement de conteneur possible${NC}"
            echo -e "      ${DGRAY}├─${NC} Le conteneur peut créer/modifier/supprimer des conteneurs sur l'hôte"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            [[ -n "$socket_group" ]] && echo -e "      ${DGRAY}├─${NC} Groupe : ${LBLUE}$socket_group${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LYELLOW}RW=$socket_mode${NC}"
            ((warnings++))
        else
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Socket Docker monté (configuration read-only)${NC}"
            echo -e "      ${DGRAY}├─${NC} Accès limité mais peut lire les informations Docker"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            ((warnings++))
        fi
        docker_socket_found=true
    fi
    
    # 4.2. Vérifier le socket Podman
    if echo "$volumes" | grep -q "/run/podman/podman.sock"; then
        socket_mode=$(get_container_field "$cid" '{{range .Mounts}}{{if eq .Destination "/run/podman/podman.sock"}}{{.RW}}{{end}}{{end}}')
        
        local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l /run/podman/podman.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        
        if [[ "$socket_mode" == "true" ]] || echo "$socket_perms" | grep -q "rw"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Socket Podman monté (risque accès ÉCRITURE)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Contrôle total du moteur Podman${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LYELLOW}RW=$socket_mode${NC}"
            ((warnings++))
        else
            echo -e "  ${YELLOW}[!]${NC} Socket Podman monté (configuration read-only)"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            ((warnings++))
        fi
        docker_socket_found=true
    fi
    
    # 4.3. Vérifier si d'autres répertoires Docker sont montés
    if echo "$volumes" | grep -q "/var/lib/docker"; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire Docker monté (/var/lib/docker)${NC}"
        echo -e "      ${DGRAY}├─${NC} Accès direct aux données Docker (images, volumes, conteneurs)"
        echo -e "      ${DGRAY}└─${NC} ${LRED}Possibilité de manipulation des données Docker${NC}"
        ((warnings++))
        docker_socket_found=true
    fi
    
    # 4.4. Détecter les variables d'environnement Docker exposées
    local docker_host_var=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}' | grep "DOCKER_HOST=" || echo "")
    if [[ -n "$docker_host_var" ]]; then
        echo -e "  ${LRED}[!]${NC} Variable DOCKER_HOST détectée : ${LYELLOW}$docker_host_var${NC}"
        echo -e "      ${DGRAY}└─${NC} Accès potentiel à un daemon Docker distant"
        ((warnings++))
        docker_socket_found=true
    fi
    
    # 4.5. Vérifier si le conteneur peut accéder au socket depuis l'intérieur (cas où le montage n'a pas été détecté)
    if $DOCKER_CMD exec "$cid" sh -c "test -S /var/run/docker.sock" 2>/dev/null; then
        if [[ "$docker_socket_found" == "false" ]]; then
            local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            if echo "$socket_perms" | grep -q "rw"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}Socket Docker accessible DANS le conteneur (permissions écriture)${NC}"
                echo -e "      ${DGRAY}├─${NC} Le socket est présent (bind mount non détecté ou copié)"
                [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            else
                echo -e "  ${YELLOW}[!]${NC} Socket Docker accessible DANS le conteneur"
                echo -e "      ${DGRAY}├─${NC} Le socket est présent (bind mount non détecté ou copié)"
                [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            fi
            ((warnings++))
            docker_socket_found=true
        fi
    fi
    
    # 4.6. Vérifier si Docker CLI est installé dans le conteneur
    if $DOCKER_CMD exec "$cid" sh -c "command -v docker" &>/dev/null; then
        local docker_version=$($DOCKER_CMD exec "$cid" sh -c "docker --version 2>/dev/null" || echo "Version inconnue")
        echo -e "  ${YELLOW}[!]${NC} Docker CLI installé dans le conteneur"
        echo -e "      ${DGRAY}├─${NC} Version : ${LBLUE}$docker_version${NC}"
        if [[ "$docker_socket_found" == "true" ]]; then
            echo -e "      ${DGRAY}└─${NC} ${LRED}RISQUE CRITIQUE : Docker CLI + Socket = Contrôle total de l'hôte${NC}"
        else
            echo -e "      ${DGRAY}└─${NC} CLI présent mais aucun socket détecté"
        fi
    fi
    
    # 4.7. Vérifier si Podman CLI est installé
    if $DOCKER_CMD exec "$cid" sh -c "command -v podman" &>/dev/null; then
        local podman_version=$($DOCKER_CMD exec "$cid" sh -c "podman --version 2>/dev/null" || echo "Version inconnue")
        echo -e "  ${YELLOW}[!]${NC} Podman CLI installé dans le conteneur"
        echo -e "      ${DGRAY}└─${NC} Version : ${LBLUE}$podman_version${NC}"
    fi
    
    if [[ "$docker_socket_found" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun accès au socket Docker/Podman détecté"
    fi
    
    # 5. Namespace PID
    if [[ "$pid_mode" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} Namespace PID partagé avec l'hôte (--pid=host)"
        ((warnings++))
    fi
    
    # 6. Namespace IPC
    if [[ "$ipc_mode" == "host" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Namespace IPC partagé avec l'hôte (--ipc=host)"
        ((warnings++))
    fi
    
    # 7. Mode réseau
    if [[ "$network_mode" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} Mode réseau host (--network=host)"
        ((warnings++))
    fi
    
    # 8. SELinux / AppArmor
    if [[ "$security_opt" == "[]" || "$security_opt" == "<no value>" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucune option de sécurité supplémentaire (SELinux/AppArmor)"
    else
        if echo "$security_opt" | grep -q "seccomp=unconfined"; then
            echo -e "  ${LRED}[!]${NC} Seccomp désactivé - Tous les syscalls autorisés"
            ((warnings++))
        fi
        if echo "$security_opt" | grep -q "apparmor=unconfined"; then
            echo -e "  ${LRED}[!]${NC} AppArmor désactivé"
            ((warnings++))
        fi
        if echo "$security_opt" | grep -q "label=disable"; then
            echo -e "  ${LRED}[!]${NC} SELinux désactivé"
            ((warnings++))
        fi
    fi
    
    # 9. Système de fichiers racine
    if [[ "$readonly_rootfs" == "true" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Système de fichiers racine en lecture seule"
    else
        echo -e "  ${LBLUE}[i]${NC} Système de fichiers racine en lecture/écriture"
    fi
    
    # 10. Montages sensibles
    local has_sensitive_mount=false
    if echo "$volumes" | grep -qE "/(etc|root|home|boot|dev|sys|proc)\""; then
        echo -e "  ${LRED}[!]${NC} Répertoires système sensibles montés depuis l'hôte"
        ((warnings++))
        has_sensitive_mount=true
    fi
    
    if echo "$volumes" | grep -qE "\.env\"|\.env\.|/\.env\""; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Fichier .env monté - Risque d'exposition de secrets${NC}"
        ((warnings++))
        has_sensitive_mount=true
    fi
    
    if [[ "$has_sensitive_mount" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun montage sensible détecté"
    fi
    
    # 11. Variables sensibles exposées
    local sensitive_count=0
    local all_env=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}')
    local all_labels=$(get_container_field "$cid" '{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}')
    
    local sensitive_env=$(detect_sensitive_data "$all_env")
    if [[ -n "$sensitive_env" ]]; then
        local env_count=$(echo "$sensitive_env" | wc -l)
        echo -e "  ${LRED}[!]${NC} ${LRED}$env_count variable(s) d'environnement sensible(s) détectée(s)${NC}"
        ((warnings++))
        ((sensitive_count += env_count))
    fi
    
    local sensitive_labels=$(detect_sensitive_data "$all_labels")
    if [[ -n "$sensitive_labels" ]]; then
        local label_count=$(echo "$sensitive_labels" | wc -l)
        echo -e "  ${YELLOW}[!]${NC} $label_count label(s) avec informations sensibles détecté(s)"
        ((warnings++))
        ((sensitive_count += label_count))
    fi
    
    if [[ $sensitive_count -gt 0 ]]; then
        echo -e "  ${DGRAY}└─${NC} ${LRED}Total : $sensitive_count donnée(s) sensible(s) exposée(s)${NC}"
    fi
    
    # 12. Flag no-new-privileges
    local no_new_privs=$(echo "$security_opt" | grep -o "no-new-privileges:true" || echo "")
    if [[ -z "$no_new_privs" ]]; then
        echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Flag --security-opt=no-new-privileges non défini${NC}"
        ((warnings++))
    else
        echo -e "  ${LGREEN}[+]${NC} Flag no-new-privileges activé (protection SUID/SGID)"
    fi
    
    # 13. Devices exposés (/dev)
    local devices=$(get_container_field "$cid" '{{range .HostConfig.Devices}}{{.PathOnHost}}{{println}}{{end}}')
    if [[ -n "$devices" ]] && [[ "$devices" != "<no value>" ]]; then
        local critical_device=false
        while IFS= read -r device; do
            [[ -z "$device" ]] && continue
            
            if echo "$device" | grep -qE "/dev/(sd|hd|nvme|vd|xvd)"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Périphérique de disque exposé : $device${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Accès direct au système de fichiers de l'hôte${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount $device /mnt && chroot /mnt${NC}"
                ((warnings++))
                critical_device=true
            elif echo "$device" | grep -qE "/dev/kmsg|/dev/mem|/dev/kmem"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Device de mémoire kernel exposé : $device${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Lecture/écriture de la mémoire kernel${NC}"
                echo -e "      ${DGRAY}└─${NC} Permet de dumper des secrets, modifier le kernel en live"
                ((warnings++))
                critical_device=true
            elif echo "$device" | grep -qE "/dev/tty|/dev/console"; then
                echo -e "  ${YELLOW}[!]${NC} Device TTY/Console exposé : $device"
                echo -e "      ${DGRAY}└─${NC} Peut permettre de capturer ou injecter des entrées clavier"
                ((warnings++))
                critical_device=true
            elif [[ "$device" == "/dev/fuse" ]]; then
                echo -e "  ${YELLOW}[!]${NC} Device FUSE exposé : $device"
                echo -e "      ${DGRAY}└─${NC} Permet de créer des systèmes de fichiers en userspace"
                ((warnings++))
                critical_device=true
            fi
        done <<< "$devices"
        
        if [[ "$critical_device" == "false" ]]; then
            echo -e "  ${LBLUE}[i]${NC} Devices exposés (non critiques) : $(echo "$devices" | tr '\n' ' ')"
        fi
    fi
    
    # 14. User namespace (remapping des UIDs)
    local user_ns=$(get_container_field "$cid" '{{.HostConfig.UsernsMode}}')
    if [[ "$user_ns" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}User namespace désactivé (--userns=host)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}UID 0 dans le conteneur = UID 0 sur l'hôte${NC}"
        echo -e "      ${DGRAY}└─${NC} Pas de remapping des UIDs, risque d'escalade si évasion"
        ((warnings++))
    elif [[ -z "$user_ns" || "$user_ns" == "<no value>" ]]; then
        echo -e "  ${LBLUE}[i]${NC} User namespace par défaut (pas de remapping custom)"
    fi
    
    # 15. Sysctls dangereux
    local sysctls=$(get_container_field "$cid" '{{range $key, $value := .HostConfig.Sysctls}}{{$key}}={{$value}}{{println}}{{end}}')
    if [[ -n "$sysctls" ]]; then
        local dangerous_sysctl=false
        while IFS= read -r sysctl; do
            [[ -z "$sysctl" ]] && continue
            
            if echo "$sysctl" | grep -qiE "kernel\.|vm\.|fs\."; then
                echo -e "  ${LRED}[!]${NC} ${LRED}SYSCTL DANGEREUX : $sysctl${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Modification de paramètres kernel/VM depuis le conteneur${NC}"
                echo -e "      ${DGRAY}└─${NC} Peut affecter la stabilité et sécurité de l'hôte"
                ((warnings++))
                dangerous_sysctl=true
            elif echo "$sysctl" | grep -qiE "net\.ipv4\.ip_forward|net\.ipv4\.conf\.all\.forwarding"; then
                echo -e "  ${YELLOW}[!]${NC} SYSCTL réseau modifié : $sysctl"
                echo -e "      ${DGRAY}└─${NC} Permet le routage IP (peut être légitime pour un proxy/router)"
                ((warnings++))
                dangerous_sysctl=true
            fi
        done <<< "$sysctls"
        
        if [[ "$dangerous_sysctl" == "false" ]]; then
            echo -e "  ${LBLUE}[i]${NC} Sysctls configurés : $(echo "$sysctls" | tr '\n' ' ')"
        fi
    fi
    
    # 16. Risque d'accès aux cgroups (vecteur d'échappement via release_agent)
    local cgroup_risk=false
    local cgroup_reasons=()
    
    if [[ "$privileged" == "true" ]]; then
        cgroup_risk=true
        cgroup_reasons+=("Mode privilégié activé")
    fi
    
    if echo "$cap_add" | grep -qiE "SYS_ADMIN|ALL"; then
        cgroup_risk=true
        cgroup_reasons+=("Capability CAP_SYS_ADMIN détectée")
    fi
    
    if echo "$volumes" | grep -q '"/sys/fs/cgroup"' && echo "$volumes" | grep -q '"RW":true'; then
        cgroup_risk=true
        cgroup_reasons+=("Montage /sys/fs/cgroup en read-write")
    fi
    
    if [[ "$cgroup_risk" == "true" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Configuration permettant la manipulation des cgroups${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Risque : Échappement de conteneur via release_agent (CVE-2022-0492)${NC}"
        for reason in "${cgroup_reasons[@]}"; do
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Raison : $reason${NC}"
        done
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}PoC : https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/${NC}"
        ((warnings++))
    fi
    
    # 17. Kernel vulnérable
    local kernel_version=$($DOCKER_CMD info 2>/dev/null | grep "Kernel Version" | cut -d: -f2 | xargs)
    if [[ -n "$kernel_version" ]]; then
        local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
        local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
        if [[ "$kernel_major" -lt 4 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Kernel hôte OBSOLÈTE : $kernel_version${NC}"
            echo -e "      ${DGRAY}└─${NC} Mise à jour du kernel de l'hôte Docker fortement recommandée"
            ((warnings++))
        elif [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -lt 15 ]]; then
            echo -e "  ${YELLOW}[!]${NC} Kernel hôte potentiellement vulnérable : $kernel_version"
            echo -e "      ${DGRAY}└─${NC} Vérifier les CVE associées à cette version"
            ((warnings++))
        fi
    fi
    
    # 18. Détection de l'exposition de secrets dans l'historique des layers
    local image=$(get_container_field "$cid" '{{.Image}}')
    local layer_count=$(get_container_field "$image" '{{range .RootFS.Layers}}{{println}}{{end}}' 2>/dev/null | wc -l)
    if [[ $layer_count -gt 30 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Image avec $layer_count layers (risque de secrets dans l'historique)"
        echo -e "      ${DGRAY}└─${NC} Vérifier avec : docker history $image | grep -E 'ENV|COPY|ADD'"
    fi
    
    # 19. Credentials cloud
    if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.aws" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire AWS CLI détecté (/root/.aws)${NC}"
        ((warnings++))
    fi
    if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.config/gcloud" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire GCP CLI détecté (/root/.config/gcloud)${NC}"
        ((warnings++))
    fi
    if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.azure" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire Azure CLI détecté (/root/.azure)${NC}"
        ((warnings++))
    fi
    
    # 20. Limites de ressources (ANSSI/CIS - CRITIQUE pour prévenir DoS)
    local mem_limit=$(get_container_field "$cid" '{{.HostConfig.Memory}}')
    local cpu_quota=$(get_container_field "$cid" '{{.HostConfig.CpuQuota}}')
    local cpu_shares=$(get_container_field "$cid" '{{.HostConfig.CpuShares}}')
    
    local resource_unlimited=false
    if [[ "$mem_limit" == "0" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}RAM illimitée - Risque de déni de service (DoS)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Memory exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --memory=<limit> (ex: --memory=2g)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    if [[ "$cpu_quota" == "-1" ]] || [[ "$cpu_quota" == "0" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}CPU illimité - Risque de monopolisation CPU${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : CPU exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --cpus=<limit> (ex: --cpus=2)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    # 21. Tag :latest (ANSSI/OWASP - CRITIQUE pour reproductibilité)
    local image_full=$(get_container_field "$cid" '{{.Config.Image}}')
    if echo "$image_full" | grep -qE ':latest$|^[^:]+$'; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Image avec tag :latest ou sans tag${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Risque : Déploiements non-déterministes, versions non traçables${NC}"
        echo -e "      ${DGRAY}├─${NC} Image : ${LYELLOW}$image_full${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser des tags versionnés (ex: nginx:1.21.6)${NC}"
        ((warnings++))
    fi
    
    # 22. PIDs limit (CIS - HAUTE pour prévenir fork bomb)
    local pids_limit=$(get_container_field "$cid" '{{.HostConfig.PidsLimit}}')
    if [[ "$pids_limit" == "0" ]] || [[ "$pids_limit" == "-1" ]] || [[ -z "$pids_limit" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}PIDs limit non défini - Risque de fork bomb${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : :(){ :|:& };: (fork bomb)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --pids-limit=100${NC}"
        ((warnings++))
    fi
    
    # 23. Ulimits (ANSSI - MOYENNE)
    local ulimits=$(get_container_field "$cid" '{{.HostConfig.Ulimits}}')
    if [[ "$ulimits" == "[]" ]] || [[ "$ulimits" == "<no value>" ]] || [[ -z "$ulimits" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Ulimits non configurés (utilise les valeurs par défaut de l'hôte)"
        echo -e "      ${DGRAY}├─${NC} Risque : Épuisement des file descriptors/processus"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --ulimit nofile=1024:2048${NC}"
        ((warnings++))
    fi
    
    # 24. Healthcheck (OWASP/CIS - MOYENNE pour monitoring)
    local healthcheck=$(get_container_field "$cid" '{{.Config.Healthcheck}}' 2>/dev/null)
    if [[ "$healthcheck" == "<no value>" ]] || [[ "$healthcheck" == "null" ]] || [[ -z "$healthcheck" ]] || [[ "$healthcheck" == "&lt;no value&gt;" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Healthcheck non défini"
        echo -e "      ${DGRAY}├─${NC} Pas de monitoring automatique de l'état du service"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : HEALTHCHECK CMD curl -f http://localhost/ || exit 1${NC}"
        ((warnings++))
    fi
    
    # 25. Logging driver (ANSSI/CIS - MOYENNE pour traçabilité)
    local log_driver=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Type}}')
    if [[ "$log_driver" == "none" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Logging désactivé (driver: none)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Aucune traçabilité des événements${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser json-file, syslog, ou journald${NC}"
        ((warnings++))
    elif [[ "$log_driver" == "json-file" ]]; then
        local log_max_size=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Config.max-size}}')
        if [[ -z "$log_max_size" ]] || [[ "$log_max_size" == "<no value>" ]]; then
            echo -e "  ${YELLOW}[!]${NC} Logs sans limite de taille (risque de saturation disque)"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --log-opt max-size=10m --log-opt max-file=3${NC}"
            ((warnings++))
        fi
    fi
    
    # 26. Restart policy (OWASP - BASSE pour résilience)
    local restart_policy=$(get_container_field "$cid" '{{.HostConfig.RestartPolicy.Name}}')
    if [[ "$restart_policy" == "no" ]] || [[ -z "$restart_policy" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Restart policy non configuré (le conteneur ne redémarrera pas automatiquement)"
    elif [[ "$restart_policy" == "always" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Restart policy 'always' (peut masquer des crashs répétés)"
        echo -e "      ${DGRAY}└─${NC} Considérer 'on-failure' avec un max-retry"
    fi
    
    # 27. OOM Score adjustment (CIS - BASSE)
    local oom_score=$(get_container_field "$cid" '{{.HostConfig.OomScoreAdj}}')
    if [[ -n "$oom_score" ]] && [[ "$oom_score" != "<no value>" ]] && [[ "$oom_score" -lt -500 ]]; then
        echo -e "  ${YELLOW}[!]${NC} OOM Score très bas ($oom_score) - Le conteneur sera protégé du OOM killer"
        echo -e "      ${DGRAY}└─${NC} Peut affecter la stabilité du système en cas de pression mémoire"
    fi
    
    # 28. Init process (OWASP - BASSE pour gestion des processus zombies)
    local init_process=$(get_container_field "$cid" '{{.HostConfig.Init}}')
    if [[ "$init_process" != "true" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Init process non activé (--init)"
        echo -e "      ${DGRAY}└─${NC} Les processus zombies ne seront pas gérés automatiquement"
    fi
    
    # Résumé
    echo
    if [[ $warnings -eq 0 ]]; then
        echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Aucune alerte de sécurité majeure${NC}"
    elif [[ $warnings -le 2 ]]; then
        echo -e "  ${YELLOW}[!]${NC} $warnings alerte(s) de sécurité détectée(s)"
    else
        echo -e "  ${LRED}[!]${NC} ${LRED}$warnings alerte(s) de sécurité détectée(s) - RÉVISION RECOMMANDÉE${NC}"
    fi
}

# =============================================================================
# FONCTIONS D'INSPECTION DÉTAILLÉE
# =============================================================================

# Fonction d'affichage des conteneurs (simplifiée)
display_containers() {
    local filter="$1"
    local title_color="$2"
    local title="$3"
    local status_width="$4"
    local ports_width="$5"
    
    # Symbole selon la couleur (simplifié)
    local symbol="+"
    [[ "$title_color" != "LGREEN" ]] && symbol="!"
    
    echo -e "${!title_color}[$symbol]${NC} $title :"
    
    # Construire la commande docker ps
    local count
    if [[ -n "$filter" ]]; then
        count=$("$DOCKER_CMD" ps -f "$filter" -q 2>/dev/null | wc -l)
    else
        count=$("$DOCKER_CMD" ps -q 2>/dev/null | wc -l)
    fi
    
    if [[ $count -eq 0 ]]; then
        local msg="en cours d'exécution"
        [[ -n "$filter" ]] && msg="arrêté"
        echo -e "  ${LBLUE}[i]${NC} Aucun conteneur $msg"
        return
    fi
    
    echo ""
    printf "  ${LYELLOW}%-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s${NC}\n" "ID" "NOM" "IMAGE" "STATUS" "TYPE" "SOURCE" "PORTS"
    echo -e "  ${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Construire la commande format selon le filtre
    local format_cmd
    if [[ -n "$filter" ]]; then
        format_cmd=("$DOCKER_CMD" ps -f "$filter" --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}")
    else
        format_cmd=("$DOCKER_CMD" ps --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}")
    fi
    
    # Traiter chaque conteneur
    "${format_cmd[@]}" 2>/dev/null | while IFS='|' read -r cid name image status ports; do
        # Récupérer mounts et compose
        local mounts_str=$(get_container_field "$cid" '{{range .Mounts}}1{{end}}')
        local compose_project=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project"}}')
        
        # Déterminer type et source
        local type="Stateless"
        [[ ${#mounts_str} -gt 0 ]] && type="Stateful"
        
        local source="manuel"
        [[ -n "$compose_project" && "$compose_project" != "<no value>" ]] && source="compose"
        
        # Tronquer et formater
        cid="${cid:0:12}"
        name=$(truncate_text "$name" 18)
        image=$(truncate_text "$image" 30)
        status=$(truncate_text "$status" $status_width)
        ports=$(truncate_text "${ports:-aucun}" $ports_width)
        
        printf "  %-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s\n" "$cid" "$name" "$image" "$status" "$type" "$source" "$ports"
    done
}

# Fonction d'inspection des fichiers de configuration
inspect_config_files() {
    local cid="$1"
    
    echo "Fichiers de configuration et sources :"
    
    # 1. Docker Compose
    local COMPOSE_FILE=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project.config_files"}}')
    local COMPOSE_WORKDIR=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project.working_dir"}}')
    local COMPOSE_PROJECT=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project"}}')
    local COMPOSE_SERVICE=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.service"}}')
    
    if [[ -n "$COMPOSE_PROJECT" && "$COMPOSE_PROJECT" != "<no value>" ]]; then
        echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Docker Compose détecté${NC}"
        echo -e "      ${DGRAY}├─${NC} Projet : $COMPOSE_PROJECT"
        if [[ -n "$COMPOSE_SERVICE" && "$COMPOSE_SERVICE" != "<no value>" ]]; then
            echo -e "      ${DGRAY}├─${NC} Service : $COMPOSE_SERVICE"
        fi
        if [[ -n "$COMPOSE_FILE" && "$COMPOSE_FILE" != "<no value>" ]]; then
            echo -e "      ${DGRAY}├─${NC} Fichier(s) Compose : $COMPOSE_FILE"
        fi
        if [[ -n "$COMPOSE_WORKDIR" && "$COMPOSE_WORKDIR" != "<no value>" ]]; then
            echo -e "      ${DGRAY}└─${NC} Répertoire de travail : $COMPOSE_WORKDIR"
        fi
    else
        echo -e "  ${LBLUE}[i]${NC} Pas de labels Docker Compose (conteneur créé manuellement)"
    fi
    
    echo
    
    # 2. Entrypoint et CMD
    local ENTRYPOINT=$(get_container_field "$cid" '{{json .Config.Entrypoint}}')
    local CMD=$(get_container_field "$cid" '{{json .Config.Cmd}}')
    local WORKDIR=$(get_container_field "$cid" '{{.Config.WorkingDir}}')
    
    echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Exécution détectée${NC}"
    if [[ -n "$ENTRYPOINT" && "$ENTRYPOINT" != "null" ]]; then
        echo -e "      ${DGRAY}├─${NC} Entrypoint : $ENTRYPOINT"
    fi
    if [[ -n "$CMD" && "$CMD" != "null" ]]; then
        echo -e "      ${DGRAY}├─${NC} Command : $CMD"
    fi
    if [[ -n "$WORKDIR" && "$WORKDIR" != "<no value>" ]]; then
        echo -e "      ${DGRAY}└─${NC} WorkDir : $WORKDIR"
    fi
    
    echo
    
    # 3. Labels personnalisés
    local ALL_LABELS=$(get_container_field "$cid" '{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}')
    local CUSTOM_LABELS=$(echo "$ALL_LABELS" | grep -v "^com.docker.compose" | grep -v "^org.opencontainers" | grep -v "^org.label-schema" || true)
    
    if [[ -n "$CUSTOM_LABELS" ]]; then
        echo -e "  ${LBLUE}Labels personnalisés :${NC}"
        local LABEL_COUNT=$(echo "$CUSTOM_LABELS" | wc -l)
        local line_num=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ((line_num++))
            # Vérifier si la ligne contient des données sensibles
            if echo "$line" | grep -qiE "(password|passwd|pwd|pass|secret|token|api[_-]?key|auth|credential)="; then
                if [[ $line_num -eq $LABEL_COUNT ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LRED}$line${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LRED}$line${NC}"
                fi
            else
                if [[ $line_num -eq $LABEL_COUNT ]]; then
                    echo -e "      ${DGRAY}└─${NC} $line"
                else
                    echo -e "      ${DGRAY}├─${NC} $line"
                fi
            fi
        done <<< "$CUSTOM_LABELS"
    fi
}

# Fonction d'inspection des ports
inspect_ports() {
    local cid="$1"
    
    echo "Ports exposés :"
    local PORTS=$(get_container_field "$cid" '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} -> {{(index $conf 0).HostPort}} {{end}}{{end}}')
    
    if [[ -z "$PORTS" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun port exposé sur l'hôte"
    else
        echo -e "  ${DGRAY}├─${NC} ${LBLUE}Docker${NC} → ${LYELLOW}Hôte${NC}"
        get_container_field "$cid" '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} {{(index $conf 0).HostIp}}:{{(index $conf 0).HostPort}}{{println}}{{end}}{{end}}' | while read -r port_container host_mapping; do
            [[ -z "$port_container" ]] && continue
            echo -e "  ${DGRAY}├─${NC} ${LBLUE}$port_container${NC} → ${LYELLOW}$host_mapping${NC}"
        done
    fi
}

# Fonction d'inspection réseau
inspect_network() {
    local cid="$1"
    
    echo "Réseaux :"
    local NETWORKS=$(get_container_field "$cid" '{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s " $name}}{{end}}')
    
    if [[ -z "${NETWORKS// }" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun réseau explicite (bridge par défaut)"
    else
        local NET_ARRAY=($NETWORKS)
        local NET_COUNT=${#NET_ARRAY[@]}
        local i=0
        for NET in $NETWORKS; do
            [[ -z "$NET" ]] && continue
            ((i++))
            local DRIVER=$($DOCKER_CMD network inspect -f '{{.Driver}}' "$NET" 2>/dev/null || echo "inconnu")
            # Récupérer l'IP en utilisant index avec le nom du réseau
            # Construire le template avec le nom du réseau
            local ip_template="{{index .NetworkSettings.Networks \"$NET\" \"IPAddress\"}}"
            local IP=$(get_container_field "$cid" "$ip_template")
            [[ -z "$IP" ]] && IP="inconnu"
            if [[ $i -eq $NET_COUNT ]]; then
                echo -e "  ${DGRAY}└─${NC} $NET :${LBLUE} $DRIVER - $IP${NC}"
            else
                echo -e "  ${DGRAY}├─${NC} $NET :${LBLUE} $DRIVER - $IP${NC}"
            fi
        done
    fi
}

# Fonction d'inspection des montages
inspect_mounts() {
    local cid="$1"
    
    local MOUNTS=$(get_container_field "$cid" '{{range .Mounts}}{{println .Destination "|" .Type "|" .Source "|" .RW}}{{end}}')
    local MOUNTS_COUNT=$(echo "$MOUNTS" | grep -c "|" 2>/dev/null || echo 0)
    
    if [[ -z "$MOUNTS" || $MOUNTS_COUNT -eq 0 ]]; then
        echo -e "Type de conteneur : ${LBLUE}STATELESS${NC} (applicatif sans persistance)"
        echo -e "  ${LBLUE}[i]${NC} Aucun montage détecté"
        echo -e "  ${LBLUE}[i]${NC} Les données sont volatiles et seront perdues à la suppression du conteneur"
    else
        echo -e "Type de conteneur : ${LYELLOW}STATEFUL${NC} (avec persistance de données)"
        echo -e "  ${LGREEN}[+]${NC} $MOUNTS_COUNT montage(s) détecté(s)"
        echo
        local mount_num=0
        while IFS='|' read -r dest type source rw; do
            [[ -z "$dest" ]] && continue
            # Trim whitespace
            dest=$(echo "$dest" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            type=$(echo "$type" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            source=$(echo "$source" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            rw=$(echo "$rw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            
            ((mount_num++))
            
            # Affichage
            if [[ $mount_num -eq $MOUNTS_COUNT ]]; then
                printf "  ${DGRAY}└─${NC} %s\n" "$dest"
            else
                printf "  ${DGRAY}├─${NC} %s\n" "$dest"
            fi
            echo -e "      ${DGRAY}├─${NC} Type : $type"
            if [[ "$rw" == "true" ]]; then
                echo -e "      ${DGRAY}├─${NC} Mode : ${LYELLOW}read-write${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} Mode : ${LBLUE}read-only${NC}"
            fi
            printf "      ${DGRAY}└─${NC} Hôte : %s\n" "$source"
            
            if [[ $mount_num -ne $MOUNTS_COUNT ]]; then
                echo
            fi
        done <<< "$MOUNTS"
        echo

    fi
}

# Fonction d'inspection des ressources
inspect_resources() {
    local cid="$1"
    
    echo "Ressources :"
    local MEM_LIMIT=$(get_container_field "$cid" '{{.HostConfig.Memory}}')
    local CPU_SHARES=$(get_container_field "$cid" '{{.HostConfig.CpuShares}}')
    local CPU_QUOTA=$(get_container_field "$cid" '{{.HostConfig.CpuQuota}}')
    
    local has_cpu_shares=false
    if [[ "$CPU_SHARES" != "0" && "$CPU_SHARES" != "" ]]; then
        has_cpu_shares=true
    fi
    
    # Affichage Mémoire
    if [[ "$MEM_LIMIT" != "0" ]]; then
        if [[ "$CPU_QUOTA" == "0" && "$has_cpu_shares" == "false" ]]; then
            echo -e "  ${DGRAY}└─${NC} RAM limitée : ${LBLUE}$((MEM_LIMIT / 1024 / 1024)) MB${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} RAM limitée : ${LBLUE}$((MEM_LIMIT / 1024 / 1024)) MB${NC}"
        fi
    else
        if [[ "$CPU_QUOTA" == "0" && "$has_cpu_shares" == "false" ]]; then
            echo -e "  ${DGRAY}└─${NC} RAM : ${LRED}illimitée${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} RAM : ${LRED}illimitée${NC}"
        fi
    fi
    
    # Affichage CPU quota
    if [[ "$CPU_QUOTA" != "0" ]]; then
        if [[ "$has_cpu_shares" == "false" ]]; then
            echo -e "  ${DGRAY}└─${NC} CPU quota : ${LBLUE}$CPU_QUOTA${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} CPU quota : ${LBLUE}$CPU_QUOTA${NC}"
        fi
    else
        if [[ "$has_cpu_shares" == "false" ]]; then
            echo -e "  ${DGRAY}└─${NC} CPU : ${LRED}illimité${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} CPU : ${LRED}illimité${NC}"
        fi
    fi
    
    # Affichage CPU shares
    if [[ "$has_cpu_shares" == "true" ]]; then
        echo -e "  ${DGRAY}└─${NC} CPU shares : ${LBLUE}$CPU_SHARES${NC}"
    fi
}

# Fonction d'inspection des variables d'environnement
inspect_env() {
    local cid="$1"
    
    echo "Variables d'environnement :"
    local ALL_ENV=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}')
    local ENV_COUNT=$(echo "$ALL_ENV" | wc -l)
    
    if [[ $ENV_COUNT -eq 0 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucune variable d'environnement"
    else
        local line_num=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ((line_num++))
            echo -e "  ${DGRAY}├─${NC} $line"
        done <<< "$ALL_ENV"
        echo
    fi
}

# Fonction principale d'inspection d'un conteneur
inspect_container() {
    local cid="$1"
    local name=$(get_container_field "$cid" '{{.Name}}' | sed 's|/||')
    local image=$(get_container_field "$cid" '{{.Config.Image}}')
    local status=$(get_container_field "$cid" '{{.State.Status}}')
    local uptime=$(get_container_field "$cid" '{{.State.StartedAt}}')
    # Formater la date pour n'afficher que jusqu'aux minutes (2026-01-13T17:09:16.919855227Z -> 2026-01-13T17:09)
    uptime=$(echo "$uptime" | sed 's/:[0-9][0-9]\..*Z$//' | sed 's/Z$//')
    
    print_subsection "$name ($cid)"
    echo -e "Image  : $image$"
    # Colorer le statut selon son état
    local status_color="${LGREEN}"
    [[ "$status" == "exited" ]] && status_color="${LRED}"
    echo -e "Statut : $status_color$status$NC (depuis : $uptime)"
    echo
    
    inspect_config_files "$cid"
    echo
    
    inspect_ports "$cid"
    echo
    
    inspect_network "$cid"
    echo
    
    inspect_mounts "$cid"
    echo
    
    inspect_resources "$cid"
    echo
    
    inspect_env "$cid"
}

# =============================================================================
# ANALYSE DES CONTENEURS
# =============================================================================

analyze_container() {
    local cid="$1"
    
    # Validation
    validate_container_id "$cid" || return 1
    
    inspect_container "$cid"
    echo
    echo -e "${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Parser les arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--ci)
                CI_MODE=true
                shift
                ;;
            -t|--threshold)
                FAIL_THRESHOLD="$2"
                shift 2
                ;;
            --no-color)
                # Désactiver les couleurs (redéfinir toutes les variables)
                for color_var in RED LRED GREEN LGREEN YELLOW LYELLOW BLUE LBLUE CYAN LCYAN MAGENTA LMAGENTA DGRAY NC; do
                    eval "$color_var=''"
                done
                shift
                ;;
            *)
                log_error "Option inconnue: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Banner
    echo
    echo -e "${LBLUE}╔═════════════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${LBLUE}║${NC}                                                                                     ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}██████╗  ██████╗  ██████╗██╗  ██╗${LRED}███╗   ██╗ ██████╗ ██╗   ██╗ █████╗${NC}         ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝${LRED}████╗  ██║██╔═══██╗██║   ██║██╔══██╗${NC}        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}██║  ██║██║   ██║██║     █████╔╝ ${LRED}██╔██╗ ██║██║   ██║██║   ██║███████║${NC}        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}██║  ██║██║   ██║██║     ██╔═██╗ ${LRED}██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║${NC}        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}██████╔╝╚██████╔╝╚██████╗██║  ██╗${LRED}██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║${NC}        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}        ${LGREEN}╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝${LRED}╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝${NC}        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}                                                                                     ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}                       ${LYELLOW}Inventaire Docker${NC}                        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}                                                                                     ${LBLUE}║${NC}"
    echo -e "${LBLUE}╚═════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Détection Docker/Podman
    detect_container_engine || exit 1
    
    log_info "Moteur de conteneurs: ${LGREEN}$DOCKER_CMD${NC}"
    log_debug "Utilisation de docker inspect --format (pas de dépendance externe)"
    
    [[ "$VERBOSE" == "true" ]] && log_info "Mode verbeux activé"
    [[ "$CI_MODE" == "true" ]] && log_info "Mode CI/CD activé (seuil: $FAIL_THRESHOLD%)"
    
    # 0. Informations système Docker
    print_section "INFO DOCKER"
    
    echo -e "${LBLUE}[+]${NC} Informations système :"
    echo ""
    
    # Hostname
    local hostname=$(hostname)
    echo -e "  ${DGRAY}├─${NC} ${LBLUE}Hostname${NC} : ${LGREEN}$hostname${NC}"
    
    # Adresse IP
    local ip_addr
    if command -v ip &> /dev/null; then
        ip_addr=$(ip route get 1 2>/dev/null | grep -oP 'src \K\S+' || echo "Non disponible")
    elif command -v hostname &> /dev/null; then
        ip_addr=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "Non disponible")
    else
        ip_addr="Non disponible"
    fi
    echo -e "  ${DGRAY}├─${NC} ${LBLUE}Adresse IP${NC} : ${LGREEN}$ip_addr${NC}"
    
    # Version Docker/Podman
    local engine_version=$($DOCKER_CMD --version 2>/dev/null || echo "Version non disponible")
    echo -e "  ${DGRAY}├─${NC} ${LBLUE}Moteur${NC} : ${LGREEN}$DOCKER_CMD${NC}"
    echo -e "  ${DGRAY}└─${NC} ${LBLUE}Version${NC} : ${LGREEN}$engine_version${NC}"
    
    echo ""
    
    # Informations détaillées du daemon
    $DOCKER_CMD info 2>/dev/null | grep -E "Server Version|Storage Driver|Kernel Version|Operating System|CPUs|Total Memory" | while IFS=: read -r key value; do
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        echo -e "  ${DGRAY}├─${NC} ${LBLUE}$key${NC} : $value"
    done
    
    # 1. Vue d'ensemble des conteneurs
    print_section "CONTENEURS DOCKER"
    
    # Afficher les conteneurs en cours d'exécution
    display_containers "" "LGREEN" "Conteneurs en cours d'exécution" 20 30
    
    echo
    
    # Afficher les conteneurs arrêtés
    display_containers "status=exited" "LRED" "Conteneurs arrêtés" 23 20
    
    # 2. Vue d'ensemble des images
    print_section "IMAGES DISPONIBLES"
    $DOCKER_CMD images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}" 2>/dev/null
    
    # 3. Vue d'ensemble des volumes
    print_section "VOLUMES DOCKER"
    $DOCKER_CMD volume ls 2>/dev/null
    
    # 4. Espace utilisé par Docker
    print_section "ESPACE UTILISÉ PAR DOCKER"
    $DOCKER_CMD system df 2>/dev/null
    
    # 5. Réseaux
    print_section "RÉSEAUX DOCKER"
    $DOCKER_CMD network ls 2>/dev/null
    
    # 6. Inspection détaillée des conteneurs
    print_section "INSPECTION DÉTAILLÉE DES CONTENEURS"
    
    local running_containers
    mapfile -t running_containers < <("$DOCKER_CMD" ps -q 2>/dev/null)
    local stopped_containers
    mapfile -t stopped_containers < <("$DOCKER_CMD" ps -a -f "status=exited" -q 2>/dev/null)
    
    local running_count=${#running_containers[@]}
    local stopped_count=${#stopped_containers[@]}
    local total_count=$((running_count + stopped_count))
    
    if [[ $total_count -eq 0 ]]; then
        echo "Aucun conteneur trouvé."
        exit 0
    fi
    
    # Analyse séquentielle de tous les conteneurs (actifs puis arrêtés)
    for cid in "${running_containers[@]}"; do
        analyze_container "$cid"
    done
    
    for cid in "${stopped_containers[@]}"; do
        analyze_container "$cid"
    done
    
    # Résumé final
    print_section "RÉSUMÉ"
    
    # Comptage des conteneurs stateless vs stateful et compose vs manuel
    local stateless_count=0
    local stateful_count=0
    local compose_count=0
    local manual_count=0
    
    for cid in "${running_containers[@]}"; do
        local mounts_count=$(get_container_field "$cid" '{{range .Mounts}}1{{end}}' | wc -c)
        local compose_project=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project"}}')
        
        # Comptage type de conteneur
        if [[ $mounts_count -gt 0 ]]; then
            ((stateful_count++))
        else
            ((stateless_count++))
        fi
        
        if [[ -n "$compose_project" && "$compose_project" != "<no value>" ]]; then
            ((compose_count++))
        else
            ((manual_count++))
        fi
    done
    
    # Ajout des conteneurs arrêtés pour le comptage total (stopped_containers déjà défini plus haut)
    for cid in "${stopped_containers[@]}"; do
        local mounts_count=$(get_container_field "$cid" '{{range .Mounts}}1{{end}}' | wc -c)
        local compose_project=$(get_container_field "$cid" '{{index .Config.Labels "com.docker.compose.project"}}')
        
        if [[ $mounts_count -gt 0 ]]; then
            ((stateful_count++))
        else
            ((stateless_count++))
        fi
        
        if [[ -n "$compose_project" && "$compose_project" != "<no value>" ]]; then
            ((compose_count++))
        else
            ((manual_count++))
        fi
    done
    
    # Affichage du résumé
    print_subsection "Vue d'ensemble"
    echo -e "  ${LGREEN}[+]${NC} Conteneurs actifs  : ${LGREEN}$running_count${NC}"
    
    # Afficher la liste des conteneurs actifs
    if [[ $running_count -gt 0 ]]; then
        local idx=0
        for cid in "${running_containers[@]}"; do
            local name=$(get_container_field "$cid" '{{.Name}}')
            name="${name#/}"  # Enlever le / au début si présent
            ((idx++))
            if [[ $idx -eq $running_count ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$name${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$name${NC}"
            fi
        done
    fi
    
    local stopped_count=${#stopped_containers[@]}
    if [[ $stopped_count -gt 0 ]]; then
        echo -e "  ${LRED}[+]${NC} Conteneurs arrêtés : ${LRED}$stopped_count${NC}"
        
        # Afficher la liste des conteneurs arrêtés
        local idx=0
        for cid in "${stopped_containers[@]}"; do
            local name=$(get_container_field "$cid" '{{.Name}}')
            name="${name#/}"  # Enlever le / au début si présent
            ((idx++))
            if [[ $idx -eq $stopped_count ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LRED}$name${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LRED}$name${NC}"
            fi
        done
    fi
    
    echo
    
    print_subsection "Par type de données"
    echo -e "  ${DGRAY}├─${NC} ${LBLUE}Stateless${NC} : $stateless_count ${DGRAY}(applicatifs sans persistance)${NC}"
    echo -e "  ${DGRAY}└─${NC} ${LYELLOW}Stateful${NC} : $stateful_count ${DGRAY}(avec volumes de données ou montages)${NC}"
    echo
    
    print_subsection "Par méthode de création"
    echo -e "  ${DGRAY}├─${NC} ${LGREEN}Docker Compose${NC} : $compose_count"
    echo -e "  ${DGRAY}└─${NC} Manuel : $manual_count"
    echo
    
    print_subsection "Ressources Docker"
    # Utiliser docker system df pour obtenir les comptages cohérents
    local system_df_output=$($DOCKER_CMD system df 2>/dev/null)
    local total_images=$(echo "$system_df_output" | grep "^Images" | awk '{print $2}')
    local active_images=$(echo "$system_df_output" | grep "^Images" | awk '{print $3}')
    local total_volumes=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $3}')
    local active_volumes=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $4}')
    local total_networks=$($DOCKER_CMD network ls -q 2>/dev/null | wc -l)
    
    # Calculer les non utilisées
    local unused_images=$((total_images - active_images))
    local unused_volumes=$((total_volumes - active_volumes))
    
    # Images utilisées
    echo -e "  ${LGREEN}[+]${NC} Images : $total_images ${DGRAY}(${LGREEN}$active_images${DGRAY} utilisées, ${LYELLOW}$unused_images${DGRAY} non utilisées)${NC}"
    
    # Récupérer les images utilisées par les conteneurs
    local used_image_names
    mapfile -t used_image_names < <($DOCKER_CMD ps -a --format '{{.Image}}' 2>/dev/null | sort -u)
    if [[ ${#used_image_names[@]} -gt 0 ]]; then
        local idx=0
        local has_unused=$([[ $unused_images -gt 0 ]] && echo "true" || echo "false")
        for img in "${used_image_names[@]}"; do
            [[ -z "$img" ]] && continue
            ((idx++))
            # Utiliser └─ seulement si c'est le dernier ET qu'il n'y a pas d'images non utilisées
            if [[ $idx -eq ${#used_image_names[@]} ]] && [[ "$has_unused" == "false" ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$img${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$img${NC}"
            fi
        done
    fi
    
    # Images non utilisées (utiliser docker system df -v pour identifier celles avec 0 conteneurs)
    if [[ $unused_images -gt 0 ]]; then
        local unused_image_list
        mapfile -t unused_image_list < <($DOCKER_CMD system df -v 2>/dev/null | awk '/^Images space usage:/{flag=1; next} /^Containers space usage:/{flag=0} flag && NF>0 && $NF=="0" {print $1":"$2}' | grep -v '^$')
        
        if [[ ${#unused_image_list[@]} -gt 0 ]]; then
            local idx=0
            for img_name in "${unused_image_list[@]}"; do
                [[ -z "$img_name" ]] && continue
                ((idx++))
                # Si c'est le dernier élément de toute la liste (utilisées + non utilisées), utiliser └─
                if [[ $idx -eq ${#unused_image_list[@]} ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}$img_name${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}$img_name${NC}"
                fi
            done
        fi
    fi
    
    # Volumes montés
    echo -e "  ${LGREEN}[+]${NC} Volumes : $total_volumes ${DGRAY}(${LGREEN}$active_volumes${DGRAY} montés, ${LYELLOW}$unused_volumes${DGRAY} non montés)${NC}"
    
    # Récupérer les volumes montés (via inspect de tous les conteneurs)
    local used_volumes=()
    for cid in "${running_containers[@]}" "${stopped_containers[@]}"; do
        local vol_names=$(get_container_field "$cid" '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{println}}{{end}}{{end}}' 2>/dev/null)
        while IFS= read -r vol_name; do
            [[ -n "$vol_name" ]] && used_volumes+=("$vol_name")
        done <<< "$vol_names"
    done
    # Dédupliquer
    local used_volumes_unique
    mapfile -t used_volumes_unique < <(printf '%s\n' "${used_volumes[@]}" | sort -u)
    used_volumes=("${used_volumes_unique[@]}")
    if [[ ${#used_volumes[@]} -gt 0 ]] && [[ -n "${used_volumes[0]}" ]]; then
        local idx=0
        local has_unused_vol=$([[ $unused_volumes -gt 0 ]] && echo "true" || echo "false")
        for vol in "${used_volumes[@]}"; do
            [[ -z "$vol" ]] && continue
            ((idx++))
            # Utiliser └─ seulement si c'est le dernier ET qu'il n'y a pas de volumes non montés
            if [[ $idx -eq ${#used_volumes[@]} ]] && [[ "$has_unused_vol" == "false" ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$vol${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$vol${NC}"
            fi
        done
    fi
    
    # Volumes non montés
    if [[ $unused_volumes -gt 0 ]]; then
        local all_volumes
        mapfile -t all_volumes < <($DOCKER_CMD volume ls --format '{{.Name}}' 2>/dev/null)
        local unused_volume_list=()
        for vol in "${all_volumes[@]}"; do
            local is_used=false
            for used_vol in "${used_volumes[@]}"; do
                if [[ "$vol" == "$used_vol" ]]; then
                    is_used=true
                    break
                fi
            done
            [[ "$is_used" == "false" ]] && unused_volume_list+=("$vol")
        done
        
        if [[ ${#unused_volume_list[@]} -gt 0 ]]; then
            local idx=0
            for vol in "${unused_volume_list[@]}"; do
                ((idx++))
                if [[ $idx -eq ${#unused_volume_list[@]} ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}$vol${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}$vol${NC}"
                fi
            done
        fi
    fi
    
    # Réseaux utilisés (via inspect de tous les conteneurs)
    local used_networks=()
    for cid in "${running_containers[@]}" "${stopped_containers[@]}"; do
        local net_names=$(get_container_field "$cid" '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}}{{println}}{{end}}' 2>/dev/null)
        while IFS= read -r net_name; do
            [[ -n "$net_name" ]] && used_networks+=("$net_name")
        done <<< "$net_names"
    done
    # Dédupliquer
    local used_networks_unique
    mapfile -t used_networks_unique < <(printf '%s\n' "${used_networks[@]}" | sort -u)
    used_networks=("${used_networks_unique[@]}")
    local used_network_count=${#used_networks[@]}
    local unused_network_count=$((total_networks - used_network_count))
    
    echo -e "  ${LGREEN}[+]${NC} Réseaux : $total_networks ${DGRAY}(${LGREEN}$used_network_count${DGRAY} utilisés, ${LYELLOW}$unused_network_count${DGRAY} non utilisés)${NC}"
    
    if [[ ${#used_networks[@]} -gt 0 ]] && [[ -n "${used_networks[0]}" ]]; then
        local idx=0
        for net in "${used_networks[@]}"; do
            [[ -z "$net" ]] && continue
            ((idx++))
            if [[ $idx -eq ${#used_networks[@]} ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$net${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$net${NC}"
            fi
        done
    fi
    
    # Réseaux non utilisés
    if [[ $unused_network_count -gt 0 ]]; then
        local all_networks
        mapfile -t all_networks < <($DOCKER_CMD network ls --format '{{.Name}}' 2>/dev/null)
        local unused_network_list=()
        for net in "${all_networks[@]}"; do
            # Ignorer les réseaux système par défaut
            [[ "$net" == "bridge" ]] || [[ "$net" == "host" ]] || [[ "$net" == "none" ]] && continue
            local is_used=false
            for used_net in "${used_networks[@]}"; do
                if [[ "$net" == "$used_net" ]]; then
                    is_used=true
                    break
                fi
            done
            [[ "$is_used" == "false" ]] && unused_network_list+=("$net")
        done
        
        if [[ ${#unused_network_list[@]} -gt 0 ]]; then
            local idx=0
            for net in "${unused_network_list[@]}"; do
                ((idx++))
                if [[ $idx -eq ${#unused_network_list[@]} ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}$net${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}$net${NC}"
                fi
            done
        fi
    fi
    
    echo
    
    # Section Recommandations d'optimisation
    # stopped_count déjà défini plus haut
    local system_df_output=$($DOCKER_CMD system df 2>/dev/null)
    # Extraction de la colonne RECLAIMABLE
    # Format: TYPE TOTAL ACTIVE SIZE RECLAIMABLE [PERCENTAGE]
    # Pour "Local Volumes" (2 mots), les colonnes sont: Local Volumes TOTAL ACTIVE SIZE RECLAIMABLE PERCENTAGE
    # On extrait la colonne qui contient une taille (GB/MB/KB/B) et qui est la dernière avant le pourcentage
    # Méthode: prendre toutes les colonnes de taille, la dernière est RECLAIMABLE
    local images_reclaimable=$(echo "$system_df_output" | grep "^Images" | awk '{
        for(i=NF; i>=1; i--) {
            if($i ~ /^[0-9.]+(GB|MB|KB|B)$/) {
                print $i
                break
            }
        }
    }' || echo "")
    local containers_reclaimable=$(echo "$system_df_output" | grep "^Containers" | awk '{
        for(i=NF; i>=1; i--) {
            if($i ~ /^[0-9.]+(GB|MB|KB|B)$/) {
                print $i
                break
            }
        }
    }' || echo "")
    local volumes_reclaimable=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{
        for(i=NF; i>=1; i--) {
            if($i ~ /^[0-9.]+(GB|MB|KB|B)$/) {
                print $i
                break
            }
        }
    }' || echo "")
    local build_cache_reclaimable=$(echo "$system_df_output" | grep "^Build Cache" | awk '{
        for(i=NF; i>=1; i--) {
            if($i ~ /^[0-9.]+(GB|MB|KB|B)$/) {
                print $i
                break
            }
        }
    }' || echo "")
    
    # Vérifier si on doit afficher les recommandations
    # Afficher si : images récupérables, volumes non utilisés, conteneurs arrêtés, ou cache de build
    local has_optimizations=false
    [[ -n "$images_reclaimable" ]] && [[ "$images_reclaimable" != "0B" ]] && [[ "$images_reclaimable" != "0" ]] && has_optimizations=true
    [[ $unused_volumes -gt 0 ]] && has_optimizations=true
    [[ $stopped_count -gt 0 ]] && has_optimizations=true
    [[ -n "$build_cache_reclaimable" ]] && [[ "$build_cache_reclaimable" != "0B" ]] && [[ "$build_cache_reclaimable" != "0" ]] && has_optimizations=true
    
    if [[ "$has_optimizations" == "true" ]]; then
        print_section "RECOMMANDATIONS D'OPTIMISATION"
        echo
        
        echo -e "  ${LBLUE}[OPTIMISATION]${NC} Libération d'espace disque :"
        
        # Afficher la recommandation pour les images si espace récupérable significatif
        if [[ -n "$images_reclaimable" ]] && [[ "$images_reclaimable" != "0B" ]] && [[ "$images_reclaimable" != "0" ]]; then
            local image_count_text=""
            if [[ $unused_images -gt 0 ]]; then
                image_count_text="${LYELLOW}$unused_images${DGRAY} image(s) · "
            fi
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker image prune -a${NC} ${DGRAY}(${image_count_text}${LGREEN}~$images_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        if [[ $unused_volumes -gt 0 ]] && [[ -n "$volumes_reclaimable" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker volume prune${NC} ${DGRAY}(${LYELLOW}$unused_volumes${DGRAY} volume(s) · ${LGREEN}~$volumes_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        if [[ $stopped_count -gt 0 ]] && [[ -n "$containers_reclaimable" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker container prune${NC} ${DGRAY}(${LYELLOW}$stopped_count${DGRAY} conteneur(s) · ${LGREEN}~$containers_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        if [[ -n "$build_cache_reclaimable" ]] && [[ "$build_cache_reclaimable" != "0B" ]] && [[ "$build_cache_reclaimable" != "0" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker builder prune${NC} ${DGRAY}(cache de build · ${LGREEN}~$build_cache_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker network prune${NC} ${DGRAY}(supprimer les réseaux non utilisés)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker system prune -a --volumes${NC} ${DGRAY}(nettoyage complet - ${LRED}ATTENTION aux données${DGRAY})${NC}"
        echo
    fi
    
    # Mode CI désactivé pour l'inventaire (pas de score de sécurité)
    
    exit 0
}

# Exécution du main
main "$@"
