#!/usr/bin/env bash

# =============================================================================
# DockNova - Audit de Sécurité Docker Professionnel
# Version: 2.0 (Sécurité uniquement)
# Références: CIS Docker Benchmark, ANSSI, OWASP Docker Security
# =============================================================================

# Hardening du script
set -uo pipefail  # Pas de -e car les fonctions check retournent 1 intentionnellement
IFS=$'\n\t'

# Gestion des signaux
trap 'echo -e "\n${LRED}[x] Script interrompu${NC}" >&2; exit 130' INT TERM

# =============================================================================
# CONFIGURATION ET CONSTANTES
# =============================================================================

# Couleurs (non-readonly pour permettre désactivation avec --no-color)
RED='\033[0;31m'
LRED='\033[1;31m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
YELLOW='\033[0;33m'
LYELLOW='\033[1;33m'
BLUE='\033[0;34m'
LBLUE='\033[1;34m'
CYAN='\033[0;36m'
LCYAN='\033[1;36m'
MAGENTA='\033[0;35m'
LMAGENTA='\033[1;35m'
DGRAY='\033[1;30m'
NC='\033[0m'

# Configuration
readonly VERSION="2.0"
readonly SCRIPT_NAME="DockNova Sécurité"

# Options de ligne de commande
VERBOSE=false
NO_COLOR=false     # Désactiver les couleurs

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
${LGREEN}${SCRIPT_NAME}${NC} v${VERSION} - Audit de Sécurité Docker Professionnel

${LBLUE}USAGE:${NC}
    $(basename "$0") [OPTIONS]

${LBLUE}OPTIONS:${NC}
    -h, --help              Afficher cette aide
    -v, --verbose           Mode verbeux avec debug
    --no-color              Désactiver les couleurs

${LBLUE}EXEMPLES:${NC}
    $(basename "$0")                          # Audit standard
    $(basename "$0") -v                       # Mode verbeux

${LBLUE}RÉFÉRENCES:${NC}
    - ANSSI Docker: https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker
    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

${LBLUE}NOTE:${NC}

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
    local total_width=87
    local title_length=${#title}
    local lines_space=$((total_width - title_length - 4))
    local left_width=$((lines_space / 2))
    local right_width=$((lines_space - left_width))
    
    # Génération des lignes sans dépendance à seq (compatible tous systèmes)
    local left_line=""
    local right_line=""
    local i=0
    while [[ $i -lt $left_width ]]; do
        left_line="${left_line}═"
        ((i++))
    done
    i=0
    while [[ $i -lt $right_width ]]; do
        right_line="${right_line}═"
        ((i++))
    done
    
    echo ""
    echo -e "${LBLUE}${left_line}{ ${LGREEN}$title${NC} ${LBLUE}}${right_line}${NC}"
}

print_subsection() {
    local subtitle="$1"
    echo ""
    echo -e "  ${LBLUE}▶ $subtitle${NC}"
    echo ""
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
# FONCTION DE VÉRIFICATION DE SÉCURITÉ COMPLÈTE
# =============================================================================

check_security() {
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
            echo -e "  ${LRED}[x]${NC} ${LRED}Conteneur exécuté en root (User: $user)${NC}"
        else
            echo -e "  ${LRED}[x]${NC} ${LRED}Conteneur exécuté en root (User non défini = root par défaut)${NC}"
        fi
        ((warnings++))
    else
        echo -e "  ${LGREEN}[+]${NC} Utilisateur non-root : $user (UID: $uid_only)"
    fi
    
    # 2. Mode privilégié
    if [[ "$privileged" == "true" ]]; then
        echo -e "  ${LRED}[x]${NC} Conteneur en mode privilégié"
        ((warnings++))
    else
        echo -e "  ${LGREEN}[+]${NC} Pas de mode privilégié"
    fi
    
    # 3. Capabilities - Détection avancée
    local dangerous_caps_found=false
    if [[ "$cap_add" != "[]" && "$cap_add" != "<no value>" && "$cap_add" != "null" ]]; then
        if echo "$cap_add" | grep -qiE "SYS_ADMIN|ALL"; then
            echo -e "  ${LRED}[x]${NC} ${LRED}CRITIQUE : Capability SYS_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Montage de cgroups, accès /dev, échappement de conteneur${NC}"
            echo -e "      ${DGRAY}├─${NC} Permet de monter des systèmes de fichiers arbitraires"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount -t cgroup -o rdma cgroup /tmp/cg && echo > /tmp/cg/release_agent${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_PTRACE"; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Capability SYS_PTRACE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Injection de code dans les processus de l'hôte${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet d'utiliser ptrace() pour attacher et modifier des processus${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_MODULE"; then
            echo -e "  ${LRED}[x]${NC} ${LRED}CRITIQUE : Capability SYS_MODULE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Chargement de modules kernel malveillants${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : insmod /tmp/rootkit.ko${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_RAWIO"; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Capability SYS_RAWIO ajoutée${NC}"
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
            echo -e "  ${LRED}[x]${NC} ${LRED}Capability SYS_BOOT ajoutée${NC}"
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
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Docker monté (risque accès ÉCRITURE)${NC}"
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
    
    # 4.2. Vérifier le socket Podman (root et rootless)
    local podman_socket_dest=""
    
    # Détecter socket root: /run/podman/podman.sock
    if echo "$volumes" | grep -q "/run/podman/podman.sock"; then
        podman_socket_dest="/run/podman/podman.sock"
    # Détecter socket rootless: /run/user/*/podman/podman.sock
    elif echo "$volumes" | grep -qE "/run/user/[0-9]+/podman/podman.sock"; then
        # Extraire le chemin exact depuis le JSON des volumes
        podman_socket_dest=$(echo "$volumes" | grep -oE '"/run/user/[0-9]+/podman/podman.sock"' | head -1 | tr -d '"')
    fi
    
    if [[ -n "$podman_socket_dest" ]]; then
        socket_mode=$(get_container_field "$cid" "{{range .Mounts}}{{if eq .Destination \"$podman_socket_dest\"}}{{.RW}}{{end}}{{end}}")
        
        local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l \"$podman_socket_dest\" 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        local socket_path_display="$podman_socket_dest"
        # Afficher le pattern générique pour rootless
        if [[ "$podman_socket_dest" =~ /run/user/[0-9]+/podman/podman.sock ]]; then
            socket_path_display="/run/user/\$(id -u)/podman/podman.sock (rootless)"
        fi
        
        if [[ "$socket_mode" == "true" ]] || echo "$socket_perms" | grep -q "rw"; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Podman monté (risque accès ÉCRITURE)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Contrôle total du moteur Podman${NC}"
            echo -e "      ${DGRAY}├─${NC} Chemin : ${LBLUE}$socket_path_display${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LYELLOW}RW=$socket_mode${NC}"
            ((warnings++))
        else
            echo -e "  ${YELLOW}[!]${NC} Socket Podman monté (configuration read-only)"
            echo -e "      ${DGRAY}├─${NC} Chemin : ${LBLUE}$socket_path_display${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            ((warnings++))
        fi
        docker_socket_found=true
    fi
    
    # 4.3. Vérifier si d'autres répertoires Docker sont montés
    if echo "$volumes" | grep -q "/var/lib/docker"; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Répertoire Docker monté (/var/lib/docker)${NC}"
        echo -e "      ${DGRAY}├─${NC} Accès direct aux données Docker (images, volumes, conteneurs)"
        echo -e "      ${DGRAY}└─${NC} ${LRED}Possibilité de manipulation des données Docker${NC}"
        ((warnings++))
        docker_socket_found=true
    fi
    
    # 4.4. Détecter les variables d'environnement Docker exposées
    local docker_host_var=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}' | grep "DOCKER_HOST=" || echo "")
    if [[ -n "$docker_host_var" ]]; then
        echo -e "  ${LRED}[x]${NC} Variable DOCKER_HOST détectée : ${LYELLOW}$docker_host_var${NC}"
        echo -e "      ${DGRAY}└─${NC} Accès potentiel à un daemon Docker distant"
        ((warnings++))
        docker_socket_found=true
    fi
    
    # 4.5. Vérifier si le conteneur peut accéder au socket depuis l'intérieur (cas où le montage n'a pas été détecté)
    if $DOCKER_CMD exec "$cid" sh -c "test -S /var/run/docker.sock" 2>/dev/null; then
        if [[ "$docker_socket_found" == "false" ]]; then
            local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            if echo "$socket_perms" | grep -q "rw"; then
                echo -e "  ${LRED}[x]${NC} ${LRED}Socket Docker accessible DANS le conteneur (permissions écriture)${NC}"
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
        echo -e "  ${LRED}[x]${NC} Namespace PID partagé avec l'hôte (--pid=host)"
        ((warnings++))
    fi
    
    # 6. Namespace IPC
    if [[ "$ipc_mode" == "host" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Namespace IPC partagé avec l'hôte (--ipc=host)"
        ((warnings++))
    fi
    
    # 7. Mode réseau
    if [[ "$network_mode" == "host" ]]; then
        echo -e "  ${LRED}[x]${NC} Mode réseau host (--network=host)"
        ((warnings++))
    fi
    
    # 8. SELinux / AppArmor
    if [[ "$security_opt" == "[]" || "$security_opt" == "<no value>" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucune option de sécurité supplémentaire (SELinux/AppArmor)"
    else
        if echo "$security_opt" | grep -q "seccomp=unconfined"; then
            echo -e "  ${LRED}[x]${NC} Seccomp désactivé - Tous les syscalls autorisés"
            ((warnings++))
        fi
        if echo "$security_opt" | grep -q "apparmor=unconfined"; then
            echo -e "  ${LRED}[x]${NC} AppArmor désactivé"
            ((warnings++))
        fi
        if echo "$security_opt" | grep -q "label=disable"; then
            echo -e "  ${LRED}[x]${NC} SELinux désactivé"
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
        echo -e "  ${LRED}[x]${NC} Répertoires système sensibles montés depuis l'hôte"
        ((warnings++))
        has_sensitive_mount=true
    fi
    
    # Détection des fichiers .env montés avec affichage de l'emplacement
    if echo "$volumes" | grep -qE "\.env\"|\.env\.|/\.env\""; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Fichier .env monté - Risque d'exposition de secrets${NC}"
        # Extraire tous les montages et filtrer ceux contenant .env
        # Utiliser range pour parcourir tous les montages et mieux gérer les chemins Windows
        local env_mounts_found=false
        local mount_num=0
        local total_env_mounts=0
        
        # Récupérer tous les montages avec un séparateur unique qui ne peut pas être dans un chemin
        local all_mounts=$(get_container_field "$cid" '{{range .Mounts}}{{.Source}}___SEP___{{.Destination}}{{println}}{{end}}')
        
        # Compter d'abord le nombre de montages .env
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local source="${line%%___SEP___*}"
            local dest="${line#*___SEP___}"
            source=$(echo "$source" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r')
            dest=$(echo "$dest" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r')
            if echo "$source" | grep -qE "\.env" || echo "$dest" | grep -qE "\.env"; then
                ((total_env_mounts++))
            fi
        done <<< "$all_mounts"
        
        # Afficher les montages .env
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local source="${line%%___SEP___*}"
            local dest="${line#*___SEP___}"
            # Nettoyer les espaces en début/fin et préserver les backslashes
            source=$(echo "$source" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r')
            dest=$(echo "$dest" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r')
            [[ -z "$source" || -z "$dest" ]] && continue
            if echo "$source" | grep -qE "\.env" || echo "$dest" | grep -qE "\.env"; then
                env_mounts_found=true
                ((mount_num++))
                # Tronquer si trop long pour l'affichage (max 60 caractères)
                local source_display="$source"
                local dest_display="$dest"
                if [[ ${#source_display} -gt 60 ]]; then
                    source_display="...${source_display: -57}"
                fi
                if [[ ${#dest_display} -gt 60 ]]; then
                    dest_display="...${dest_display: -57}"
                fi
                if [[ $mount_num -eq $total_env_mounts ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LRED}Hôte${NC} : ${LYELLOW}$source_display${NC} → ${LRED}Conteneur${NC} : ${LYELLOW}$dest_display${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LRED}Hôte${NC} : ${LYELLOW}$source_display${NC} → ${LRED}Conteneur${NC} : ${LYELLOW}$dest_display${NC}"
                fi
            fi
        done <<< "$all_mounts"
        
        ((warnings++))
        has_sensitive_mount=true
    fi
    
    if [[ "$has_sensitive_mount" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun montage sensible détecté"
    fi
    
    # 11. Variables sensibles exposées
    local all_env=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}')
    local all_labels=$(get_container_field "$cid" '{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}')
    
    local sensitive_env=$(detect_sensitive_data "$all_env")
    local sensitive_labels=$(detect_sensitive_data "$all_labels")
    
    # Rechercher les variables d'utilisateur associées si un mot de passe est détecté
    local has_password=false
    if echo "$sensitive_env" | grep -qiE "(password|passwd|pwd|pass)="; then
        has_password=true
    fi
    
    # Si un mot de passe est trouvé, rechercher les variables d'utilisateur associées
    local user_vars=""
    if [[ "$has_password" == "true" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            # Rechercher les variables d'utilisateur courantes (patterns variés)
            if echo "$line" | grep -qiE "^[A-Z_]*USER[A-Z_]*=|^USERNAME=|^DB_USER|^MYSQL_USER|^POSTGRES_USER|^MONGO_USER|^REDIS_USER|^ADMIN_USER|^API_USER|^APP_USER|^SERVICE_USER|^LOGIN_USER"; then
                # Vérifier si cette variable n'est pas déjà dans sensitive_env
                local var_name=$(echo "$line" | cut -d'=' -f1)
                if ! echo "$sensitive_env" | grep -qi "^$var_name="; then
                    if [[ -z "$user_vars" ]]; then
                        user_vars="$line"
                    else
                        user_vars="${user_vars}\n${line}"
                    fi
                fi
            fi
        done <<< "$all_env"
    fi
    
    if [[ -n "$sensitive_env" ]] || [[ -n "$user_vars" ]]; then
        local env_count=0
        local user_count=0
        if [[ -n "$sensitive_env" ]]; then
            env_count=$(echo "$sensitive_env" | grep -c . 2>/dev/null || echo "0")
            # S'assurer que c'est un nombre
            [[ ! "$env_count" =~ ^[0-9]+$ ]] && env_count=0
        fi
        if [[ -n "$user_vars" ]]; then
            user_count=$(echo -e "$user_vars" | grep -c . 2>/dev/null || echo "0")
            # S'assurer que c'est un nombre
            [[ ! "$user_count" =~ ^[0-9]+$ ]] && user_count=0
        fi
        local total_count=$((env_count + user_count))
        echo -e "  ${LRED}[x]${NC} ${LRED}$total_count variable(s) d'environnement sensible(s) détectée(s)${NC}"
        # Afficher les variables sensibles détectées
        local env_line_num=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ((env_line_num++))
            # Masquer partiellement la valeur pour la sécurité (afficher seulement les 10 premiers caractères)
            local var_name=$(echo "$line" | cut -d'=' -f1)
            local var_value=$(echo "$line" | cut -d'=' -f2-)
            # Utiliser ├─ pour toutes les variables (car on peut avoir des labels ou le total après)
            echo -e "      ${DGRAY}├─${NC} ${LRED}$var_name=${NC}${LYELLOW}$var_value${NC}"
        done <<< "$sensitive_env"
        
        # Afficher les variables d'utilisateur associées
        if [[ -n "$user_vars" ]]; then
            local user_count=$(echo -e "$user_vars" | grep -c . || echo "0")
            local user_line_num=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                ((user_line_num++))
                local var_name=$(echo "$line" | cut -d'=' -f1)
                local var_value=$(echo "$line" | cut -d'=' -f2-)
                # Utiliser ├─ pour toutes les variables utilisateur
                echo -e "      ${DGRAY}├─${NC} ${YELLOW}$var_name=${NC}${LYELLOW}$var_value${NC}"
            done <<< "$(echo -e "$user_vars")"
        fi
        
        ((warnings++))
    fi
    
    if [[ -n "$sensitive_labels" ]]; then
        local label_count=$(echo "$sensitive_labels" | grep -c . 2>/dev/null || echo "0")
        # S'assurer que c'est un nombre
        [[ ! "$label_count" =~ ^[0-9]+$ ]] && label_count=0
        echo -e "  ${YELLOW}[!]${NC} $label_count label(s) avec informations sensibles détecté(s)"
        # Afficher les labels sensibles détectés
        local label_line_num=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ((label_line_num++))
            # Masquer partiellement la valeur pour la sécurité
            local label_name=$(echo "$line" | cut -d'=' -f1)
            local label_value=$(echo "$line" | cut -d'=' -f2-)
            local masked_value=""
            if [[ ${#label_value} -gt 10 ]]; then
                masked_value="${label_value:0:10}...${label_value: -4}"
            else
                masked_value="***"
            fi
            # Utiliser ├─ pour tous les labels car le total sera toujours affiché après
            echo -e "      ${DGRAY}├─${NC} ${YELLOW}$label_name=${NC}${LYELLOW}$masked_value${NC}"
        done <<< "$sensitive_labels"
        ((warnings++))
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
                echo -e "  ${LRED}[x]${NC} ${LRED}CRITIQUE : Périphérique de disque exposé : $device${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Accès direct au système de fichiers de l'hôte${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount $device /mnt && chroot /mnt${NC}"
                ((warnings++))
                critical_device=true
            elif echo "$device" | grep -qE "/dev/kmsg|/dev/mem|/dev/kmem"; then
                echo -e "  ${LRED}[x]${NC} ${LRED}CRITIQUE : Device de mémoire kernel exposé : $device${NC}"
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
        echo -e "  ${LRED}[x]${NC} ${LRED}User namespace désactivé (--userns=host)${NC}"
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
                echo -e "  ${LRED}[x]${NC} ${LRED}SYSCTL DANGEREUX : $sysctl${NC}"
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
        echo -e "  ${LRED}[x]${NC} ${LRED}CRITIQUE : Configuration permettant la manipulation des cgroups${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Risque : Échappement de conteneur via release_agent (CVE-2022-0492)${NC}"
        for reason in "${cgroup_reasons[@]}"; do
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Raison : $reason${NC}"
        done
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}PoC : https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/${NC}"
        ((warnings++))
    fi
    
    # 17. Kernel vulnérable
    local kernel_version=$($DOCKER_CMD info 2>/dev/null | grep "Kernel Version" | cut -d: -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [[ -n "$kernel_version" ]]; then
        local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
        local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
        # Valider que kernel_major et kernel_minor sont numériques avant comparaison
        if [[ "$kernel_major" =~ ^[0-9]+$ ]] && [[ "$kernel_minor" =~ ^[0-9]+$ ]]; then
            if [[ "$kernel_major" -lt 4 ]]; then
                echo -e "  ${LRED}[x]${NC} ${LRED}Kernel hôte OBSOLÈTE : $kernel_version${NC}"
                echo -e "      ${DGRAY}└─${NC} Mise à jour du kernel de l'hôte Docker fortement recommandée"
                ((warnings++))
            elif [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -lt 15 ]]; then
                echo -e "  ${YELLOW}[!]${NC} Kernel hôte potentiellement vulnérable : $kernel_version"
                echo -e "      ${DGRAY}└─${NC} Vérifier les CVE associées à cette version"
                ((warnings++))
            fi
        else
            log_debug "Version kernel non numérique détectée: $kernel_version"
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
        echo -e "  ${LRED}[x]${NC} ${LRED}Répertoire AWS CLI détecté (/root/.aws)${NC}"
        ((warnings++))
    fi
    if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.config/gcloud" 2>/dev/null; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Répertoire GCP CLI détecté (/root/.config/gcloud)${NC}"
        ((warnings++))
    fi
    if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.azure" 2>/dev/null; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Répertoire Azure CLI détecté (/root/.azure)${NC}"
        ((warnings++))
    fi
    
    # 20. Limites de ressources (ANSSI/CIS - HAUTE pour prévenir DoS)
    local mem_limit=$(get_container_field "$cid" '{{.HostConfig.Memory}}')
    local cpu_quota=$(get_container_field "$cid" '{{.HostConfig.CpuQuota}}')
    local cpu_shares=$(get_container_field "$cid" '{{.HostConfig.CpuShares}}')
    
    local resource_unlimited=false
    if [[ "$mem_limit" == "0" ]]; then
        echo -e "  ${LRED}[x]${NC} ${LRED}RAM illimitée - Risque de déni de service (DoS)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Memory exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --memory=<limit> (ex: --memory=2g)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    if [[ "$cpu_quota" == "-1" ]] || [[ "$cpu_quota" == "0" ]]; then
        echo -e "  ${LRED}[x]${NC} ${LRED}CPU illimité - Risque de monopolisation CPU${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : CPU exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --cpus=<limit> (ex: --cpus=2)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    # 21. Tag :latest (ANSSI/OWASP - HAUTE pour reproductibilité et traçabilité)
    local image_full=$(get_container_field "$cid" '{{.Config.Image}}')
    if echo "$image_full" | grep -qE ':latest$|^[^:]+$'; then
        echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Image avec tag :latest ou sans tag${NC}"
        echo -e "      ${DGRAY}├─${NC} ${YELLOW}Risque : Déploiements non-déterministes, versions non traçables${NC}"
        echo -e "      ${DGRAY}├─${NC} Image : ${LYELLOW}$image_full${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser des tags versionnés (ex: nginx:1.21.6)${NC}"
        ((warnings++))
    fi
    
    # 22. PIDs limit (CIS - HAUTE pour prévenir fork bomb)
    local pids_limit=$(get_container_field "$cid" '{{.HostConfig.PidsLimit}}')
    if [[ "$pids_limit" == "0" ]] || [[ "$pids_limit" == "-1" ]] || [[ -z "$pids_limit" ]]; then
        echo -e "  ${LRED}[x]${NC} ${LRED}PIDs limit non défini - Risque de fork bomb${NC}"
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
    # Vérifier si healthcheck est vide, null, ou contient des valeurs indiquant l'absence
    if [[ -z "$healthcheck" ]] || [[ "$healthcheck" =~ ^(<no value>|null|&lt;no value&gt;)$ ]]; then
        echo -e "  ${YELLOW}[!]${NC} Healthcheck non défini"
        echo -e "      ${DGRAY}├─${NC} Pas de monitoring automatique de l'état du service"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : HEALTHCHECK CMD curl -f http://localhost/ || exit 1${NC}"
        ((warnings++))
    fi
    
    # 25. Logging driver (ANSSI/CIS - MOYENNE pour traçabilité)
    local log_driver=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Type}}')
    if [[ "$log_driver" == "none" ]]; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Logging désactivé (driver: none)${NC}"
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
    if [[ -n "$oom_score" ]] && [[ "$oom_score" != "<no value>" ]] && [[ "$oom_score" =~ ^-?[0-9]+$ ]] && [[ "$oom_score" -lt -500 ]]; then
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
        echo -e "  ${LRED}[x]${NC} ${LRED}$warnings alerte(s) de sécurité détectée(s) - RÉVISION RECOMMANDÉE${NC}"
    fi
}

# =============================================================================
# FONCTIONS D'INSPECTION DÉTAILLÉE
# =============================================================================

# Fonction d'affichage des conteneurs (réutilisable)
display_containers() {
    local filter="$1"  # "" pour running, "status=exited" pour stopped
    local title_color="$2"  # LGREEN ou YELLOW
    local title="$3"
    local status_width="$4"  # 20 ou 23
    local ports_width="$5"  # 30 ou 20
    
    echo -e "${!title_color}[$( [[ "$title_color" == "LGREEN" ]] && echo "+" || echo "!" )]${NC} $title :"
    
    local cmd_filter=""
    [[ -n "$filter" ]] && cmd_filter="-f $filter"
    
    local count=$($DOCKER_CMD ps $cmd_filter -q 2>/dev/null | wc -l)
    if [[ $count -eq 0 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun conteneur $( [[ -z "$filter" ]] && echo "en cours d'exécution" || echo "arrêté" )"
        return
    fi
    
    
    # Récupérer toutes les infos en un seul appel par conteneur
    $DOCKER_CMD ps $cmd_filter --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" 2>/dev/null | while IFS='|' read -r cid name image status ports; do
        # Récupérer les infos supplémentaires nécessaires
        local mounts_info=$(get_container_field "$cid" '{{range .Mounts}}1{{end}}|{{index .Config.Labels "com.docker.compose.project"}}')
        local mounts_count=$(echo "$mounts_info" | cut -d'|' -f1 | grep -o '1' | wc -l)
        local compose_project=$(echo "$mounts_info" | cut -d'|' -f2)
        
        # Déterminer le type
        local type=$( [[ $mounts_count -gt 0 ]] && echo "Stateful" || echo "Stateless" )
        
        # Déterminer la source
        local source="manuel"
        [[ -n "$compose_project" && "$compose_project" != "<no value>" ]] && source="compose"
        
        # Gérer les ports
        [[ -z "$ports" ]] && ports="aucun"
        
        # Tronquer les champs
        cid="${cid:0:12}"
        name=$(truncate_text "$name" 18)
        image=$(truncate_text "$image" 30)
        status=$(truncate_text "$status" $status_width)
        ports=$(truncate_text "$ports" $ports_width)
        
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
    
    echo -e "  ${LBLUE}Exécution :${NC}"
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
        echo -e "  ${DGRAY}├─${NC} ${LBLUE}Docker${NC} → ${LGREEN}Hôte${NC}"
        get_container_field "$cid" '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} {{(index $conf 0).HostIp}}:{{(index $conf 0).HostPort}}{{println}}{{end}}{{end}}' | while read -r port_container host_mapping; do
            [[ -z "$port_container" ]] && continue
            echo -e "  ${DGRAY}├─${NC} ${LBLUE}$port_container${NC} → ${LGREEN}$host_mapping${NC}"
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
            # Correction : utiliser le nom de la variable correctement dans le template Go
            local IP=$(get_container_field "$cid" "{{index (index .NetworkSettings.Networks \"$NET\") \"IPAddress\"}}")
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
        echo -e "  ${LBLUE}[+]${NC} $MOUNTS_COUNT montage(s) détecté(s)"
        echo
        echo "Montages et emplacements sur l'hôte :"
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
            
            # Détection de montage sensible
            local IS_SENSITIVE=""
            if echo "$dest" | grep -qE "^/(var/run/docker\.sock|var/lib/docker|etc|root|boot|dev|sys|proc)"; then
                IS_SENSITIVE="${LRED}[x] "
            fi
            if echo "$dest" | grep -qE "\.env$|\.env\.|/\.env$" || echo "$source" | grep -qE "\.env$|\.env\.|/\.env$"; then
                IS_SENSITIVE="${LRED}[x] "
            fi
            
            # Affichage
            if [[ $mount_num -eq $MOUNTS_COUNT ]]; then
                if [[ -n "$IS_SENSITIVE" ]]; then
                    printf "  ${DGRAY}└─${NC} ${IS_SENSITIVE}${LRED}%s${NC}\n" "$dest"
                else
                    printf "  ${DGRAY}└─${NC} %s\n" "$dest"
                fi
            else
                if [[ -n "$IS_SENSITIVE" ]]; then
                    printf "  ${DGRAY}├─${NC} ${IS_SENSITIVE}${LRED}%s${NC}\n" "$dest"
                else
                    printf "  ${DGRAY}├─${NC} %s\n" "$dest"
                fi
            fi
            echo -e "      ${DGRAY}├─${NC} Type : $type"
            if [[ "$rw" == "true" ]]; then
                echo -e "      ${DGRAY}├─${NC} Mode : ${LYELLOW}read-write${NC} (RW=true)"
            else
                echo -e "      ${DGRAY}├─${NC} Mode : ${LBLUE}read-only déclaré${NC} (RW=false) ${DGRAY}*${NC}"
            fi
            if [[ -n "$IS_SENSITIVE" ]]; then
                printf "      ${DGRAY}└─${NC} Hôte : ${LRED}%s${NC}\n" "$source"
            else
                printf "      ${DGRAY}└─${NC} Hôte : %s\n" "$source"
            fi
            
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
            echo -e "  ${DGRAY}└─${NC} RAM : ${LYELLOW}illimitée${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} RAM : ${LYELLOW}illimitée${NC}"
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
            echo -e "  ${DGRAY}└─${NC} CPU : ${LYELLOW}illimité${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} CPU : ${LYELLOW}illimité${NC}"
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
        local sensitive_count=0
        local line_num=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ((line_num++))
            # Vérifier si la variable contient des données sensibles
            if echo "$line" | grep -qiE "(password|passwd|pwd|pass|secret|token|api[_-]?key|auth|credential)="; then
                if [[ $line_num -eq $ENV_COUNT ]]; then
                    echo -e "  ${DGRAY}└─${NC} ${LRED}$line${NC}"
                else
                    echo -e "  ${DGRAY}├─${NC} ${LRED}$line${NC}"
                fi
                ((sensitive_count++))
            else
                if [[ $line_num -eq $ENV_COUNT ]]; then
                    echo -e "  ${DGRAY}└─${NC} $line"
                else
                    echo -e "  ${DGRAY}├─${NC} $line"
                fi
            fi
        done <<< "$ALL_ENV"
        echo
        if [[ $sensitive_count -gt 0 ]]; then
            echo -e "  ${LRED}[x]${NC} Total : $ENV_COUNT variable(s) dont ${LRED}$sensitive_count sensible(s)${NC}"
        else
            echo -e "  ${LBLUE}[i]${NC} Total : $ENV_COUNT variable(s) d'environnement"
        fi
    fi
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
            --no-color)
                # Désactiver les couleurs (vider toutes les variables de couleur)
                RED=''
                LRED=''
                GREEN=''
                LGREEN=''
                YELLOW=''
                LYELLOW=''
                BLUE=''
                LBLUE=''
                CYAN=''
                LCYAN=''
                MAGENTA=''
                LMAGENTA=''
                DGRAY=''
                NC=''
                NO_COLOR=true
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
    echo -e "${LBLUE}║${NC}                              ${LYELLOW}Audit de Sécurité Docker${NC}                               ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}                                                                                     ${LBLUE}║${NC}"
    echo -e "${LBLUE}╚═════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Détection Docker/Podman
    detect_container_engine || exit 1
    
    log_info "Moteur de conteneurs: ${LGREEN}$DOCKER_CMD${NC}"
    log_debug "Utilisation de docker inspect --format (pas de dépendance externe)"
    
    [[ "$VERBOSE" == "true" ]] && log_info "Mode verbeux activé"
    
    # Audit de sécurité des conteneurs
    print_section "AUDIT DE SÉCURITÉ DES CONTENEURS"
    
    local running_containers
    mapfile -t running_containers < <("$DOCKER_CMD" ps -q 2>/dev/null)
    
    local running_count=${#running_containers[@]}
    
    if [[ $running_count -eq 0 ]]; then
        echo "Aucun conteneur en cours d'exécution."
        exit 0
    fi
    
    log_info "Analyse de ${LGREEN}$running_count${NC} conteneur(s)..."
    echo
    
    # Analyse séquentielle de tous les conteneurs (audit de sécurité uniquement)
    for cid in "${running_containers[@]}"; do
        validate_container_id "$cid" || continue
        
        local name=$(get_container_field "$cid" '{{.Name}}' | sed 's|/||')
        print_subsection "$name ($cid)"
        check_security "$cid" "$name"
        echo
        echo -e "${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo
    done
    
    # Résumé final
    print_section "RÉSUMÉ"
    
    # Compteurs de sécurité uniquement
    
    # Compteurs de sécurité
    local total_security_issues=0
    local containers_with_root=0
    local containers_privileged=0
    local containers_with_docker_socket=0
    local containers_with_host_pid=0
    local containers_with_host_network=0
    local containers_with_sensitive_mounts=0
    local containers_with_sensitive_vars=0
    local containers_secure=0
    local containers_with_dangerous_caps=0
    local containers_without_no_new_privs=0
    local containers_with_dangerous_devices=0
    local containers_with_cgroup_access=0
    local containers_with_cloud_creds=0
    local containers_with_seccomp_disabled=0
    local containers_with_unlimited_resources=0
    local containers_with_latest_tag=0
    local containers_without_pids_limit=0
    local containers_without_ulimits=0
    local containers_without_healthcheck=0
    local containers_with_no_logging=0
    
    for cid in "${running_containers[@]}"; do
        # Audit de sécurité du conteneur
        local container_issues=0
        
        # Vérification utilisateur root
        local user=$(get_container_field "$cid" '{{.Config.User}}')
        local uid_only="${user%%:*}"
        if [[ -z "$user" || "$uid_only" == "0" || "$user" == "root" ]]; then
            ((containers_with_root++))
            ((container_issues++))
        fi
        
        # Vérification mode privilégié
        local privileged=$(get_container_field "$cid" '{{.HostConfig.Privileged}}')
        if [[ "$privileged" == "true" ]]; then
            ((containers_privileged++))
            ((container_issues++))
        fi
        
        # Vérification socket Docker
        local volumes=$(get_container_field "$cid" '{{json .Mounts}}')
        if echo "$volumes" | grep -q "/var/run/docker.sock"; then
            ((containers_with_docker_socket++))
            ((container_issues++))
        fi
        
        # Vérification namespace PID
        local pid_mode=$(get_container_field "$cid" '{{.HostConfig.PidMode}}')
        if [[ "$pid_mode" == "host" ]]; then
            ((containers_with_host_pid++))
            ((container_issues++))
        fi
        
        # Vérification mode réseau host
        local network_mode=$(get_container_field "$cid" '{{.HostConfig.NetworkMode}}')
        if [[ "$network_mode" == "host" ]]; then
            ((containers_with_host_network++))
            ((container_issues++))
        fi
        
        # Vérification montages sensibles
        if echo "$volumes" | grep -qE "/(etc|root|home|boot|dev|sys|proc)\"" || echo "$volumes" | grep -qE "\.env\"|\.env\.|/\.env\""; then
            ((containers_with_sensitive_mounts++))
            ((container_issues++))
        fi
        
        # Vérification variables sensibles
        local all_env=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}')
        local all_labels=$(get_container_field "$cid" '{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}')
        if detect_sensitive_data "$all_env" >/dev/null 2>&1 || detect_sensitive_data "$all_labels" >/dev/null 2>&1; then
            ((containers_with_sensitive_vars++))
            ((container_issues++))
        fi
        
        # Vérification capabilities dangereuses
        local cap_add=$(get_container_field "$cid" '{{.HostConfig.CapAdd}}')
        if echo "$cap_add" | grep -qiE "SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|SYS_BOOT|ALL"; then
            ((containers_with_dangerous_caps++))
            ((container_issues++))
        fi
        
        # Vérification no-new-privileges
        local security_opt=$(get_container_field "$cid" '{{.HostConfig.SecurityOpt}}')
        if ! echo "$security_opt" | grep -q "no-new-privileges:true"; then
            ((containers_without_no_new_privs++))
        fi
        
        # Vérification devices dangereux
        local devices=$(get_container_field "$cid" '{{range .HostConfig.Devices}}{{.PathOnHost}}{{println}}{{end}}')
        if echo "$devices" | grep -qE "/dev/(sd|hd|nvme|vd|xvd|kmsg|mem|kmem)"; then
            ((containers_with_dangerous_devices++))
            ((container_issues++))
        fi
        
        # Vérification risque cgroups
        if [[ "$privileged" == "true" ]] || \
           echo "$cap_add" | grep -qiE "SYS_ADMIN|ALL" || \
           (echo "$volumes" | grep -q '"/sys/fs/cgroup"' && echo "$volumes" | grep -q '"RW":true'); then
            ((containers_with_cgroup_access++))
            ((container_issues++))
        fi
        
        # Vérification credentials cloud
        if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.aws -o -d /root/.config/gcloud -o -d /root/.azure" 2>/dev/null; then
            ((containers_with_cloud_creds++))
            ((container_issues++))
        fi
        
        # Vérification Seccomp désactivé
        if echo "$security_opt" | grep -q "seccomp=unconfined"; then
            ((containers_with_seccomp_disabled++))
            ((container_issues++))
        fi
        
        # Vérification limites ressources
        local mem_limit=$(get_container_field "$cid" '{{.HostConfig.Memory}}')
        local cpu_quota=$(get_container_field "$cid" '{{.HostConfig.CpuQuota}}')
        if [[ "$mem_limit" == "0" ]] || [[ "$cpu_quota" == "-1" ]] || [[ "$cpu_quota" == "0" ]]; then
            ((containers_with_unlimited_resources++))
            ((container_issues++))
        fi
        
        # Vérification tag :latest
        local image_full=$(get_container_field "$cid" '{{.Config.Image}}')
        if echo "$image_full" | grep -qE ':latest$|^[^:]+$'; then
            ((containers_with_latest_tag++))
            ((container_issues++))
        fi
        
        # Vérification PIDs limit
        local pids_limit=$(get_container_field "$cid" '{{.HostConfig.PidsLimit}}')
        if [[ "$pids_limit" == "0" ]] || [[ "$pids_limit" == "-1" ]] || [[ -z "$pids_limit" ]]; then
            ((containers_without_pids_limit++))
            ((container_issues++))
        fi
        
        # Vérification Ulimits
        local ulimits=$(get_container_field "$cid" '{{.HostConfig.Ulimits}}')
        if [[ "$ulimits" == "[]" ]] || [[ "$ulimits" == "<no value>" ]] || [[ -z "$ulimits" ]]; then
            ((containers_without_ulimits++))
        fi
        
        # Vérification Healthcheck
        local healthcheck=$(get_container_field "$cid" '{{.Config.Healthcheck}}' 2>/dev/null)
        if [[ "$healthcheck" == "<no value>" ]] || [[ "$healthcheck" == "null" ]] || [[ -z "$healthcheck" ]]; then
            ((containers_without_healthcheck++))
        fi
        
        # Vérification Logging
        local log_driver=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Type}}')
        if [[ "$log_driver" == "none" ]]; then
            ((containers_with_no_logging++))
            ((container_issues++))
        fi
        
        # Comptage total des problèmes
        total_security_issues=$((total_security_issues + container_issues))
        
        if [[ $container_issues -eq 0 ]]; then
            ((containers_secure++))
        fi
    done
    
    # Affichage de l'audit de sécurité
    if [[ $running_count -gt 0 ]]; then
        print_subsection "Audit de Sécurité"
        echo -e "  ${LBLUE}[+]${NC} Conteneurs analysés : ${LBLUE}$running_count${NC}"
        echo -e "  ${DGRAY}├─${NC} ${LGREEN}Conteneurs sécurisés${NC} : $containers_secure"
        echo -e "  ${DGRAY}└─${NC} ${LRED}Conteneurs avec alertes${NC} : $((running_count - containers_secure))"
        echo
        
        if [[ $total_security_issues -gt 0 ]]; then
            print_subsection "Problèmes détectés"
            
            [[ $containers_with_root -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_root${NC} conteneur(s) exécuté(s) en root"
            [[ $containers_privileged -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_privileged${NC} conteneur(s) en mode privilégié"
            [[ $containers_with_docker_socket -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_docker_socket${NC} conteneur(s) avec accès au socket Docker ${LRED}[CRITIQUE]${NC}"
            [[ $containers_with_host_pid -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_host_pid${NC} conteneur(s) avec namespace PID host"
            [[ $containers_with_host_network -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_host_network${NC} conteneur(s) en mode réseau host"
            [[ $containers_with_sensitive_mounts -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_sensitive_mounts${NC} conteneur(s) avec montages système sensibles"
            [[ $containers_with_sensitive_vars -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_sensitive_vars${NC} conteneur(s) avec variables sensibles exposées ${LRED}[CREDENTIALS]${NC}"
            [[ $containers_with_dangerous_caps -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_dangerous_caps${NC} conteneur(s) avec capabilities DANGEREUSES ${LRED}[CAP_SYS_ADMIN, etc.]${NC}"
            [[ $containers_without_no_new_privs -gt 0 ]] && echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$containers_without_no_new_privs${NC} conteneur(s) sans flag no-new-privileges ${YELLOW}[SUID/SGID]${NC}"
            [[ $containers_with_dangerous_devices -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_dangerous_devices${NC} conteneur(s) avec devices CRITIQUES exposés ${LRED}[/dev/sda, /dev/mem]${NC}"
            [[ $containers_with_cgroup_access -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_cgroup_access${NC} conteneur(s) avec config risque cgroups ${LRED}[CONTAINER ESCAPE]${NC}"
            [[ $containers_with_cloud_creds -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_cloud_creds${NC} conteneur(s) avec credentials cloud détectés ${LRED}[AWS/GCP/Azure]${NC}"
            [[ $containers_with_seccomp_disabled -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_seccomp_disabled${NC} conteneur(s) avec Seccomp DÉSACTIVÉ ${LRED}[ALL SYSCALLS]${NC}"
            [[ $containers_with_unlimited_resources -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_unlimited_resources${NC} conteneur(s) avec ressources ILLIMITÉES ${LRED}[DoS RISK]${NC}"
            [[ $containers_with_latest_tag -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_latest_tag${NC} conteneur(s) avec tag :latest ${LRED}[NON-DETERMINISTIC]${NC}"
            [[ $containers_without_pids_limit -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_without_pids_limit${NC} conteneur(s) sans PIDs limit ${LRED}[FORK BOMB]${NC}"
            [[ $containers_without_ulimits -gt 0 ]] && echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$containers_without_ulimits${NC} conteneur(s) sans ulimits configurés"
            [[ $containers_without_healthcheck -gt 0 ]] && echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$containers_without_healthcheck${NC} conteneur(s) sans healthcheck"
            [[ $containers_with_no_logging -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_no_logging${NC} conteneur(s) avec logging DÉSACTIVÉ ${LRED}[NO AUDIT]${NC}"
            
            echo
            echo -e "  ${LRED}Total : $total_security_issues alerte(s) de sécurité${NC}"
            echo
            
            # Section recommandations de mitigation
            print_section "RECOMMANDATIONS DE SÉCURITÉ"
            echo
            
            if [[ $containers_privileged -gt 0 ]] || [[ $containers_with_docker_socket -gt 0 ]] || [[ $containers_with_dangerous_caps -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Vecteurs d'échappement de conteneur détectés :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --security-opt=no-new-privileges${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --cap-drop=ALL --cap-add=<MINIMAL_CAPS>${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --read-only${NC} (système de fichiers racine en lecture seule)"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Éviter --privileged et le montage du socket Docker${NC}"
                echo
            fi
            
            if [[ $containers_with_root -gt 0 ]]; then
                echo -e "  ${YELLOW}[HAUTE]${NC} Conteneurs exécutés en root :"
                echo -e "      ${DGRAY}├─${NC} Ajouter 'USER <non-root>' dans le Dockerfile"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --user <uid>:<gid>${NC}"
                echo
            fi
            
            if [[ $containers_with_seccomp_disabled -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Seccomp désactivé :"
                echo -e "      ${DGRAY}├─${NC} Activer un profil Seccomp personnalisé"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --security-opt seccomp=/path/to/profile.json${NC}"
                echo
            fi
            
            if [[ $containers_with_unlimited_resources -gt 0 ]]; then
                echo -e "  ${YELLOW}[HAUTE]${NC} Ressources illimitées (DoS) :"
                echo -e "      ${DGRAY}├─${NC} ${YELLOW}Risque de déni de service par épuisement RAM/CPU${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --memory=2g --memory-swap=2g${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --cpus=2 --cpu-shares=1024${NC}"
                echo
            fi
            
            if [[ $containers_with_latest_tag -gt 0 ]]; then
                echo -e "  ${YELLOW}[HAUTE]${NC} Tag :latest utilisé :"
                echo -e "      ${DGRAY}├─${NC} ${YELLOW}Déploiements non reproductibles, versions non traçables${NC}"
                echo -e "      ${DGRAY}├─${NC} Utiliser des tags versionnés spécifiques"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Exemple : nginx:1.21.6 au lieu de nginx:latest${NC}"
                echo
            fi
            
            if [[ $containers_without_pids_limit -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} PIDs limit non défini (fork bomb) :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque de fork bomb paralysant le système${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --pids-limit=100${NC}"
                echo
            fi
            
            if [[ $containers_with_no_logging -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Logging désactivé :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Aucune traçabilité en cas d'incident${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --log-driver=json-file${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --log-opt max-size=10m --log-opt max-file=3${NC}"
                echo
            fi
            
            if [[ $containers_with_cloud_creds -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Credentials cloud exposés :"
                echo -e "      ${DGRAY}├─${NC} Utiliser les IAM Roles (AWS) ou Workload Identity (GCP)"
                echo -e "      ${DGRAY}├─${NC} Utiliser des secrets managers (Vault, AWS Secrets Manager)"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}NE JAMAIS monter ~/.aws ou ~/.config/gcloud${NC}"
                echo
            fi
            
            if [[ $containers_with_cgroup_access -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Configuration à risque pour manipulation cgroups :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque d'échappement de conteneur via release_agent (CVE-2022-0492)${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Supprimer CAP_SYS_ADMIN : docker run --cap-drop=SYS_ADMIN${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Activer AppArmor/SELinux : docker run --security-opt apparmor=docker-default${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Ne PAS utiliser --privileged${NC}"
                echo
            fi
            
            echo -e "  ${LBLUE}[INFO]${NC} Ressources utiles :"
            echo -e "      ${DGRAY}├─${NC} ANSSI - Recommandations Docker : https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker"
            echo -e "      ${DGRAY}├─${NC} OWASP Docker Security : https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
            echo -e "      ${DGRAY}└─${NC} Docker Security Best Practices : https://docs.docker.com/engine/security/"
            echo
        else
            echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Aucun problème de sécurité majeur détecté${NC}"
        fi
    fi
    
    exit 0
}

# Exécution du main
main "$@"
