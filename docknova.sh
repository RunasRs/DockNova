#!/usr/bin/env bash

# =============================================================================
# DockNova - Audit de Sécurité Docker Professionnel
# Version: 2.0 (Optimisée)
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
LYELLOW='\033[1;33m'
ORANGE='\033[38;5;208m'
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
readonly SCRIPT_NAME="DockNova"

# Options de ligne de commande

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
    echo -e "${LGREEN}${SCRIPT_NAME}${NC} v${VERSION} - Audit de Sécurité Docker Professionnel"
    echo ""
    echo -e "${LBLUE}USAGE:${NC}"
    echo -e "    $(basename "$0") [OPTIONS]"
    echo ""
    echo -e "${LBLUE}OPTIONS:${NC}"
    echo -e "    -h, --help              Afficher cette aide"
    echo -e "    --no-color              Désactiver les couleurs"
    echo ""
    echo -e "${LBLUE}EXEMPLES:${NC}"
    echo -e "    $(basename "$0")                          # Audit standard"
    echo ""
    echo -e "${LBLUE}RÉFÉRENCES:${NC}"
    echo -e "    - ANSSI Docker: https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker"
    echo -e "    - OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
    echo -e "    - Docker Security Best Practices: https://docs.docker.com/engine/security/"
    echo ""
    echo -e "${LBLUE}NOTE:${NC}"
    echo -e "    - Utilise uniquement Bash et Docker/Podman"
}

# =============================================================================
# DÉTECTION ET VALIDATION
# =============================================================================

# Variable globale pour la commande Docker/Podman
DOCKER_CMD=""

detect_container_engine() {
    if command -v docker &> /dev/null && docker info &> /dev/null 2>&1; then
        DOCKER_CMD="docker"
        return 0
    fi
    
    if command -v podman &> /dev/null && podman info &> /dev/null 2>&1; then
        DOCKER_CMD="podman"
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
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability SYS_PTRACE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Exploitation : Injection de code dans les processus de l'hôte${NC}"
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
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability DAC_OVERRIDE/DAC_READ_SEARCH ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Bypass des permissions de fichiers"
            echo -e "      ${DGRAY}└─${NC} Permet de lire/écrire des fichiers sans vérification des permissions"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "NET_ADMIN"; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability NET_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Configuration réseau, sniffing, spoofing"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet de créer des interfaces réseau, modifier les routes, iptables${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "NET_RAW"; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability NET_RAW ajoutée${NC}"
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
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability SYS_TIME ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Modification de l'horloge système"
            echo -e "      ${DGRAY}└─${NC} Peut affecter les certificats, logs, et synchronisation"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "SYS_CHROOT"; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability SYS_CHROOT ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Échappement via chroot"
            echo -e "      ${DGRAY}└─${NC} Combiné avec d'autres caps, peut faciliter l'échappement"
            ((warnings++))
            dangerous_caps_found=true
        fi
        if echo "$cap_add" | grep -qiE "MKNOD"; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capability MKNOD ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Création de périphériques bloc/caractères"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mknod /tmp/sda b 8 0${NC}"
            ((warnings++))
            dangerous_caps_found=true
        fi
        
        if [[ "$dangerous_caps_found" == "false" ]]; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Capabilities ajoutées : $cap_add${NC}"
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
        
        # IMPORTANT : Le mode RO n'est PAS une protection réelle contre l'API Docker
        # Les permissions Unix ro ne bloquent pas les requêtes HTTP (POST/DELETE/PUT) sur un socket Unix
        # Monter le socket Docker = accès à l'API Docker = contrôle équivalent à root Docker
        if [[ "$socket_mode" == "true" ]]; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Docker monté (mode read-write)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Escalade de privilèges & échapement de conteneur possible${NC}"
            echo -e "      ${DGRAY}├─${NC} Le conteneur peut créer/modifier/supprimer des conteneurs sur l'hôte"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            [[ -n "$socket_group" ]] && echo -e "      ${DGRAY}├─${NC} Groupe : ${LBLUE}$socket_group${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LRED}RW (read-write)${NC}"
            ((warnings++))
        elif [[ "$socket_mode" == "false" ]]; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Docker monté (mode read-only déclaré)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Escalade de privilèges & échapement de conteneur possible${NC}"
            echo -e "      ${DGRAY}├─${NC} Les permissions Unix ro ne bloquent pas les requêtes HTTP (POST/DELETE/PUT)"
            echo -e "      ${DGRAY}├─${NC} Le conteneur peut toujours utiliser l'API REST Docker (équivalent root Docker)"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage déclaré : ${LYELLOW}RO (non protecteur)${NC}"
            ((warnings++))
        else
            # Cas où socket_mode n'est pas défini ou a une valeur inattendue
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Docker monté${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Accès à l'API Docker = contrôle équivalent à root Docker${NC}"
            echo -e "      ${DGRAY}├─${NC} Mode montage : ${LBLUE}$socket_mode${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            ((warnings++))
        fi
        docker_socket_found=true
    fi
    
    # 4.2. Vérifier le socket Podman
    if echo "$volumes" | grep -q "/run/podman/podman.sock"; then
        socket_mode=$(get_container_field "$cid" '{{range .Mounts}}{{if eq .Destination "/run/podman/podman.sock"}}{{.RW}}{{end}}{{end}}')
        
        local socket_perms=$($DOCKER_CMD exec "$cid" sh -c "ls -l /run/podman/podman.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        
        # IMPORTANT : Le mode RO n'est PAS une protection réelle contre l'API Podman
        # Les permissions Unix ro ne bloquent pas les requêtes HTTP (POST/DELETE/PUT) sur un socket Unix
        # Monter le socket Podman = accès à l'API Podman = contrôle équivalent à root Podman
        if [[ "$socket_mode" == "true" ]]; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Podman monté (mode read-write)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Contrôle total du moteur Podman${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LRED}RW (read-write)${NC}"
            ((warnings++))
        elif [[ "$socket_mode" == "false" ]]; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Podman monté (mode read-only déclaré)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Le mode RO ne protège PAS contre l'API Podman${NC}"
            echo -e "      ${DGRAY}├─${NC} Les permissions Unix ro ne bloquent pas les requêtes HTTP (POST/DELETE/PUT)"
            echo -e "      ${DGRAY}├─${NC} Le conteneur peut toujours utiliser l'API REST Podman (équivalent root Podman)"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage déclaré : ${LYELLOW}RO (non protecteur)${NC}"
            ((warnings++))
        else
            echo -e "  ${LRED}[x]${NC} ${LRED}Socket Podman monté${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Accès à l'API Podman = contrôle équivalent à root Podman${NC}"
            echo -e "      ${DGRAY}├─${NC} Mode montage : ${LBLUE}$socket_mode${NC}"
            [[ -n "$socket_perms" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$socket_perms${NC}"
            ((warnings++))
        fi
        docker_socket_found=true
    fi
    
    # 4.3. Vérifier si d'autres répertoires Docker sont montés
    if echo "$volumes" | grep -q "/var/lib/docker"; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Répertoire Docker monté (/var/lib/docker)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Accès direct aux données Docker (images, volumes, conteneurs)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LRED}Possibilité de manipulation des données Docker${NC}"
        ((warnings++))
        docker_socket_found=true
    fi
    
    # 4.4. Détecter les variables d'environnement Docker exposées
    local docker_host_var=$(get_container_field "$cid" '{{range .Config.Env}}{{println .}}{{end}}' | grep "DOCKER_HOST=" || echo "")
    if [[ -n "$docker_host_var" ]]; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Variable DOCKER_HOST détectée : $docker_host_var${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LRED}Accès potentiel à un daemon Docker distant${NC}"
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
                echo -e "  ${LYELLOW}[!]${NC} Socket Docker accessible DANS le conteneur"
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
        echo -e "  ${LYELLOW}[!]${NC} Docker CLI installé dans le conteneur"
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
        echo -e "  ${LYELLOW}[!]${NC} Podman CLI installé dans le conteneur"
        echo -e "      ${DGRAY}└─${NC} Version : ${LBLUE}$podman_version${NC}"
    fi
    
    if [[ "$docker_socket_found" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun accès au socket Docker/Podman détecté"
    fi
    
    # 5. Namespace PID
    if [[ "$pid_mode" == "host" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Namespace PID partagé avec l'hôte (--pid=host)${NC}"
        ((warnings++))
    fi
    
    # 6. Namespace IPC
    if [[ "$ipc_mode" == "host" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} Namespace IPC partagé avec l'hôte (--ipc=host)"
        ((warnings++))
    fi
    
    # 7. Mode réseau
    if [[ "$network_mode" == "host" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Mode réseau host (--network=host)${NC}"
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
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}AppArmor désactivé${NC}"
            ((warnings++))
        fi
        if echo "$security_opt" | grep -q "label=disable"; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}SELinux désactivé${NC}"
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
    
    if echo "$volumes" | grep -qE "\.env\"|\.env\.|/\.env\""; then
        echo -e "  ${LRED}[x]${NC} ${LRED}Fichier .env monté - Risque d'exposition de secrets${NC}"
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
        echo -e "  ${LRED}[x]${NC} ${LRED}$env_count variable(s) d'environnement sensible(s) détectée(s)${NC}"
        ((warnings++))
        ((sensitive_count += env_count))
    fi
    
    local sensitive_labels=$(detect_sensitive_data "$all_labels")
    if [[ -n "$sensitive_labels" ]]; then
        local label_count=$(echo "$sensitive_labels" | wc -l)
        echo -e "  ${LYELLOW}[!]${NC} $label_count label(s) avec informations sensibles détecté(s)"
        ((warnings++))
        ((sensitive_count += label_count))
    fi
    
    if [[ $sensitive_count -gt 0 ]]; then
        echo -e "      ${DGRAY}└─${NC} ${LRED}Total : $sensitive_count donnée(s) sensible(s) exposée(s)${NC}"
    fi
    
    # 12. Flag no-new-privileges
    local no_new_privs=$(echo "$security_opt" | grep -o "no-new-privileges:true" || echo "")
    if [[ -z "$no_new_privs" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Flag --security-opt=no-new-privileges non défini${NC}"
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
                echo -e "  ${LYELLOW}[!]${NC} Device TTY/Console exposé : $device"
                echo -e "      ${DGRAY}└─${NC} Peut permettre de capturer ou injecter des entrées clavier"
                ((warnings++))
                critical_device=true
            elif [[ "$device" == "/dev/fuse" ]]; then
                echo -e "  ${LYELLOW}[!]${NC} Device FUSE exposé : $device"
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
                echo -e "  ${LYELLOW}[!]${NC} SYSCTL réseau modifié : $sysctl"
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
            echo -e "      ${DGRAY}├─${NC} ${LRED}Raison : $reason${NC}"
        done
        echo -e "      ${DGRAY}└─${NC} ${LRED}PoC : https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/${NC}"
        ((warnings++))
    fi
    
    # 17. Kernel vulnérable
    local kernel_version=$($DOCKER_CMD info 2>/dev/null | grep "Kernel Version" | cut -d: -f2 | xargs)
    if [[ -n "$kernel_version" ]]; then
        local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
        local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
        if [[ "$kernel_major" -lt 4 ]]; then
            echo -e "  ${LRED}[x]${NC} ${LRED}Kernel hôte OBSOLÈTE : $kernel_version${NC}"
            echo -e "      ${DGRAY}└─${NC} Mise à jour du kernel de l'hôte Docker fortement recommandée"
            ((warnings++))
        elif [[ "$kernel_major" -eq 4 ]] && [[ "$kernel_minor" -lt 15 ]]; then
            echo -e "  ${LYELLOW}[!]${NC} Kernel hôte potentiellement vulnérable : $kernel_version"
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
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}RAM illimitée - Risque de déni de service (DoS)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Exploitation : Memory exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --memory=<limit> (ex: --memory=2g)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    if [[ "$cpu_quota" == "-1" ]] || [[ "$cpu_quota" == "0" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}CPU illimité - Risque de monopolisation CPU${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Exploitation : CPU exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --cpus=<limit> (ex: --cpus=2)${NC}"
        ((warnings++))
        resource_unlimited=true
    fi
    
    # 21. Tag :latest (ANSSI/OWASP - HAUTE pour reproductibilité et traçabilité)
    local image_full=$(get_container_field "$cid" '{{.Config.Image}}')
    if echo "$image_full" | grep -qE ':latest$|^[^:]+$'; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Image avec tag :latest ou sans tag${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque : Déploiements non-déterministes, versions non traçables${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Image : $image_full${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser des tags versionnés (ex: nginx:1.21.6)${NC}"
        ((warnings++))
    fi
    
    # 22. PIDs limit (CIS - HAUTE pour prévenir fork bomb)
    local pids_limit=$(get_container_field "$cid" '{{.HostConfig.PidsLimit}}')
    if [[ "$pids_limit" == "0" ]] || [[ "$pids_limit" == "-1" ]] || [[ -z "$pids_limit" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}PIDs limit non défini - Risque de fork bomb${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Exploitation : :(){ :|:& };: (fork bomb)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --pids-limit=100${NC}"
        ((warnings++))
    fi
    
    # 23. Ulimits (ANSSI - MOYENNE)
    local ulimits=$(get_container_field "$cid" '{{.HostConfig.Ulimits}}')
    if [[ "$ulimits" == "[]" ]] || [[ "$ulimits" == "<no value>" ]] || [[ -z "$ulimits" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Ulimits non configurés (utilise les valeurs par défaut de l'hôte)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque : Épuisement des file descriptors/processus${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --ulimit nofile=1024:2048${NC}"
        ((warnings++))
    fi
    
    # 24. Healthcheck (OWASP/CIS - MOYENNE pour monitoring)
    local healthcheck=$(get_container_field "$cid" '{{.Config.Healthcheck}}' 2>/dev/null)
    if [[ "$healthcheck" == "<no value>" ]] || [[ "$healthcheck" == "null" ]] || [[ -z "$healthcheck" ]] || [[ "$healthcheck" == "&lt;no value&gt;" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Healthcheck non défini${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Pas de monitoring automatique de l'état du service${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : HEALTHCHECK CMD curl -f http://localhost/ || exit 1${NC}"
        ((warnings++))
    fi
    
    # 25. Logging driver (ANSSI/CIS - HAUTE pour traçabilité)
    local log_driver=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Type}}')
    if [[ "$log_driver" == "none" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Logging désactivé (driver: none)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Aucune traçabilité des événements${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser json-file, syslog, ou journald${NC}"
        ((warnings++))
    elif [[ "$log_driver" == "json-file" ]]; then
        local log_max_size=$(get_container_field "$cid" '{{.HostConfig.LogConfig.Config.max-size}}')
        if [[ -z "$log_max_size" ]] || [[ "$log_max_size" == "<no value>" ]]; then
            echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Logs sans limite de taille (risque de saturation disque)${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --log-opt max-size=10m --log-opt max-file=3${NC}"
            ((warnings++))
        fi
    fi
    
    # 26. Restart policy (OWASP - BASSE pour résilience)
    local restart_policy=$(get_container_field "$cid" '{{.HostConfig.RestartPolicy.Name}}')
    if [[ "$restart_policy" == "no" ]] || [[ -z "$restart_policy" ]]; then
        echo -e "  ${LBLUE}[i]${NC} ${LYELLOW}Restart policy non configuré (le conteneur ne redémarrera pas automatiquement)${NC}"
    elif [[ "$restart_policy" == "always" ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}Restart policy 'always' (peut masquer des crashs répétés)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Considérer 'on-failure' avec un max-retry${NC}"
    fi
    
    # 27. OOM Score adjustment (CIS - BASSE)
    local oom_score=$(get_container_field "$cid" '{{.HostConfig.OomScoreAdj}}')
    if [[ -n "$oom_score" ]] && [[ "$oom_score" != "<no value>" ]] && [[ "$oom_score" -lt -500 ]]; then
        echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}OOM Score très bas ($oom_score) - Le conteneur sera protégé du OOM killer${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Peut affecter la stabilité du système en cas de pression mémoire${NC}"
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
        echo -e "  ${LYELLOW}[!]${NC} $warnings alerte(s) de sécurité détectée(s)"
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
    local title_color="$2"  # LGREEN ou LYELLOW
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
    
    echo ""
    printf "  ${LYELLOW}%-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s${NC}\n" "ID" "NOM" "IMAGE" "STATUS" "TYPE" "SOURCE" "PORTS"
    echo -e "  ${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Récupérer toutes les infos en un seul appel par conteneur
    $DOCKER_CMD ps $cmd_filter --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" 2>/dev/null | while IFS='|' read -r cid name image status ports; do
        # Récupérer les infos supplémentaires nécessaires
        local mounts_info=$(get_container_field "$cid" '{{range .Mounts}}1{{end}}|{{index .Config.Labels "com.docker.compose.project"}}')
        local mounts_count=$(echo "$mounts_info" | cut -d'|' -f1 | wc -c)
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
        
        # Colorer le statut
        local status_display="$status"
        if echo "$status" | grep -qiE "^up|running"; then
            status_display="${LGREEN}$status${NC}"
        elif echo "$status" | grep -qiE "^exited|stopped"; then
            status_display="${LRED}$status${NC}"
        fi
        
        printf "  %-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s\n" "$cid" "$name" "$image" "$status_display" "$type" "$source" "$ports"
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
    
    echo -e "Ports exposés : (${LBLUE}Docker${NC} → ${LGREEN}Hôte${NC})"
    local PORTS=$(get_container_field "$cid" '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} -> {{(index $conf 0).HostPort}} {{end}}{{end}}')
    
    if [[ -z "$PORTS" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun port exposé sur l'hôte"
    else
        get_container_field "$cid" '{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} {{(index $conf 0).HostIp}}:{{(index $conf 0).HostPort}}{{println}}{{end}}{{end}}' | while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local port_container="${line%% *}"
            local host_mapping="${line#* }"
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
            local IP=$(get_container_field "$cid" "{{range .NetworkSettings.Networks}}{{if eq \"$NET\" \"$NET\"}}{{.IPAddress}}{{end}}{{end}}")
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
        echo -e "Type de conteneur : ${LGREEN}STATEFUL${NC} (avec persistance de données)"
        echo -e "  ${LBLUE}[+]${NC} $MOUNTS_COUNT montage(s) détecté(s)"
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
                echo -e "      ${DGRAY}├─${NC} Mode : ${LYELLOW}read-write${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} Mode : ${LBLUE}read-only${NC}"
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

# Fonction principale d'inspection d'un conteneur
inspect_container() {
    local cid="$1"
    local name=$(get_container_field "$cid" '{{.Name}}' | sed 's|/||')
    local image=$(get_container_field "$cid" '{{.Config.Image}}')
    local status=$(get_container_field "$cid" '{{.State.Status}}')
    local uptime=$(get_container_field "$cid" '{{.State.StartedAt}}')
    uptime=$(echo "$uptime" | sed 's/:[0-9][0-9]\..*Z$//' | sed 's/Z$//')
    
    print_subsection "$name ($cid)"
    echo "Image : $image"
    # Colorer le statut selon son état
    local status_color="${LGREEN}"
    [[ "$status" == "exited" ]] && status_color="${LRED}"
    echo -e "Status : ${status_color}$status${NC} (démarré : $uptime)"
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
    echo
    
    check_security "$cid" "$name"
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
            --no-color)
                # Désactiver les couleurs (redéfinir toutes les variables)
                for color_var in RED LRED GREEN LGREEN LYELLOW ORANGE BLUE LBLUE CYAN LCYAN MAGENTA LMAGENTA DGRAY NC; do
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
    echo -e "${LBLUE}║${NC}                       ${LYELLOW}Inventaire et Audit de Sécurité Docker${NC}                        ${LBLUE}║${NC}"
    echo -e "${LBLUE}║${NC}                                                                                     ${LBLUE}║${NC}"
    echo -e "${LBLUE}╚═════════════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    # Détection Docker/Podman
    detect_container_engine || exit 1
    
    log_info "Moteur de conteneurs: ${LGREEN}$DOCKER_CMD${NC}"
    
    # 0. Informations système Docker
    print_section "INFO DOCKER"
    
    echo -e "${LBLUE}[+]${NC} Informations système :"
    echo ""
    
    # Hostname
    local hostname=$(hostname)
    echo -e "  ${DGRAY}┌─${NC} ${LBLUE}Hostname${NC} : ${LGREEN}$hostname${NC}"
    
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
    local daemon_info_lines
    mapfile -t daemon_info_lines < <($DOCKER_CMD info 2>/dev/null | grep -E "Server Version|Storage Driver|Kernel Version|Operating System|CPUs|Total Memory")
    local daemon_count=${#daemon_info_lines[@]}
    local daemon_idx=0
    for line in "${daemon_info_lines[@]}"; do
        IFS=: read -r key value <<< "$line"
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        ((daemon_idx++))
        if [[ $daemon_idx -eq 1 ]]; then
            echo -e "  ${DGRAY}┌─${NC} ${LBLUE}$key${NC} : ${LGREEN}$value${NC}"
        elif [[ $daemon_idx -eq $daemon_count ]]; then
            echo -e "  ${DGRAY}└─${NC} ${LBLUE}$key${NC} : ${LGREEN}$value${NC}"
        else
            echo -e "  ${DGRAY}├─${NC} ${LBLUE}$key${NC} : ${LGREEN}$value${NC}"
        fi
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
    
    # Recalculer les comptages pour le résumé (si pas déjà fait)
    local running_count_summary=${#running_containers[@]}
    local stopped_count_summary=${#stopped_containers[@]}
    local total_count_summary=$((running_count_summary + stopped_count_summary))
    
    # Comptage des conteneurs stateless vs stateful et compose vs manuel
    local stateless_count=0
    local stateful_count=0
    local compose_count=0
    local manual_count=0
    
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
    
    # Analyser tous les conteneurs (running et stopped)
    for cid in "${running_containers[@]}" "${stopped_containers[@]}"; do
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
        
        # Audit de sécurité du conteneur
        local container_issues=0
        local is_running=false
        # Vérifier si le conteneur est en cours d'exécution
        for running_cid in "${running_containers[@]}"; do
            if [[ "$cid" == "$running_cid" ]]; then
                is_running=true
                break
            fi
        done
        
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
        
        # Vérification credentials cloud (uniquement pour conteneurs en cours d'exécution)
        if [[ "$is_running" == "true" ]]; then
            if $DOCKER_CMD exec "$cid" sh -c "test -d /root/.aws -o -d /root/.config/gcloud -o -d /root/.azure" 2>/dev/null; then
                ((containers_with_cloud_creds++))
                ((container_issues++))
            fi
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
    echo -e "  ${LGREEN}[+]${NC} Conteneurs actifs  : ${LGREEN}$running_count_summary${NC}"
    
    # Afficher la liste des conteneurs actifs
    if [[ $running_count_summary -gt 0 ]]; then
        local idx=0
        for cid in "${running_containers[@]}"; do
            local name=$(get_container_field "$cid" '{{.Name}}')
            name="${name#/}"  # Enlever le / au début si présent
            ((idx++))
            if [[ $idx -eq $running_count_summary ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$name${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$name${NC}"
            fi
        done
    fi
    
    if [[ $stopped_count_summary -gt 0 ]]; then
        echo -e "  ${LRED}[x]${NC} Conteneurs arrêtés : ${LRED}$stopped_count_summary${NC}"
        
        # Afficher la liste des conteneurs arrêtés
        local idx=0
        for cid in "${stopped_containers[@]}"; do
            local name=$(get_container_field "$cid" '{{.Name}}')
            name="${name#/}"  # Enlever le / au début si présent
            ((idx++))
            if [[ $idx -eq $stopped_count_summary ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LRED}$name${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LRED}$name${NC}"
            fi
        done
    fi
    
    echo
    
    print_subsection "Par type de données"
    local total_containers_type=$((stateless_count + stateful_count))
    echo -e "  ${LGREEN}[+]${NC} Type de conteneur : $total_containers_type"
    echo -e "      ${DGRAY}├─${NC} ${LBLUE}Stateless${NC} : $stateless_count ${DGRAY}(applicatifs sans persistance)${NC}"
    echo -e "      ${DGRAY}└─${NC} ${LGREEN}Stateful${NC} : $stateful_count ${DGRAY}(avec volumes de données ou montages)${NC}"
    echo
    
    print_subsection "Par méthode de création"
    local total_creation_method=$((compose_count + manual_count))
    echo -e "  ${LGREEN}[+]${NC} Fichiers de configuration et sources : $total_creation_method"
    echo -e "      ${DGRAY}├─${NC} ${LGREEN}Docker Compose${NC} : $compose_count"
    echo -e "      ${DGRAY}└─${NC} Manuel : $manual_count"
    echo
    
    print_subsection "Ressources Docker"
    # Utiliser docker system df pour obtenir les comptages cohérents
    local system_df_output=$($DOCKER_CMD system df 2>/dev/null)
    local total_images=$(echo "$system_df_output" | grep "^Images" | awk '{print $2}')
    local active_images=$(echo "$system_df_output" | grep "^Images" | awk '{print $3}')
    local total_volumes=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $3}')
    local active_volumes=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $4}')
    local total_networks=$($DOCKER_CMD network ls -q 2>/dev/null | wc -l)
    
    # Calculer les non utilisées (avec valeurs par défaut si vides)
    [[ -z "$total_images" ]] && total_images=0
    [[ -z "$active_images" ]] && active_images=0
    [[ -z "$total_volumes" ]] && total_volumes=0
    [[ -z "$active_volumes" ]] && active_volumes=0
    [[ -z "$total_networks" ]] && total_networks=0
    
    local unused_images=$((total_images - active_images))
    local unused_volumes=$((total_volumes - active_volumes))
    
    # Images
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
            if [[ $idx -eq ${#used_image_names[@]} ]] && [[ "$has_unused" == "false" ]]; then
                echo -e "      ${DGRAY}└─${NC} ${LGREEN}$img${NC}"
            else
                echo -e "      ${DGRAY}├─${NC} ${LGREEN}$img${NC}"
            fi
        done
    fi
    
    # Images non utilisées
    if [[ $unused_images -gt 0 ]]; then
        local unused_image_list
        mapfile -t unused_image_list < <($DOCKER_CMD system df -v 2>/dev/null | awk '/^Images space usage:/{flag=1; next} /^Containers space usage:/{flag=0} flag && NF>0 && $NF=="0" {print $1":"$2}' | grep -v '^$')
        if [[ ${#unused_image_list[@]} -gt 0 ]]; then
            local idx=0
            for img_name in "${unused_image_list[@]}"; do
                [[ -z "$img_name" ]] && continue
                ((idx++))
                if [[ $idx -eq ${#unused_image_list[@]} ]]; then
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}[!] $img_name${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}[!] $img_name${NC}"
                fi
            done
        fi
    fi
    
    # Volumes
    echo -e "  ${LGREEN}[+]${NC} Volumes : $total_volumes ${DGRAY}(${LGREEN}$active_volumes${DGRAY} montés, ${LYELLOW}$unused_volumes${DGRAY} non montés)${NC}"
    
    # Récupérer les volumes montés
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
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}[!] $vol${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}[!] $vol${NC}"
                fi
            done
        fi
    fi
    
    # Réseaux utilisés
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
        local has_unused_net=$([[ $unused_network_count -gt 0 ]] && echo "true" || echo "false")
        for net in "${used_networks[@]}"; do
            [[ -z "$net" ]] && continue
            ((idx++))
            if [[ $idx -eq ${#used_networks[@]} ]] && [[ "$has_unused_net" == "false" ]]; then
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
                    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}[!] $net${NC}"
                else
                    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}[!] $net${NC}"
                fi
            done
        fi
    fi
    
    echo
    
    # Affichage de l'audit de sécurité
    if [[ $total_count_summary -gt 0 ]]; then
        print_subsection "Audit de Sécurité"
        echo -e "  ${LGREEN}[+]${NC} Conteneurs analysés : $total_count_summary"
        echo -e "      ${DGRAY}├─${NC} Conteneurs sécurisés : $containers_secure"
        echo -e "      ${DGRAY}└─${NC} Conteneurs avec alertes : $((total_count_summary - containers_secure))"
        echo
        
        if [[ $total_security_issues -gt 0 ]]; then
            print_subsection "Problèmes détectés"
            
            [[ $containers_with_root -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_root${NC} conteneur(s) exécuté(s) en root"
            [[ $containers_privileged -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_privileged${NC} conteneur(s) en mode privilégié"
            [[ $containers_with_docker_socket -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_docker_socket${NC} conteneur(s) avec accès au socket Docker ${LRED}[CRITIQUE]${NC}"
            [[ $containers_with_host_pid -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_host_pid${NC} conteneur(s) avec namespace PID host ${ORANGE}[HAUTE]${NC}"
            [[ $containers_with_host_network -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_host_network${NC} conteneur(s) en mode réseau host ${ORANGE}[HAUTE]${NC}"
            [[ $containers_with_sensitive_mounts -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_sensitive_mounts${NC} conteneur(s) avec montages système sensibles"
            [[ $containers_with_sensitive_vars -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_sensitive_vars${NC} conteneur(s) avec variables sensibles exposées ${ORANGE}[HAUTE]${NC}"
            [[ $containers_with_dangerous_caps -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_dangerous_caps${NC} conteneur(s) avec capabilities DANGEREUSES ${LRED}[CAP_SYS_ADMIN, etc.]${NC}"
            [[ $containers_without_no_new_privs -gt 0 ]] && echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}$containers_without_no_new_privs${NC} conteneur(s) sans flag no-new-privileges ${LYELLOW}[SUID/SGID]${NC}"
            [[ $containers_with_dangerous_devices -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_dangerous_devices${NC} conteneur(s) avec devices CRITIQUES exposés ${LRED}[/dev/sda, /dev/mem]${NC}"
            [[ $containers_with_cgroup_access -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_cgroup_access${NC} conteneur(s) avec config risque cgroups ${LRED}[CONTAINER ESCAPE]${NC}"
            [[ $containers_with_cloud_creds -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_cloud_creds${NC} conteneur(s) avec credentials cloud détectés ${LRED}[AWS/GCP/Azure]${NC}"
            [[ $containers_with_seccomp_disabled -gt 0 ]] && echo -e "  ${LRED}[x]${NC} ${LRED}$containers_with_seccomp_disabled${NC} conteneur(s) avec Seccomp DÉSACTIVÉ ${LRED}[ALL SYSCALLS]${NC}"
            [[ $containers_with_unlimited_resources -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_unlimited_resources${NC} conteneur(s) avec ressources ILLIMITÉES ${ORANGE}[DoS RISK]${NC}"
            [[ $containers_with_latest_tag -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_latest_tag${NC} conteneur(s) avec tag :latest ${ORANGE}[NON-DETERMINISTIC]${NC}"
            [[ $containers_without_pids_limit -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_without_pids_limit${NC} conteneur(s) sans PIDs limit ${ORANGE}[FORK BOMB]${NC}"
            [[ $containers_without_ulimits -gt 0 ]] && echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}$containers_without_ulimits${NC} conteneur(s) sans ulimits configurés"
            [[ $containers_without_healthcheck -gt 0 ]] && echo -e "  ${LYELLOW}[!]${NC} ${LYELLOW}$containers_without_healthcheck${NC} conteneur(s) sans healthcheck"
            [[ $containers_with_no_logging -gt 0 ]] && echo -e "  ${ORANGE}[!]${NC} ${ORANGE}$containers_with_no_logging${NC} conteneur(s) avec logging DÉSACTIVÉ ${ORANGE}[NO AUDIT]${NC}"
            
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
            
            if [[ $containers_with_docker_socket -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Socket Docker/Podman monté - Vecteurs d'échappement de conteneur détectés :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Le mode RO n'est PAS une protection réelle contre l'API Docker/Podman${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Les permissions Unix ro ne bloquent pas les requêtes HTTP (POST/DELETE/PUT)${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Accès au socket = contrôle équivalent à root Docker/Podman${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Solution recommandée : NE PAS monter le socket${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Alternative : Utiliser un proxy API sécurisé qui limite les opérations autorisées${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Exemples de proxies : Docker Socket Proxy, Traefik avec filtres API${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Si nécessaire : User namespaces, AppArmor/SELinux, runtimes isolés (gVisor, Kata)${NC}"
                echo
            fi
            
            if [[ $containers_with_root -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Conteneurs exécutés en root :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque d'escalade de privilèges si échappement de conteneur${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Ajouter 'USER <non-root>' dans le Dockerfile${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --user <uid>:<gid>${NC}"
                echo
            fi
            
            if [[ $containers_with_sensitive_vars -gt 0 ]]; then
                echo -e "  ${ORANGE}[HAUTE]${NC} Variables sensibles exposées :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque d'exposition de credentials (passwords, tokens, API keys)${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Utiliser des secrets managers (Docker secrets, Vault, AWS Secrets Manager)${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --secret ou variables d'environnement via fichiers montés${NC}"
                echo
            fi
            
            if [[ $containers_without_no_new_privs -gt 0 ]]; then
                echo -e "  ${LYELLOW}[MOYENNE]${NC} Flag no-new-privileges absent :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque d'escalade via binaires SUID/SGID${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --security-opt=no-new-privileges${NC}"
                echo
            fi
            
            if [[ $containers_without_ulimits -gt 0 ]]; then
                echo -e "  ${LYELLOW}[MOYENNE]${NC} Ulimits non configurés :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque d'épuisement des file descriptors/processus${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --ulimit nofile=1024:2048${NC}"
                echo
            fi
            
            if [[ $containers_with_seccomp_disabled -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Seccomp désactivé :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Activer un profil Seccomp personnalisé${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --security-opt seccomp=/path/to/profile.json${NC}"
                echo
            fi
            
            if [[ $containers_with_unlimited_resources -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Ressources illimitées (DoS) :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque de déni de service par épuisement RAM/CPU${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --memory=2g --memory-swap=2g${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --cpus=2 --cpu-shares=1024${NC}"
                echo
            fi
            
            if [[ $containers_with_latest_tag -gt 0 ]]; then
                echo -e "  ${ORANGE}[HAUTE]${NC} Tag :latest utilisé :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Déploiements non reproductibles, versions non traçables${NC}"
                echo -e "      ${DGRAY}├─${NC} Utiliser des tags versionnés spécifiques"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Exemple : nginx:1.21.6 au lieu de nginx:latest${NC}"
                echo
            fi
            
            if [[ $containers_without_pids_limit -gt 0 ]]; then
                echo -e "  ${ORANGE}[HAUTE]${NC} PIDs limit non défini (fork bomb) :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Risque de fork bomb paralysant le système${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --pids-limit=100${NC}"
                echo
            fi
            
            if [[ $containers_with_no_logging -gt 0 ]]; then
                echo -e "  ${ORANGE}[HAUTE]${NC} Logging désactivé :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Aucune traçabilité en cas d'incident${NC}"
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
    
    # Section Recommandations d'optimisation
    local system_df_output=$($DOCKER_CMD system df 2>/dev/null)
    local total_images_opt=$(echo "$system_df_output" | grep "^Images" | awk '{print $2}')
    local active_images_opt=$(echo "$system_df_output" | grep "^Images" | awk '{print $3}')
    local total_volumes_opt=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $3}')
    local active_volumes_opt=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $4}')
    
    # Calculer les non utilisées (avec valeurs par défaut si vides)
    [[ -z "$total_images_opt" ]] && total_images_opt=0
    [[ -z "$active_images_opt" ]] && active_images_opt=0
    [[ -z "$total_volumes_opt" ]] && total_volumes_opt=0
    [[ -z "$active_volumes_opt" ]] && active_volumes_opt=0
    
    local unused_images_opt=$((total_images_opt - active_images_opt))
    local unused_volumes_opt=$((total_volumes_opt - active_volumes_opt))
    
    local images_reclaimable=$(echo "$system_df_output" | grep "^Images" | awk '{print $5}' || echo "")
    local containers_reclaimable=$(echo "$system_df_output" | grep "^Containers" | awk '{print $5}' || echo "")
    local volumes_reclaimable=$(echo "$system_df_output" | grep "^Local Volumes" | awk '{print $5}' || echo "")
    local build_cache_reclaimable=$(echo "$system_df_output" | grep "^Build Cache" | awk '{print $5}' || echo "")
    
    if [[ $unused_images_opt -gt 0 ]] || [[ $unused_volumes_opt -gt 0 ]] || [[ $stopped_count_summary -gt 0 ]]; then
        print_section "RECOMMANDATIONS D'OPTIMISATION"
        echo
        
        echo -e "  ${LBLUE}[OPTIMISATION]${NC} Libération d'espace disque :"
        
        if [[ $unused_images_opt -gt 0 ]] && [[ -n "$images_reclaimable" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker image prune -a${NC} ${DGRAY}(${LYELLOW}$unused_images_opt${DGRAY} image(s) · ${LGREEN}~$images_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        if [[ $unused_volumes_opt -gt 0 ]] && [[ -n "$volumes_reclaimable" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker volume prune${NC} ${DGRAY}(${LYELLOW}$unused_volumes_opt${DGRAY} volume(s) · ${LGREEN}~$volumes_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        
        if [[ $stopped_count_summary -gt 0 ]] && [[ -n "$containers_reclaimable" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker container prune${NC} ${DGRAY}(${LYELLOW}$stopped_count_summary${DGRAY} conteneur(s) · ${LGREEN}~$containers_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        if [[ -n "$build_cache_reclaimable" ]] && [[ "$build_cache_reclaimable" != "0B" ]] && [[ "$build_cache_reclaimable" != "0" ]]; then
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker builder prune${NC} ${DGRAY}(cache de build · ${LGREEN}~$build_cache_reclaimable${DGRAY} récupérables)${NC}"
        fi
        
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker network prune${NC} ${DGRAY}(supprimer les réseaux non utilisés)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker system prune -a --volumes${NC} ${DGRAY}(nettoyage complet - ${LRED}ATTENTION aux données${DGRAY})${NC}"
        echo
    fi
    
    exit 0
}

# Exécution du main
main "$@"
