#!/bin/bash

# =============================================================================
# Script d'inventaire et d'audit de sécurité Docker
# =============================================================================

# Couleurs style LinPEAS
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
readonly NC='\033[0m' # No Color

# Variable globale pour la commande Docker/Podman
DOCKER_CMD=""

# Fonction de détection Docker/Podman
detect_container_engine() {
    if command -v docker &> /dev/null; then
        if docker info &> /dev/null; then
            DOCKER_CMD="docker"
            return 0
        fi
    fi
    
    if command -v podman &> /dev/null; then
        if podman info &> /dev/null; then
            DOCKER_CMD="podman"
            return 0
        fi
    fi
    
    return 1
}

# Fonction de troncature de texte
truncate_text() {
    local text="$1"
    local max_len="$2"
    if [[ ${#text} -gt $max_len ]]; then
        echo "${text:0:$((max_len-3))}..."
    else
        echo "$text"
    fi
}

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
    
    local count=$($DOCKER_CMD ps $cmd_filter -q | wc -l)
    if [[ $count -eq 0 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun conteneur $( [[ -z "$filter" ]] && echo "en cours d'exécution" || echo "arrêté" )"
        return
    fi
    
    echo ""
    printf "  ${LYELLOW}%-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s${NC}\n" "ID" "NOM" "IMAGE" "STATUS" "TYPE" "SOURCE" "PORTS"
    echo -e "  ${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Récupérer toutes les infos en un seul appel par conteneur
    $DOCKER_CMD ps $cmd_filter --format "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}" | while IFS='|' read -r cid name image status ports; do
        # Récupérer les infos supplémentaires nécessaires
        local mounts_info=$($DOCKER_CMD inspect --format '{{range .Mounts}}1{{end}}|{{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null)
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
        
        printf "  %-12s %-18s %-30s %-${status_width}s %-9s %-7s %-${ports_width}s\n" "$cid" "$name" "$image" "$status" "$type" "$source" "$ports"
    done
}

# Fonction de détection d'informations sensibles
detect_sensitive_data() {
    local text="$1"
    local found_secrets=()
    
    # Patterns pour détecter les mots de passe
    if echo "$text" | grep -qiE "(password|passwd|pwd|pass|secret|token|api[_-]?key|auth|credential)="; then
        # Extraire les lignes contenant des secrets potentiels
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "(password|passwd|pwd|pass|secret|token|api[_-]?key|auth|credential)="; then
                found_secrets+=("$line")
            fi
        done <<< "$text"
    fi
    
    # Retourner les secrets trouvés (un par ligne)
    if [[ ${#found_secrets[@]} -gt 0 ]]; then
        printf '%s\n' "${found_secrets[@]}"
        return 0
    fi
    return 1
}

# Fonction d'affichage de section style LinPEAS
print_section() {
    local title="$1"
    local total_width=80
    local title_length=${#title}
    
    # Calculer l'espace disponible pour les lignes (enlever le titre + 4 pour les espaces et accolades)
    local lines_space=$((total_width - title_length - 4))
    local left_width=$((lines_space / 2))
    local right_width=$((lines_space - left_width))
    
    # Créer les lignes de la bonne longueur
    local left_line=$(printf '═%.0s' $(seq 1 $left_width))
    local right_line=$(printf '═%.0s' $(seq 1 $right_width))
    
    echo ""
    echo -e "${LBLUE}${left_line}{ ${LGREEN}$title${NC} ${LBLUE}}${right_line}${NC}"
}

# Fonction d'affichage de sous-section style LinPEAS détaillé
print_subsection() {
    local subtitle="$1"
    echo ""
    echo -e "  ${LCYAN}┌──────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${LCYAN}│${NC} ${LBLUE}$subtitle${NC}"
    echo -e "  ${LCYAN}└──────────────────────────────────────────────────────────────────────┘${NC}"
}

# Fonction de vérification de sécurité
check_security() {
    local CONTAINER_ID=$1
    local NAME=$2
    local WARNINGS=0

    # Récupération des informations de sécurité
    local USER=$($DOCKER_CMD inspect --format='{{.Config.User}}' "$CONTAINER_ID")
    local PRIVILEGED=$($DOCKER_CMD inspect --format='{{.HostConfig.Privileged}}' "$CONTAINER_ID")
    local CAP_ADD=$($DOCKER_CMD inspect --format='{{.HostConfig.CapAdd}}' "$CONTAINER_ID")
    local CAP_DROP=$($DOCKER_CMD inspect --format='{{.HostConfig.CapDrop}}' "$CONTAINER_ID")
    local VOLUMES=$($DOCKER_CMD inspect --format='{{json .Mounts}}' "$CONTAINER_ID")
    local READONLY_ROOTFS=$($DOCKER_CMD inspect --format='{{.HostConfig.ReadonlyRootfs}}' "$CONTAINER_ID")
    local PID_MODE=$($DOCKER_CMD inspect --format='{{.HostConfig.PidMode}}' "$CONTAINER_ID")
    local IPC_MODE=$($DOCKER_CMD inspect --format='{{.HostConfig.IpcMode}}' "$CONTAINER_ID")
    local NETWORK_MODE=$($DOCKER_CMD inspect --format='{{.HostConfig.NetworkMode}}' "$CONTAINER_ID")
    local SECURITY_OPT=$($DOCKER_CMD inspect --format='{{.HostConfig.SecurityOpt}}' "$CONTAINER_ID")

    echo "Audit de sécurité :"

    # 1. Utilisateur
    # Extraire l'UID (partie avant le ':' si format UID:GID)
    local UID_ONLY="${USER%%:*}"
    
    if [[ -z "$USER" || "$UID_ONLY" == "0" || "$USER" == "root" || "$USER" == "0:0" ]]; then
        if [[ -n "$USER" ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Conteneur exécuté en root (User: $USER)${NC}"
        else
            echo -e "  ${LRED}[!]${NC} ${LRED}Conteneur exécuté en root (User non défini = root par défaut)${NC}"
        fi
        ((WARNINGS++))
    else
        echo -e "  ${LGREEN}[+]${NC} Utilisateur non-root : $USER (UID: $UID_ONLY)"
    fi

    # 2. Mode privilégié
    if [[ "$PRIVILEGED" == "true" ]]; then
        echo -e "  ${LRED}[!]${NC} Conteneur en mode privilégié"
        ((WARNINGS++))
    else
        echo -e "  ${LGREEN}[+]${NC} Pas de mode privilégié"
    fi

    # 3. Capabilities - Détection avancée des capabilities dangereuses
    local DANGEROUS_CAPS_FOUND=false
    if [[ "$CAP_ADD" != "[]" && "$CAP_ADD" != "<no value>" && "$CAP_ADD" != "null" ]]; then
        # Analyser chaque capability pour détecter les dangereuses
        if echo "$CAP_ADD" | grep -qiE "SYS_ADMIN|ALL"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Capability SYS_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Montage de cgroups, accès /dev, échappement de conteneur${NC}"
            echo -e "      ${DGRAY}├─${NC} Permet de monter des systèmes de fichiers arbitraires"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount -t cgroup -o rdma cgroup /tmp/cg && echo > /tmp/cg/release_agent${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_PTRACE"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_PTRACE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Injection de code dans les processus de l'hôte${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet d'utiliser ptrace() pour attacher et modifier des processus${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_MODULE"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Capability SYS_MODULE ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Chargement de modules kernel malveillants${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : insmod /tmp/rootkit.ko${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_RAWIO"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_RAWIO ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Accès direct à la mémoire physique et I/O${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet d'accéder à /dev/mem et /dev/kmem pour lire la RAM de l'hôte${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "DAC_OVERRIDE|DAC_READ_SEARCH"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability DAC_OVERRIDE/DAC_READ_SEARCH ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Bypass des permissions de fichiers"
            echo -e "      ${DGRAY}└─${NC} Permet de lire/écrire des fichiers sans vérification des permissions"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "NET_ADMIN"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability NET_ADMIN ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Configuration réseau, sniffing, spoofing"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Permet de créer des interfaces réseau, modifier les routes, iptables${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "NET_RAW"; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Capability NET_RAW ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Création de paquets réseau raw (ARP spoofing, MitM)"
            echo -e "      ${DGRAY}└─${NC} Permet d'utiliser des raw sockets pour le sniffing et le spoofing"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_BOOT"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Capability SYS_BOOT ajoutée${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Redémarrage du système hôte${NC}"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : reboot ou shutdown -r now${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_TIME"; then
            echo -e "  ${YELLOW}[!]${NC} Capability SYS_TIME ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Modification de l'horloge système"
            echo -e "      ${DGRAY}└─${NC} Peut affecter les certificats, logs, et synchronisation"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "SYS_CHROOT"; then
            echo -e "  ${YELLOW}[!]${NC} Capability SYS_CHROOT ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Échappement via chroot"
            echo -e "      ${DGRAY}└─${NC} Combiné avec d'autres caps, peut faciliter l'échappement"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        if echo "$CAP_ADD" | grep -qiE "MKNOD"; then
            echo -e "  ${YELLOW}[!]${NC} Capability MKNOD ajoutée"
            echo -e "      ${DGRAY}├─${NC} Exploitation : Création de périphériques bloc/caractères"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mknod /tmp/sda b 8 0${NC}"
            ((WARNINGS++))
            DANGEROUS_CAPS_FOUND=true
        fi
        
        if [[ "$DANGEROUS_CAPS_FOUND" == "false" ]]; then
            echo -e "  ${YELLOW}[!]${NC} Capabilities ajoutées : $CAP_ADD"
            ((WARNINGS++))
        fi
    fi
    
    if [[ "$CAP_DROP" != "[]" && "$CAP_DROP" != "<no value>" && "$CAP_DROP" != "null" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Capabilities supprimées : $CAP_DROP"
    else
        echo -e "  ${LBLUE}[i]${NC} Aucune capability supprimée (toutes les capabilities par défaut actives)"
    fi

    # 4. Socket Docker/Podman - Détection avancée et complète
    local DOCKER_SOCKET_FOUND=false
    local SOCKET_MODE=""
    
    # 4.1. Vérifier si le socket Docker est monté comme volume
    if echo "$VOLUMES" | grep -q "/var/run/docker.sock"; then
        # Vérifier le mode RW du montage (READ-ONLY, pas de test intrusif)
        local SOCKET_MODE=$($DOCKER_CMD inspect --format='{{range .Mounts}}{{if eq .Destination "/var/run/docker.sock"}}{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")
        
        # Obtenir les permissions pour affichage (lecture seule, non intrusif)
        local SOCKET_PERMS=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        local SOCKET_GROUP=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$4}'" 2>/dev/null)
        
        # Vérifier si monté en read-write ET permissions permettent l'écriture
        if [[ "$SOCKET_MODE" == "true" ]] || echo "$SOCKET_PERMS" | grep -q "rw"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Socket Docker monté (risque accès ÉCRITURE)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Escalade de privilèges & échapement de conteneur possible${NC}"
            echo -e "      ${DGRAY}├─${NC} Le conteneur peut créer/modifier/supprimer des conteneurs sur l'hôte"
            [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            [[ -n "$SOCKET_GROUP" ]] && echo -e "      ${DGRAY}├─${NC} Groupe : ${LBLUE}$SOCKET_GROUP${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LYELLOW}RW=$SOCKET_MODE${NC}"
            ((WARNINGS++))
        else
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Socket Docker monté (configuration read-only)${NC}"
            echo -e "      ${DGRAY}├─${NC} Accès limité mais peut lire les informations Docker"
            [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            ((WARNINGS++))
        fi
        DOCKER_SOCKET_FOUND=true
    fi
    
    # 4.2. Vérifier le socket Podman
    if echo "$VOLUMES" | grep -q "/run/podman/podman.sock"; then
        # Vérifier le mode RW du montage (READ-ONLY, pas de test intrusif)
        local SOCKET_MODE=$($DOCKER_CMD inspect --format='{{range .Mounts}}{{if eq .Destination "/run/podman/podman.sock"}}{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")
        
        local SOCKET_PERMS=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "ls -l /run/podman/podman.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
        
        if [[ "$SOCKET_MODE" == "true" ]] || echo "$SOCKET_PERMS" | grep -q "rw"; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Socket Podman monté (risque accès ÉCRITURE)${NC}"
            echo -e "      ${DGRAY}├─${NC} ${LRED}CRITIQUE : Contrôle total du moteur Podman${NC}"
            [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}├─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            echo -e "      ${DGRAY}└─${NC} Mode montage : ${LYELLOW}RW=$SOCKET_MODE${NC}"
            ((WARNINGS++))
        else
            echo -e "  ${YELLOW}[!]${NC} Socket Podman monté (configuration read-only)"
            [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            ((WARNINGS++))
        fi
        DOCKER_SOCKET_FOUND=true
    fi
    
    # 4.3. Vérifier si d'autres répertoires Docker sont montés
    if echo "$VOLUMES" | grep -q "/var/lib/docker"; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire Docker monté (/var/lib/docker)${NC}"
        echo -e "      ${DGRAY}├─${NC} Accès direct aux données Docker (images, volumes, conteneurs)"
        echo -e "      ${DGRAY}└─${NC} ${LRED}Possibilité de manipulation des données Docker${NC}"
        ((WARNINGS++))
        DOCKER_SOCKET_FOUND=true
    fi
    
    # 4.4. Détecter les variables d'environnement Docker exposées
    local DOCKER_HOST_VAR=$($DOCKER_CMD inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER_ID" | grep "DOCKER_HOST=" || echo "")
    if [[ -n "$DOCKER_HOST_VAR" ]]; then
        echo -e "  ${LRED}[!]${NC} Variable DOCKER_HOST détectée : ${LYELLOW}$DOCKER_HOST_VAR${NC}"
        echo -e "      ${DGRAY}└─${NC} Accès potentiel à un daemon Docker distant"
        ((WARNINGS++))
        DOCKER_SOCKET_FOUND=true
    fi
    
    # 4.5. Vérifier si le conteneur peut accéder au socket depuis l'intérieur (cas où le montage n'a pas été détecté)
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "test -S /var/run/docker.sock" 2>/dev/null; then
        if [[ "$DOCKER_SOCKET_FOUND" == "false" ]]; then
            # Socket présent mais pas détecté dans les montages (copié ou autre méthode)
            local SOCKET_PERMS=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "ls -l /var/run/docker.sock 2>/dev/null | awk '{print \$1}'" 2>/dev/null)
            
            # Vérifier si les permissions indiquent un accès possible en écriture
            if echo "$SOCKET_PERMS" | grep -q "rw"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}Socket Docker accessible DANS le conteneur (permissions écriture)${NC}"
                echo -e "      ${DGRAY}├─${NC} Le socket est présent (bind mount non détecté ou copié)"
                [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            else
                echo -e "  ${YELLOW}[!]${NC} Socket Docker accessible DANS le conteneur"
                echo -e "      ${DGRAY}├─${NC} Le socket est présent (bind mount non détecté ou copié)"
                [[ -n "$SOCKET_PERMS" ]] && echo -e "      ${DGRAY}└─${NC} Permissions : ${LBLUE}$SOCKET_PERMS${NC}"
            fi
            ((WARNINGS++))
            DOCKER_SOCKET_FOUND=true
        fi
    fi
    
    # 4.6. Vérifier si Docker CLI est installé dans le conteneur
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "command -v docker" &>/dev/null; then
        local DOCKER_VERSION=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "docker --version 2>/dev/null" || echo "Version inconnue")
        echo -e "  ${YELLOW}[!]${NC} Docker CLI installé dans le conteneur"
        echo -e "      ${DGRAY}├─${NC} Version : ${LBLUE}$DOCKER_VERSION${NC}"
        if [[ "$DOCKER_SOCKET_FOUND" == "true" ]]; then
            echo -e "      ${DGRAY}└─${NC} ${LRED}RISQUE CRITIQUE : Docker CLI + Socket = Contrôle total de l'hôte${NC}"
        else
            echo -e "      ${DGRAY}└─${NC} CLI présent mais aucun socket détecté"
        fi
    fi
    
    # 4.7. Vérifier si Podman CLI est installé
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "command -v podman" &>/dev/null; then
        local PODMAN_VERSION=$($DOCKER_CMD exec "$CONTAINER_ID" sh -c "podman --version 2>/dev/null" || echo "Version inconnue")
        echo -e "  ${YELLOW}[!]${NC} Podman CLI installé dans le conteneur"
        echo -e "      ${DGRAY}└─${NC} Version : ${LBLUE}$PODMAN_VERSION${NC}"
    fi
    
    if [[ "$DOCKER_SOCKET_FOUND" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun accès au socket Docker/Podman détecté"
    fi

    # 5. Namespace PID
    if [[ "$PID_MODE" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} Namespace PID partagé avec l'hôte (--pid=host)"
        echo -e "      ${DGRAY}└─${NC} Le conteneur peut voir et interagir avec tous les processus de l'hôte"
        ((WARNINGS++))
    fi

    # 6. Namespace IPC
    if [[ "$IPC_MODE" == "host" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Namespace IPC partagé avec l'hôte (--ipc=host)"
        ((WARNINGS++))
    fi

    # 7. Mode réseau
    if [[ "$NETWORK_MODE" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} Mode réseau host (--network=host)"
        echo -e "      ${DGRAY}└─${NC} Le conteneur partage la pile réseau de l'hôte"
        ((WARNINGS++))
    fi

    # 8. SELinux / AppArmor
    if [[ "$SECURITY_OPT" == "[]" || "$SECURITY_OPT" == "<no value>" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucune option de sécurité supplémentaire (SELinux/AppArmor)"
    else
        if echo "$SECURITY_OPT" | grep -q "seccomp=unconfined"; then
            echo -e "  ${LRED}[!]${NC} Seccomp désactivé - Tous les syscalls autorisés"
            ((WARNINGS++))
        fi
        if echo "$SECURITY_OPT" | grep -q "apparmor=unconfined"; then
            echo -e "  ${LRED}[!]${NC} AppArmor désactivé"
            ((WARNINGS++))
        fi
        if echo "$SECURITY_OPT" | grep -q "label=disable"; then
            echo -e "  ${LRED}[!]${NC} SELinux désactivé"
            ((WARNINGS++))
        fi
    fi

    # 9. Système de fichiers racine
    if [[ "$READONLY_ROOTFS" == "true" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Système de fichiers racine en lecture seule"
    else
        echo -e "  ${LBLUE}[i]${NC} Système de fichiers racine en lecture/écriture"
    fi

    # 10. Montages sensibles
    local has_sensitive_mount=false
    if echo "$VOLUMES" | grep -qE "/(etc|root|home|boot|dev|sys|proc)\""; then
        echo -e "  ${LRED}[!]${NC} Répertoires système sensibles montés depuis l'hôte"
        ((WARNINGS++))
        has_sensitive_mount=true
    fi
    
    # 10.1. Fichiers .env montés
    if echo "$VOLUMES" | grep -qE "\.env\"|\.env\.|/\.env\""; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Fichier .env monté - Risque d'exposition de secrets${NC}"
        ((WARNINGS++))
        has_sensitive_mount=true
    fi
    
    if [[ "$has_sensitive_mount" == "false" ]]; then
        echo -e "  ${LGREEN}[+]${NC} Aucun montage sensible détecté"
    fi

    # 11. Variables sensibles exposées
    local SENSITIVE_COUNT=0
    local ALL_ENV=$($DOCKER_CMD inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER_ID")
    local ALL_LABELS=$($DOCKER_CMD inspect --format='{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}' "$CONTAINER_ID")
    
    # Détecter dans les variables d'environnement
    local SENSITIVE_ENV=$(detect_sensitive_data "$ALL_ENV")
    if [[ -n "$SENSITIVE_ENV" ]]; then
        local ENV_COUNT=$(echo "$SENSITIVE_ENV" | wc -l)
        echo -e "  ${LRED}[!]${NC} ${LRED}$ENV_COUNT variable(s) d'environnement sensible(s) détectée(s)${NC}"
        echo -e "      ${DGRAY}└─${NC} Voir la section 'Variables d'environnement' pour plus de détails"
        ((WARNINGS++))
        ((SENSITIVE_COUNT += ENV_COUNT))
    fi
    
    # Détecter dans les labels
    local SENSITIVE_LABELS=$(detect_sensitive_data "$ALL_LABELS")
    if [[ -n "$SENSITIVE_LABELS" ]]; then
        local LABEL_COUNT=$(echo "$SENSITIVE_LABELS" | wc -l)
        echo -e "  ${YELLOW}[!]${NC} $LABEL_COUNT label(s) avec informations sensibles détecté(s)"
        echo -e "      ${DGRAY}└─${NC} Voir la section 'Labels personnalisés' pour plus de détails"
        ((WARNINGS++))
        ((SENSITIVE_COUNT += LABEL_COUNT))
    fi
    
    if [[ $SENSITIVE_COUNT -gt 0 ]]; then
        echo -e "  ${DGRAY}└─${NC} ${LRED}Total : $SENSITIVE_COUNT donnée(s) sensible(s) exposée(s)${NC}"
    fi

    # 12. Flag no-new-privileges (protection contre l'escalade de privilèges SUID/SGID)
    local NO_NEW_PRIVS=$($DOCKER_CMD inspect --format='{{.HostConfig.SecurityOpt}}' "$CONTAINER_ID" | grep -o "no-new-privileges:true" || echo "")
    if [[ -z "$NO_NEW_PRIVS" ]]; then
        echo -e "  ${YELLOW}[!]${NC} ${YELLOW}Flag --security-opt=no-new-privileges non défini${NC}"
        echo -e "      ${DGRAY}├─${NC} Exploitation : Escalade via binaires SUID/SGID"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Les processus peuvent acquérir de nouveaux privilèges via execve()${NC}"
        ((WARNINGS++))
    else
        echo -e "  ${LGREEN}[+]${NC} Flag no-new-privileges activé (protection SUID/SGID)"
    fi

    # 13. Devices exposés (/dev)
    local DEVICES=$($DOCKER_CMD inspect --format='{{range .HostConfig.Devices}}{{.PathOnHost}}{{println}}{{end}}' "$CONTAINER_ID")
    if [[ -n "$DEVICES" ]] && [[ "$DEVICES" != "<no value>" ]]; then
        local CRITICAL_DEVICE=false
        while IFS= read -r device; do
            [[ -z "$device" ]] && continue
            
            if echo "$device" | grep -qE "/dev/(sd|hd|nvme|vd|xvd)"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Périphérique de disque exposé : $device${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Accès direct au système de fichiers de l'hôte${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Commande exploit : mount $device /mnt && chroot /mnt${NC}"
                ((WARNINGS++))
                CRITICAL_DEVICE=true
            elif echo "$device" | grep -qE "/dev/kmsg|/dev/mem|/dev/kmem"; then
                echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Device de mémoire kernel exposé : $device${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Lecture/écriture de la mémoire kernel${NC}"
                echo -e "      ${DGRAY}└─${NC} Permet de dumper des secrets, modifier le kernel en live"
                ((WARNINGS++))
                CRITICAL_DEVICE=true
            elif echo "$device" | grep -qE "/dev/tty|/dev/console"; then
                echo -e "  ${YELLOW}[!]${NC} Device TTY/Console exposé : $device"
                echo -e "      ${DGRAY}└─${NC} Peut permettre de capturer ou injecter des entrées clavier"
                ((WARNINGS++))
                CRITICAL_DEVICE=true
            elif [[ "$device" == "/dev/fuse" ]]; then
                echo -e "  ${YELLOW}[!]${NC} Device FUSE exposé : $device"
                echo -e "      ${DGRAY}└─${NC} Permet de créer des systèmes de fichiers en userspace"
                ((WARNINGS++))
                CRITICAL_DEVICE=true
            fi
        done <<< "$DEVICES"
        
        if [[ "$CRITICAL_DEVICE" == "false" ]]; then
            echo -e "  ${LBLUE}[i]${NC} Devices exposés (non critiques) : $(echo "$DEVICES" | tr '\n' ' ')"
        fi
    fi

    # 14. User namespace (remapping des UIDs)
    local USER_NS=$($DOCKER_CMD inspect --format='{{.HostConfig.UsernsMode}}' "$CONTAINER_ID")
    if [[ "$USER_NS" == "host" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}User namespace désactivé (--userns=host)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}UID 0 dans le conteneur = UID 0 sur l'hôte${NC}"
        echo -e "      ${DGRAY}└─${NC} Pas de remapping des UIDs, risque d'escalade si évasion"
        ((WARNINGS++))
    elif [[ -z "$USER_NS" || "$USER_NS" == "<no value>" ]]; then
        echo -e "  ${LBLUE}[i]${NC} User namespace par défaut (pas de remapping custom)"
    fi

    # 15. Sysctls dangereux
    local SYSCTLS=$($DOCKER_CMD inspect --format='{{range $key, $value := .HostConfig.Sysctls}}{{$key}}={{$value}}{{println}}{{end}}' "$CONTAINER_ID")
    if [[ -n "$SYSCTLS" ]]; then
        local DANGEROUS_SYSCTL=false
        while IFS= read -r sysctl; do
            [[ -z "$sysctl" ]] && continue
            
            if echo "$sysctl" | grep -qiE "kernel\.|vm\.|fs\."; then
                echo -e "  ${LRED}[!]${NC} ${LRED}SYSCTL DANGEREUX : $sysctl${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Modification de paramètres kernel/VM depuis le conteneur${NC}"
                echo -e "      ${DGRAY}└─${NC} Peut affecter la stabilité et sécurité de l'hôte"
                ((WARNINGS++))
                DANGEROUS_SYSCTL=true
            elif echo "$sysctl" | grep -qiE "net\.ipv4\.ip_forward|net\.ipv4\.conf\.all\.forwarding"; then
                echo -e "  ${YELLOW}[!]${NC} SYSCTL réseau modifié : $sysctl"
                echo -e "      ${DGRAY}└─${NC} Permet le routage IP (peut être légitime pour un proxy/router)"
                ((WARNINGS++))
                DANGEROUS_SYSCTL=true
            fi
        done <<< "$SYSCTLS"
        
        if [[ "$DANGEROUS_SYSCTL" == "false" ]]; then
            echo -e "  ${LBLUE}[i]${NC} Sysctls configurés : $(echo "$SYSCTLS" | tr '\n' ' ')"
        fi
    fi

    # 16. Risque d'accès aux cgroups (vecteur d'échappement via release_agent)
    # Détection READ-ONLY basée sur la configuration (pas de tests intrusifs)
    local CGROUP_RISK=false
    local CGROUP_REASONS=()
    
    # Si mode privilégié → accès total aux cgroups
    if [[ "$PRIVILEGED" == "true" ]]; then
        CGROUP_RISK=true
        CGROUP_REASONS+=("Mode privilégié activé")
    fi
    
    # Si CAP_SYS_ADMIN → peut monter des cgroups
    if echo "$CAP_ADD" | grep -qiE "SYS_ADMIN|ALL"; then
        CGROUP_RISK=true
        CGROUP_REASONS+=("Capability CAP_SYS_ADMIN détectée")
    fi
    
    # Si /sys/fs/cgroup monté en read-write
    if echo "$VOLUMES" | grep -q '"/sys/fs/cgroup"' && echo "$VOLUMES" | grep -q '"RW":true'; then
        CGROUP_RISK=true
        CGROUP_REASONS+=("Montage /sys/fs/cgroup en read-write")
    fi
    
    if [[ "$CGROUP_RISK" == "true" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}CRITIQUE : Configuration permettant la manipulation des cgroups${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Risque : Échappement de conteneur via release_agent (CVE-2022-0492)${NC}"
        for reason in "${CGROUP_REASONS[@]}"; do
            echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Raison : $reason${NC}"
        done
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}PoC : https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/${NC}"
        ((WARNINGS++))
    fi

    # 17. Détection de kernels vulnérables connus (kernel partagé avec l'hôte)
    # Note: Les conteneurs partagent le kernel de l'hôte Docker
    local KERNEL_VERSION=$($DOCKER_CMD info 2>/dev/null | grep "Kernel Version" | cut -d: -f2 | xargs)
    if [[ -n "$KERNEL_VERSION" ]]; then
        # Vérifier les versions vulnérables connues
        local KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
        local KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

        if [[ "$KERNEL_MAJOR" -lt 4 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}Kernel hôte OBSOLÈTE : $KERNEL_VERSION${NC}"
            echo -e "      ${DGRAY}└─${NC} Mise à jour du kernel de l'hôte Docker fortement recommandée"
            ((WARNINGS++))
            ((CONTAINERS_WITH_VULNERABLE_KERNEL++))
        elif [[ "$KERNEL_MAJOR" -eq 4 ]] && [[ "$KERNEL_MINOR" -lt 15 ]]; then
            echo -e "  ${YELLOW}[!]${NC} Kernel hôte potentiellement vulnérable : $KERNEL_VERSION"
            echo -e "      ${DGRAY}└─${NC} Vérifier les CVE associées à cette version"
            ((WARNINGS++))
            ((CONTAINERS_WITH_VULNERABLE_KERNEL++))
        fi
    fi

    # 18. Détection de l'exposition de secrets dans l'historique des layers
    # (Simplifié - vérifier si l'image a beaucoup de layers)
    local IMAGE=$($DOCKER_CMD inspect --format='{{.Image}}' "$CONTAINER_ID")
    local LAYER_COUNT=$($DOCKER_CMD inspect --format='{{range .RootFS.Layers}}{{println}}{{end}}' "$IMAGE" 2>/dev/null | wc -l)
    if [[ $LAYER_COUNT -gt 30 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Image avec $LAYER_COUNT layers (risque de secrets dans l'historique)"
        echo -e "      ${DGRAY}└─${NC} Vérifier avec : docker history $IMAGE | grep -E 'ENV|COPY|ADD'"
    fi

    # 19. Vérification de la présence de tokens cloud (AWS, GCP, Azure)
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "test -d /root/.aws" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire AWS CLI détecté (/root/.aws)${NC}"
        echo -e "      ${DGRAY}├─${NC} Possibles credentials AWS exposés"
        echo -e "      ${DGRAY}└─${NC} Vérifier les fichiers credentials et config"
        ((WARNINGS++))
    fi
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "test -d /root/.config/gcloud" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire GCP CLI détecté (/root/.config/gcloud)${NC}"
        echo -e "      ${DGRAY}├─${NC} Possibles credentials GCP exposés"
        echo -e "      ${DGRAY}└─${NC} Vérifier les fichiers de configuration gcloud"
        ((WARNINGS++))
    fi
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "test -d /root/.azure" 2>/dev/null; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Répertoire Azure CLI détecté (/root/.azure)${NC}"
        echo -e "      ${DGRAY}├─${NC} Possibles credentials Azure exposés"
        echo -e "      ${DGRAY}└─${NC} Vérifier les fichiers de configuration Azure"
        ((WARNINGS++))
    fi

    # 20. Limites de ressources (ANSSI/CIS - CRITIQUE pour prévenir DoS)
    local MEM_LIMIT=$($DOCKER_CMD inspect --format='{{.HostConfig.Memory}}' "$CONTAINER_ID")
    local CPU_QUOTA=$($DOCKER_CMD inspect --format='{{.HostConfig.CpuQuota}}' "$CONTAINER_ID")
    local CPU_SHARES=$($DOCKER_CMD inspect --format='{{.HostConfig.CpuShares}}' "$CONTAINER_ID")
    
    local RESOURCE_UNLIMITED=false
    if [[ "$MEM_LIMIT" == "0" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}RAM illimitée - Risque de déni de service (DoS)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : Memory exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --memory=<limit> (ex: --memory=2g)${NC}"
        ((WARNINGS++))
        RESOURCE_UNLIMITED=true
    fi
    
    if [[ "$CPU_QUOTA" == "-1" ]] || [[ "$CPU_QUOTA" == "0" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}CPU illimité - Risque de monopolisation CPU${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : CPU exhaustion attack${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --cpus=<limit> (ex: --cpus=2)${NC}"
        ((WARNINGS++))
        RESOURCE_UNLIMITED=true
    fi

    # 21. Tag :latest (ANSSI/OWASP - CRITIQUE pour reproductibilité)
    local IMAGE_FULL=$($DOCKER_CMD inspect --format='{{.Config.Image}}' "$CONTAINER_ID")
    if echo "$IMAGE_FULL" | grep -qE ':latest$|^[^:]+$'; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Image avec tag :latest ou sans tag${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Risque : Déploiements non-déterministes, versions non traçables${NC}"
        echo -e "      ${DGRAY}├─${NC} Image : ${LYELLOW}$IMAGE_FULL${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser des tags versionnés (ex: nginx:1.21.6)${NC}"
        ((WARNINGS++))
    fi

    # 22. PIDs limit (CIS - HAUTE pour prévenir fork bomb)
    local PIDS_LIMIT=$($DOCKER_CMD inspect --format='{{.HostConfig.PidsLimit}}' "$CONTAINER_ID")
    if [[ "$PIDS_LIMIT" == "0" ]] || [[ "$PIDS_LIMIT" == "-1" ]] || [[ -z "$PIDS_LIMIT" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}PIDs limit non défini - Risque de fork bomb${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Exploitation : :(){ :|:& };: (fork bomb)${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --pids-limit=100${NC}"
        ((WARNINGS++))
    fi

    # 23. Ulimits (ANSSI - MOYENNE)
    local ULIMITS=$($DOCKER_CMD inspect --format='{{.HostConfig.Ulimits}}' "$CONTAINER_ID")
    if [[ "$ULIMITS" == "[]" ]] || [[ "$ULIMITS" == "<no value>" ]] || [[ -z "$ULIMITS" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Ulimits non configurés (utilise les valeurs par défaut de l'hôte)"
        echo -e "      ${DGRAY}├─${NC} Risque : Épuisement des file descriptors/processus"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --ulimit nofile=1024:2048${NC}"
        ((WARNINGS++))
    fi

    # 24. Healthcheck (OWASP/CIS - MOYENNE pour monitoring)
    local HEALTHCHECK=$($DOCKER_CMD inspect --format='{{.Config.Healthcheck}}' "$CONTAINER_ID" 2>/dev/null)
    if [[ "$HEALTHCHECK" == "<no value>" ]] || [[ "$HEALTHCHECK" == "null" ]] || [[ -z "$HEALTHCHECK" ]] || [[ "$HEALTHCHECK" == "&lt;no value&gt;" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Healthcheck non défini"
        echo -e "      ${DGRAY}├─${NC} Pas de monitoring automatique de l'état du service"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : HEALTHCHECK CMD curl -f http://localhost/ || exit 1${NC}"
        ((WARNINGS++))
    fi

    # 25. Logging driver (ANSSI/CIS - MOYENNE pour traçabilité)
    local LOG_DRIVER=$($DOCKER_CMD inspect --format='{{.HostConfig.LogConfig.Type}}' "$CONTAINER_ID")
    if [[ "$LOG_DRIVER" == "none" ]]; then
        echo -e "  ${LRED}[!]${NC} ${LRED}Logging désactivé (driver: none)${NC}"
        echo -e "      ${DGRAY}├─${NC} ${LRED}Aucune traçabilité des événements${NC}"
        echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : Utiliser json-file, syslog, ou journald${NC}"
        ((WARNINGS++))
    elif [[ "$LOG_DRIVER" == "json-file" ]]; then
        # Vérifier les limites de logs
        local LOG_MAX_SIZE=$($DOCKER_CMD inspect --format='{{.HostConfig.LogConfig.Config.max-size}}' "$CONTAINER_ID")
        if [[ -z "$LOG_MAX_SIZE" ]] || [[ "$LOG_MAX_SIZE" == "<no value>" ]]; then
            echo -e "  ${YELLOW}[!]${NC} Logs sans limite de taille (risque de saturation disque)"
            echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Correction : docker run --log-opt max-size=10m --log-opt max-file=3${NC}"
            ((WARNINGS++))
        fi
    fi

    # 26. Restart policy (OWASP - BASSE pour résilience)
    local RESTART_POLICY=$($DOCKER_CMD inspect --format='{{.HostConfig.RestartPolicy.Name}}' "$CONTAINER_ID")
    if [[ "$RESTART_POLICY" == "no" ]] || [[ -z "$RESTART_POLICY" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Restart policy non configuré (le conteneur ne redémarrera pas automatiquement)"
    elif [[ "$RESTART_POLICY" == "always" ]]; then
        echo -e "  ${YELLOW}[!]${NC} Restart policy 'always' (peut masquer des crashs répétés)"
        echo -e "      ${DGRAY}└─${NC} Considérer 'on-failure' avec un max-retry"
    fi

    # 27. OOM Score adjustment (CIS - BASSE)
    local OOM_SCORE=$($DOCKER_CMD inspect --format='{{.HostConfig.OomScoreAdj}}' "$CONTAINER_ID")
    if [[ "$OOM_SCORE" -lt -500 ]]; then
        echo -e "  ${YELLOW}[!]${NC} OOM Score très bas ($OOM_SCORE) - Le conteneur sera protégé du OOM killer"
        echo -e "      ${DGRAY}└─${NC} Peut affecter la stabilité du système en cas de pression mémoire"
    fi

    # 28. Init process (OWASP - BASSE pour gestion des processus zombies)
    local INIT_PROCESS=$($DOCKER_CMD inspect --format='{{.HostConfig.Init}}' "$CONTAINER_ID")
    if [[ "$INIT_PROCESS" != "true" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Init process non activé (--init)"
        echo -e "      ${DGRAY}└─${NC} Les processus zombies ne seront pas gérés automatiquement"
    fi

    # Résumé
    echo
    if [[ $WARNINGS -eq 0 ]]; then
        echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Aucune alerte de sécurité majeure${NC}"
    elif [[ $WARNINGS -le 2 ]]; then
        echo -e "  ${YELLOW}[!]${NC} $WARNINGS alerte(s) de sécurité détectée(s)"
    else
        echo -e "  ${LRED}[!]${NC} ${LRED}$WARNINGS alerte(s) de sécurité détectée(s) - RÉVISION RECOMMANDÉE${NC}"
    fi
}

# Fonction d'inspection des fichiers de configuration
inspect_config_files() {
    local CONTAINER_ID=$1
    
    echo "Fichiers de configuration et sources :"
    
    # 1. Docker Compose
    local COMPOSE_FILE=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$CONTAINER_ID" 2>/dev/null)
    local COMPOSE_WORKDIR=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$CONTAINER_ID" 2>/dev/null)
    local COMPOSE_PROJECT=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.project"}}' "$CONTAINER_ID" 2>/dev/null)
    local COMPOSE_SERVICE=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.service"}}' "$CONTAINER_ID" 2>/dev/null)
    
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
    local ENTRYPOINT=$($DOCKER_CMD inspect --format='{{json .Config.Entrypoint}}' "$CONTAINER_ID")
    local CMD=$($DOCKER_CMD inspect --format='{{json .Config.Cmd}}' "$CONTAINER_ID")
    local WORKDIR=$($DOCKER_CMD inspect --format='{{.Config.WorkingDir}}' "$CONTAINER_ID")
    
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
    
    # 3. Labels personnalisés (peuvent contenir des infos utiles)
    local ALL_LABELS=$($DOCKER_CMD inspect --format='{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}' "$CONTAINER_ID")
    local CUSTOM_LABELS=$(echo "$ALL_LABELS" | grep -v "^com.docker.compose" | grep -v "^org.opencontainers" | grep -v "^org.label-schema")
    
    if [[ -n "$CUSTOM_LABELS" ]]; then
        echo -e "  ${LBLUE}Labels personnalisés :${NC}"
        local LABEL_COUNT=$(echo "$CUSTOM_LABELS" | wc -l)
        local line_num=0
        while IFS= read -r line; do
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
    local CONTAINER_ID=$1
    
    echo "Ports exposés :"
    local PORTS=$($DOCKER_CMD inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} -> {{(index $conf 0).HostPort}} {{end}}{{end}}' "$CONTAINER_ID")
    
    if [[ -z "$PORTS" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun port exposé sur l'hôte"
    else
        echo -e "  ${DGRAY}├─${NC} ${LBLUE}Docker${NC} → ${LGREEN}Hôte${NC}"
        $DOCKER_CMD inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{if $conf}}{{$p}} {{(index $conf 0).HostIp}}:{{(index $conf 0).HostPort}}{{println}}{{end}}{{end}}' "$CONTAINER_ID" | while read port_container host_mapping; do
            if [[ -n "$port_container" ]]; then
                echo -e "  ${DGRAY}├─${NC} ${LBLUE}$port_container${NC} → ${LGREEN}$host_mapping${NC}"
            fi
        done
    fi
}

# Fonction d'inspection réseau
inspect_network() {
    local CONTAINER_ID=$1
    
    echo "Réseaux :"
    local NETWORKS=$($DOCKER_CMD inspect --format='{{range $name, $_ := .NetworkSettings.Networks}}{{printf "%s " $name}}{{end}}' "$CONTAINER_ID")

    if [[ -z "${NETWORKS// }" ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucun réseau explicite (bridge par défaut)"
    else
        local NET_ARRAY=($NETWORKS)
        local NET_COUNT=${#NET_ARRAY[@]}
        local i=0
        for NET in $NETWORKS; do
            ((i++))
            local DRIVER=$($DOCKER_CMD network inspect -f '{{.Driver}}' "$NET" 2>/dev/null || echo "inconnu")
            local IP=$($DOCKER_CMD inspect --format="{{range .NetworkSettings.Networks}}{{if eq \"$NET\" \"$NET\"}}{{.IPAddress}}{{end}}{{end}}" "$CONTAINER_ID")
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
    local CONTAINER_ID=$1
    
    local MOUNTS=$($DOCKER_CMD inspect --format='{{range .Mounts}}{{println .Destination "|" .Type "|" .Source "|" .RW}}{{end}}' "$CONTAINER_ID")
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
            # Trim whitespace en préservant les backslashes
            dest=$(echo "$dest" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            type=$(echo "$type" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            source=$(echo "$source" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            rw=$(echo "$rw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            
            ((mount_num++))
            
            # Détection de montage sensible
            local IS_SENSITIVE=""
            
            # Vérifier les répertoires/fichiers système sensibles
            if echo "$dest" | grep -qE "^/(var/run/docker\.sock|var/lib/docker|etc|root|boot|dev|sys|proc)"; then
                IS_SENSITIVE="${LRED}[!] "
            fi
            
            # Vérifier les fichiers .env (source ou destination)
            if echo "$dest" | grep -qE "\.env$|\.env\.|/\.env$" || echo "$source" | grep -qE "\.env$|\.env\.|/\.env$"; then
                IS_SENSITIVE="${LRED}[!] "
            fi
            
            # Affichage du chemin de destination (utiliser printf pour Windows)
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
            
            # Affichage du mode avec clarification
            if [[ "$rw" == "true" ]]; then
                echo -e "      ${DGRAY}├─${NC} Mode : ${LYELLOW}read-write${NC} (RW=true)"
            else
                echo -e "      ${DGRAY}├─${NC} Mode : ${LBLUE}read-only déclaré${NC} (RW=false) ${DGRAY}*${NC}"
            fi
            
            # Affichage du chemin hôte (utiliser printf pour éviter l'interprétation des backslashes Windows)
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
        echo -e "  ${LBLUE}[i]${NC} Légende :"
        echo -e "      ${DGRAY}├─${NC} volume : Volume Docker géré par Docker"
        echo -e "      ${DGRAY}├─${NC} bind   : Montage direct d'un répertoire existant sur l'hôte"
        echo -e "      ${DGRAY}└─${NC} ${DGRAY}*${NC} Les permissions réelles dépendent aussi du propriétaire/groupe du fichier"
    fi
}

# Fonction d'inspection des ressources
inspect_resources() {
    local CONTAINER_ID=$1
    
    echo "Ressources :"
    local MEM_LIMIT=$($DOCKER_CMD inspect --format='{{.HostConfig.Memory}}' "$CONTAINER_ID")
    local CPU_SHARES=$($DOCKER_CMD inspect --format='{{.HostConfig.CpuShares}}' "$CONTAINER_ID")
    local CPU_QUOTA=$($DOCKER_CMD inspect --format='{{.HostConfig.CpuQuota}}' "$CONTAINER_ID")
    
    # Déterminer si CPU shares sera affiché (pour savoir où mettre └─)
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
    
    # Affichage CPU shares (toujours le dernier si présent)
    if [[ "$has_cpu_shares" == "true" ]]; then
        echo -e "  ${DGRAY}└─${NC} CPU shares : ${LBLUE}$CPU_SHARES${NC}"
    fi
}

# Fonction d'inspection des variables d'environnement
inspect_env() {
    local CONTAINER_ID=$1
    
    echo "Variables d'environnement :"
    local ALL_ENV=$($DOCKER_CMD inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER_ID")
    local ENV_COUNT=$(echo "$ALL_ENV" | wc -l)
    
    if [[ $ENV_COUNT -eq 0 ]]; then
        echo -e "  ${LBLUE}[i]${NC} Aucune variable d'environnement"
    else
        local sensitive_count=0
        local line_num=0
        while IFS= read -r line; do
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
            echo -e "  ${LRED}[!]${NC} Total : $ENV_COUNT variable(s) dont ${LRED}$sensitive_count sensible(s)${NC}"
        else
            echo -e "  ${LBLUE}[i]${NC} Total : $ENV_COUNT variable(s) d'environnement"
        fi
    fi
}

# Fonction principale d'inspection d'un conteneur
inspect_container() {
    local CONTAINER_ID=$1
    local NAME=$($DOCKER_CMD inspect --format='{{.Name}}' "$CONTAINER_ID" | sed 's|/||')
    local IMAGE=$($DOCKER_CMD inspect --format='{{.Config.Image}}' "$CONTAINER_ID")
    local STATUS=$($DOCKER_CMD inspect --format='{{.State.Status}}' "$CONTAINER_ID")
    local UPTIME=$($DOCKER_CMD inspect --format='{{.State.StartedAt}}' "$CONTAINER_ID")
    
    print_subsection "$NAME ($CONTAINER_ID)"
    echo "Image : $IMAGE"
    echo "Status : $STATUS (démarré : $UPTIME)"
    echo
    
    inspect_config_files "$CONTAINER_ID"
    echo
    
    inspect_ports "$CONTAINER_ID"
    echo
    
    inspect_network "$CONTAINER_ID"
    echo
    
    inspect_mounts "$CONTAINER_ID"
    echo
    
    inspect_resources "$CONTAINER_ID"
    echo
    
    inspect_env "$CONTAINER_ID"
    echo
    
    check_security "$CONTAINER_ID" "$NAME"
}


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

# Détecter et vérifier que Docker/Podman est accessible
if ! detect_container_engine; then
    echo -e "${LRED}[!]${NC} ${LRED}Erreur : Docker ou Podman n'est pas accessible${NC}"
    echo -e "    ${DGRAY}└─${NC} Vérifiez que le service est démarré et que vous avez les permissions"
    exit 1
fi

# 0. Informations système Docker
print_section "INFO DOCKER"

echo -e "${LBLUE}[+]${NC} Informations système :"
echo ""

# Hostname
HOSTNAME=$(hostname)
echo -e "  ${DGRAY}├─${NC} ${LBLUE}Hostname${NC} : ${LGREEN}$HOSTNAME${NC}"

# Adresse IP
if command -v ip &> /dev/null; then
    IP_ADDR=$(ip route get 1 2>/dev/null | grep -oP 'src \K\S+' || echo "Non disponible")
elif command -v hostname &> /dev/null; then
    IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "Non disponible")
else
    IP_ADDR="Non disponible"
fi
echo -e "  ${DGRAY}├─${NC} ${LBLUE}Adresse IP${NC} : ${LGREEN}$IP_ADDR${NC}"

# Version Docker/Podman
ENGINE_VERSION=$($DOCKER_CMD --version 2>/dev/null || echo "Version non disponible")
echo -e "  ${DGRAY}├─${NC} ${LBLUE}Moteur${NC} : ${LGREEN}$DOCKER_CMD${NC}"
echo -e "  ${DGRAY}└─${NC} ${LBLUE}Version${NC} : ${LGREEN}$ENGINE_VERSION${NC}"

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
display_containers "status=exited" "YELLOW" "Conteneurs arrêtés" 23 20

# 2. Vue d'ensemble des images
print_section "IMAGES DISPONIBLES"
$DOCKER_CMD images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedAt}}"

# 3. Vue d'ensemble des volumes
print_section "VOLUMES DOCKER"
$DOCKER_CMD volume ls

# 4. Espace utilisé par Docker
print_section "ESPACE UTILISÉ PAR DOCKER"
$DOCKER_CMD system df

# 5. Réseaux
print_section "RÉSEAUX DOCKER"
$DOCKER_CMD network ls

# 6. Inspection détaillée des conteneurs
print_section "INSPECTION DÉTAILLÉE DES CONTENEURS"

RUNNING_CONTAINERS=$($DOCKER_CMD ps -q)

if [[ -z "$RUNNING_CONTAINERS" ]]; then
    echo "Aucun conteneur en cours d'exécution."
    exit 0
fi

for CONTAINER_ID in $RUNNING_CONTAINERS; do
    inspect_container "$CONTAINER_ID"
    echo
    echo -e "${DGRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
done

# Résumé final
print_section "RÉSUMÉ"

# Comptage des conteneurs stateless vs stateful et compose vs manuel
STATELESS_COUNT=0
STATEFUL_COUNT=0
COMPOSE_COUNT=0
MANUAL_COUNT=0

# Compteurs de sécurité
TOTAL_SECURITY_ISSUES=0
CONTAINERS_WITH_ROOT=0
CONTAINERS_PRIVILEGED=0
CONTAINERS_WITH_DOCKER_SOCKET=0
CONTAINERS_WITH_HOST_PID=0
CONTAINERS_WITH_HOST_NETWORK=0
CONTAINERS_WITH_SENSITIVE_MOUNTS=0
CONTAINERS_WITH_SENSITIVE_VARS=0
CONTAINERS_SECURE=0
CONTAINERS_WITH_DANGEROUS_CAPS=0
CONTAINERS_WITHOUT_NO_NEW_PRIVS=0
CONTAINERS_WITH_DANGEROUS_DEVICES=0
CONTAINERS_WITH_CGROUP_ACCESS=0
CONTAINERS_WITH_CLOUD_CREDS=0
CONTAINERS_WITH_SECCOMP_DISABLED=0
CONTAINERS_WITH_UNLIMITED_RESOURCES=0
CONTAINERS_WITH_LATEST_TAG=0
CONTAINERS_WITHOUT_PIDS_LIMIT=0
CONTAINERS_WITHOUT_ULIMITS=0
CONTAINERS_WITHOUT_HEALTHCHECK=0
CONTAINERS_WITH_NO_LOGGING=0
CONTAINERS_WITH_VULNERABLE_KERNEL=0

for CONTAINER_ID in $($DOCKER_CMD ps -q); do
    MOUNTS_COUNT=$($DOCKER_CMD inspect --format='{{range .Mounts}}1{{end}}' "$CONTAINER_ID" | wc -c)
    COMPOSE_PROJECT=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.project"}}' "$CONTAINER_ID" 2>/dev/null)
    
    # Comptage type de conteneur
    if [[ $MOUNTS_COUNT -gt 0 ]]; then
        ((STATEFUL_COUNT++))
    else
        ((STATELESS_COUNT++))
    fi
    
    if [[ -n "$COMPOSE_PROJECT" && "$COMPOSE_PROJECT" != "<no value>" ]]; then
        ((COMPOSE_COUNT++))
    else
        ((MANUAL_COUNT++))
    fi
    
    # Audit de sécurité du conteneur
    CONTAINER_ISSUES=0
    
    # Vérification utilisateur root
    USER=$($DOCKER_CMD inspect --format='{{.Config.User}}' "$CONTAINER_ID")
    UID_ONLY="${USER%%:*}"
    if [[ -z "$USER" || "$UID_ONLY" == "0" || "$USER" == "root" ]]; then
        ((CONTAINERS_WITH_ROOT++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification mode privilégié
    PRIVILEGED=$($DOCKER_CMD inspect --format='{{.HostConfig.Privileged}}' "$CONTAINER_ID")
    if [[ "$PRIVILEGED" == "true" ]]; then
        ((CONTAINERS_PRIVILEGED++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification socket Docker
    VOLUMES=$($DOCKER_CMD inspect --format='{{json .Mounts}}' "$CONTAINER_ID")
    if echo "$VOLUMES" | grep -q "/var/run/docker.sock"; then
        ((CONTAINERS_WITH_DOCKER_SOCKET++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification namespace PID
    PID_MODE=$($DOCKER_CMD inspect --format='{{.HostConfig.PidMode}}' "$CONTAINER_ID")
    if [[ "$PID_MODE" == "host" ]]; then
        ((CONTAINERS_WITH_HOST_PID++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification mode réseau host
    NETWORK_MODE=$($DOCKER_CMD inspect --format='{{.HostConfig.NetworkMode}}' "$CONTAINER_ID")
    if [[ "$NETWORK_MODE" == "host" ]]; then
        ((CONTAINERS_WITH_HOST_NETWORK++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification montages sensibles (y compris fichiers .env)
    if echo "$VOLUMES" | grep -qE "/(etc|root|home|boot|dev|sys|proc)\"" || echo "$VOLUMES" | grep -qE "\.env\"|\.env\.|/\.env\""; then
        ((CONTAINERS_WITH_SENSITIVE_MOUNTS++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification variables sensibles
    ALL_ENV=$($DOCKER_CMD inspect --format='{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER_ID")
    ALL_LABELS=$($DOCKER_CMD inspect --format='{{range $key, $value := .Config.Labels}}{{$key}}={{$value}}{{println}}{{end}}' "$CONTAINER_ID")
    if detect_sensitive_data "$ALL_ENV" >/dev/null 2>&1 || detect_sensitive_data "$ALL_LABELS" >/dev/null 2>&1; then
        ((CONTAINERS_WITH_SENSITIVE_VARS++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification capabilities dangereuses
    CAP_ADD=$($DOCKER_CMD inspect --format='{{.HostConfig.CapAdd}}' "$CONTAINER_ID")
    if echo "$CAP_ADD" | grep -qiE "SYS_ADMIN|SYS_PTRACE|SYS_MODULE|SYS_RAWIO|SYS_BOOT|ALL"; then
        ((CONTAINERS_WITH_DANGEROUS_CAPS++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification no-new-privileges
    SECURITY_OPT=$($DOCKER_CMD inspect --format='{{.HostConfig.SecurityOpt}}' "$CONTAINER_ID")
    if ! echo "$SECURITY_OPT" | grep -q "no-new-privileges:true"; then
        ((CONTAINERS_WITHOUT_NO_NEW_PRIVS++))
    fi
    
    # Vérification devices dangereux
    DEVICES=$($DOCKER_CMD inspect --format='{{range .HostConfig.Devices}}{{.PathOnHost}}{{println}}{{end}}' "$CONTAINER_ID")
    if echo "$DEVICES" | grep -qE "/dev/(sd|hd|nvme|vd|xvd|kmsg|mem|kmem)"; then
        ((CONTAINERS_WITH_DANGEROUS_DEVICES++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification risque cgroups (READ-ONLY, basé sur config)
    VOLUMES=$($DOCKER_CMD inspect --format='{{json .Mounts}}' "$CONTAINER_ID")
    PRIVILEGED=$($DOCKER_CMD inspect --format='{{.HostConfig.Privileged}}' "$CONTAINER_ID")
    CAP_ADD=$($DOCKER_CMD inspect --format='{{.HostConfig.CapAdd}}' "$CONTAINER_ID")
    
    if [[ "$PRIVILEGED" == "true" ]] || \
       echo "$CAP_ADD" | grep -qiE "SYS_ADMIN|ALL" || \
       (echo "$VOLUMES" | grep -q '"/sys/fs/cgroup"' && echo "$VOLUMES" | grep -q '"RW":true'); then
        ((CONTAINERS_WITH_CGROUP_ACCESS++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification credentials cloud
    if $DOCKER_CMD exec "$CONTAINER_ID" sh -c "test -d /root/.aws -o -d /root/.config/gcloud -o -d /root/.azure" 2>/dev/null; then
        ((CONTAINERS_WITH_CLOUD_CREDS++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification Seccomp désactivé
    if echo "$SECURITY_OPT" | grep -q "seccomp=unconfined"; then
        ((CONTAINERS_WITH_SECCOMP_DISABLED++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification limites ressources (RAM/CPU)
    MEM_LIMIT=$($DOCKER_CMD inspect --format='{{.HostConfig.Memory}}' "$CONTAINER_ID")
    CPU_QUOTA=$($DOCKER_CMD inspect --format='{{.HostConfig.CpuQuota}}' "$CONTAINER_ID")
    if [[ "$MEM_LIMIT" == "0" ]] || [[ "$CPU_QUOTA" == "-1" ]] || [[ "$CPU_QUOTA" == "0" ]]; then
        ((CONTAINERS_WITH_UNLIMITED_RESOURCES++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification tag :latest
    IMAGE_FULL=$($DOCKER_CMD inspect --format='{{.Config.Image}}' "$CONTAINER_ID")
    if echo "$IMAGE_FULL" | grep -qE ':latest$|^[^:]+$'; then
        ((CONTAINERS_WITH_LATEST_TAG++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification PIDs limit
    PIDS_LIMIT=$($DOCKER_CMD inspect --format='{{.HostConfig.PidsLimit}}' "$CONTAINER_ID")
    if [[ "$PIDS_LIMIT" == "0" ]] || [[ "$PIDS_LIMIT" == "-1" ]] || [[ -z "$PIDS_LIMIT" ]]; then
        ((CONTAINERS_WITHOUT_PIDS_LIMIT++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Vérification Ulimits
    ULIMITS=$($DOCKER_CMD inspect --format='{{.HostConfig.Ulimits}}' "$CONTAINER_ID")
    if [[ "$ULIMITS" == "[]" ]] || [[ "$ULIMITS" == "<no value>" ]] || [[ -z "$ULIMITS" ]]; then
        ((CONTAINERS_WITHOUT_ULIMITS++))
    fi
    
    # Vérification Healthcheck
    HEALTHCHECK=$($DOCKER_CMD inspect --format='{{.Config.Healthcheck}}' "$CONTAINER_ID" 2>/dev/null)
    if [[ "$HEALTHCHECK" == "<no value>" ]] || [[ "$HEALTHCHECK" == "null" ]] || [[ -z "$HEALTHCHECK" ]]; then
        ((CONTAINERS_WITHOUT_HEALTHCHECK++))
    fi
    
    # Vérification Logging
    LOG_DRIVER=$($DOCKER_CMD inspect --format='{{.HostConfig.LogConfig.Type}}' "$CONTAINER_ID")
    if [[ "$LOG_DRIVER" == "none" ]]; then
        ((CONTAINERS_WITH_NO_LOGGING++))
        ((CONTAINER_ISSUES++))
    fi
    
    # Comptage total des problèmes
    TOTAL_SECURITY_ISSUES=$((TOTAL_SECURITY_ISSUES + CONTAINER_ISSUES))
    
    if [[ $CONTAINER_ISSUES -eq 0 ]]; then
        ((CONTAINERS_SECURE++))
    fi
done

# Ajout des conteneurs arrêtés pour le comptage total
for CONTAINER_ID in $($DOCKER_CMD ps -a -f "status=exited" -q); do
    MOUNTS_COUNT=$($DOCKER_CMD inspect --format='{{range .Mounts}}1{{end}}' "$CONTAINER_ID" | wc -c)
    COMPOSE_PROJECT=$($DOCKER_CMD inspect --format='{{index .Config.Labels "com.docker.compose.project"}}' "$CONTAINER_ID" 2>/dev/null)
    
    if [[ $MOUNTS_COUNT -gt 0 ]]; then
        ((STATEFUL_COUNT++))
    else
        ((STATELESS_COUNT++))
    fi
    
    if [[ -n "$COMPOSE_PROJECT" && "$COMPOSE_PROJECT" != "<no value>" ]]; then
        ((COMPOSE_COUNT++))
    else
        ((MANUAL_COUNT++))
    fi
done

# Affichage du résumé
print_subsection "Vue d'ensemble"
echo -e "  ${LBLUE}[+]${NC} Conteneurs actifs : ${LGREEN}$($DOCKER_CMD ps -q | wc -l)${NC}"
echo -e "  ${LBLUE}[+]${NC} Conteneurs totaux : ${LBLUE}$($DOCKER_CMD ps -a -q | wc -l)${NC}"
echo

print_subsection "Par type de données"
echo -e "  ${DGRAY}├─${NC} ${LBLUE}Stateless${NC} : $STATELESS_COUNT ${DGRAY}(applicatifs sans persistance)${NC}"
echo -e "  ${DGRAY}└─${NC} ${LYELLOW}Stateful${NC} : $STATEFUL_COUNT ${DGRAY}(avec volumes de données ou montages)${NC}"
echo

print_subsection "Par méthode de création"
echo -e "  ${DGRAY}├─${NC} ${LGREEN}Docker Compose${NC} : $COMPOSE_COUNT"
echo -e "  ${DGRAY}└─${NC} Manuel : $MANUAL_COUNT"
echo

print_subsection "Ressources Docker"
TOTAL_IMAGES=$($DOCKER_CMD images -q | wc -l)
TOTAL_VOLUMES=$($DOCKER_CMD volume ls -q | wc -l)
TOTAL_NETWORKS=$($DOCKER_CMD network ls -q | wc -l)
DANGLING_IMAGES=$($DOCKER_CMD images -f "dangling=true" -q | wc -l)
UNUSED_VOLUMES=$($DOCKER_CMD volume ls -f "dangling=true" -q | wc -l)

echo -e "  ${DGRAY}├─${NC} Images : $TOTAL_IMAGES ${DGRAY}(${LYELLOW}$DANGLING_IMAGES${DGRAY} non utilisées)${NC}"
echo -e "  ${DGRAY}├─${NC} Volumes : $TOTAL_VOLUMES ${DGRAY}(${LYELLOW}$UNUSED_VOLUMES${DGRAY} non montés)${NC}"
echo -e "  ${DGRAY}└─${NC} Réseaux : $TOTAL_NETWORKS"
echo

# Affichage de l'audit de sécurité
RUNNING_COUNT=$($DOCKER_CMD ps -q | wc -l)
if [[ $RUNNING_COUNT -gt 0 ]]; then
    print_subsection "Audit de Sécurité"
    echo -e "  ${LBLUE}[+]${NC} Conteneurs analysés : ${LBLUE}$RUNNING_COUNT${NC}"
    echo
    
    # Calcul du score de sécurité
    if [[ $RUNNING_COUNT -gt 0 ]]; then
        SECURITY_SCORE=$((CONTAINERS_SECURE * 100 / RUNNING_COUNT))
    else
        SECURITY_SCORE=0
    fi
    
    # Affichage du score avec couleur et encadré selon criticité
    if [[ $SECURITY_SCORE -ge 80 ]]; then
        SCORE_COLOR=$LGREEN
        BOX_COLOR=$LGREEN
        BOX_MSG="SECURE ENVIRONMENT"
    elif [[ $SECURITY_SCORE -ge 50 ]]; then
        SCORE_COLOR=$LYELLOW
        BOX_COLOR=$LYELLOW
        BOX_MSG="WARNINGS DETECTED"
    else
        SCORE_COLOR=$LRED
        BOX_COLOR=$LRED
        BOX_MSG="CRITICAL VULNERABILITIES DETECTED"
    fi
    
    echo -e "  ${BOX_COLOR}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOX_COLOR}║${NC} Score de sécurité : ${SCORE_COLOR}${SECURITY_SCORE}%${NC}  ${BOX_COLOR}│${NC} ${BOX_COLOR}$BOX_MSG${NC}"
    echo -e "  ${BOX_COLOR}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "  ${DGRAY}├─${NC} ${LGREEN}Conteneurs sécurisés${NC} : $CONTAINERS_SECURE"
    echo -e "  ${DGRAY}└─${NC} ${LRED}Conteneurs avec alertes${NC} : $((RUNNING_COUNT - CONTAINERS_SECURE))"
    echo
    
    if [[ $TOTAL_SECURITY_ISSUES -gt 0 ]]; then
        print_subsection "Problèmes détectés"
        
        if [[ $CONTAINERS_WITH_ROOT -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_ROOT${NC} conteneur(s) exécuté(s) en root"
        fi
        
        if [[ $CONTAINERS_PRIVILEGED -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_PRIVILEGED${NC} conteneur(s) en mode privilégié"
        fi
        
        if [[ $CONTAINERS_WITH_DOCKER_SOCKET -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_DOCKER_SOCKET${NC} conteneur(s) avec accès au socket Docker ${LRED}[CRITIQUE]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_HOST_PID -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_HOST_PID${NC} conteneur(s) avec namespace PID host"
        fi
        
        if [[ $CONTAINERS_WITH_HOST_NETWORK -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_HOST_NETWORK${NC} conteneur(s) en mode réseau host"
        fi
        
        if [[ $CONTAINERS_WITH_SENSITIVE_MOUNTS -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_SENSITIVE_MOUNTS${NC} conteneur(s) avec montages système sensibles"
        fi
        
        if [[ $CONTAINERS_WITH_SENSITIVE_VARS -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_SENSITIVE_VARS${NC} conteneur(s) avec variables sensibles exposées ${LRED}[CREDENTIALS]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_DANGEROUS_CAPS -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_DANGEROUS_CAPS${NC} conteneur(s) avec capabilities DANGEREUSES ${LRED}[CAP_SYS_ADMIN, etc.]${NC}"
        fi
        
        if [[ $CONTAINERS_WITHOUT_NO_NEW_PRIVS -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$CONTAINERS_WITHOUT_NO_NEW_PRIVS${NC} conteneur(s) sans flag no-new-privileges ${YELLOW}[SUID/SGID]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_DANGEROUS_DEVICES -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_DANGEROUS_DEVICES${NC} conteneur(s) avec devices CRITIQUES exposés ${LRED}[/dev/sda, /dev/mem]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_CGROUP_ACCESS -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_CGROUP_ACCESS${NC} conteneur(s) avec config risque cgroups ${LRED}[CONTAINER ESCAPE]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_CLOUD_CREDS -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_CLOUD_CREDS${NC} conteneur(s) avec credentials cloud détectés ${LRED}[AWS/GCP/Azure]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_SECCOMP_DISABLED -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_SECCOMP_DISABLED${NC} conteneur(s) avec Seccomp DÉSACTIVÉ ${LRED}[ALL SYSCALLS]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_UNLIMITED_RESOURCES -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_UNLIMITED_RESOURCES${NC} conteneur(s) avec ressources ILLIMITÉES ${LRED}[DoS RISK]${NC}"
        fi
        
        if [[ $CONTAINERS_WITH_LATEST_TAG -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_LATEST_TAG${NC} conteneur(s) avec tag :latest ${LRED}[NON-DETERMINISTIC]${NC}"
        fi
        
        if [[ $CONTAINERS_WITHOUT_PIDS_LIMIT -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITHOUT_PIDS_LIMIT${NC} conteneur(s) sans PIDs limit ${LRED}[FORK BOMB]${NC}"
        fi
        
        if [[ $CONTAINERS_WITHOUT_ULIMITS -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$CONTAINERS_WITHOUT_ULIMITS${NC} conteneur(s) sans ulimits configurés"
        fi
        
        if [[ $CONTAINERS_WITHOUT_HEALTHCHECK -gt 0 ]]; then
            echo -e "  ${YELLOW}[!]${NC} ${YELLOW}$CONTAINERS_WITHOUT_HEALTHCHECK${NC} conteneur(s) sans healthcheck"
        fi
        
        if [[ $CONTAINERS_WITH_NO_LOGGING -gt 0 ]]; then
            echo -e "  ${LRED}[!]${NC} ${LRED}$CONTAINERS_WITH_NO_LOGGING${NC} conteneur(s) avec logging DÉSACTIVÉ ${LRED}[NO AUDIT]${NC}"
        fi
        
        echo
        echo -e "  ${LRED}Total : $TOTAL_SECURITY_ISSUES alerte(s) de sécurité${NC}"
        echo
        
        # Section recommandations de mitigation
        if [[ $TOTAL_SECURITY_ISSUES -gt 0 ]]; then
            print_section "RECOMMANDATIONS DE SÉCURITÉ"
            echo
            
            if [[ $CONTAINERS_PRIVILEGED -gt 0 ]] || [[ $CONTAINERS_WITH_DOCKER_SOCKET -gt 0 ]] || [[ $CONTAINERS_WITH_DANGEROUS_CAPS -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Vecteurs d'échappement de conteneur détectés :"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --security-opt=no-new-privileges${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --cap-drop=ALL --cap-add=<MINIMAL_CAPS>${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --read-only${NC} (système de fichiers racine en lecture seule)"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Éviter --privileged et le montage du socket Docker${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_ROOT -gt 0 ]]; then
                echo -e "  ${YELLOW}[HAUTE]${NC} Conteneurs exécutés en root :"
                echo -e "      ${DGRAY}├─${NC} Ajouter 'USER <non-root>' dans le Dockerfile"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --user <uid>:<gid>${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_SECCOMP_DISABLED -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Seccomp désactivé :"
                echo -e "      ${DGRAY}├─${NC} Activer un profil Seccomp personnalisé"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --security-opt seccomp=/path/to/profile.json${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_UNLIMITED_RESOURCES -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Ressources illimitées (DoS) :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque de déni de service par épuisement RAM/CPU${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --memory=2g --memory-swap=2g${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --cpus=2 --cpu-shares=1024${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_LATEST_TAG -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Tag :latest utilisé :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Déploiements non reproductibles, versions non traçables${NC}"
                echo -e "      ${DGRAY}├─${NC} Utiliser des tags versionnés spécifiques"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Exemple : nginx:1.21.6 au lieu de nginx:latest${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITHOUT_PIDS_LIMIT -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} PIDs limit non défini (fork bomb) :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque de fork bomb paralysant le système${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --pids-limit=100${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_NO_LOGGING -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Logging désactivé :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Aucune traçabilité en cas d'incident${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker run --log-driver=json-file${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker run --log-opt max-size=10m --log-opt max-file=3${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_CLOUD_CREDS -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Credentials cloud exposés :"
                echo -e "      ${DGRAY}├─${NC} Utiliser les IAM Roles (AWS) ou Workload Identity (GCP)"
                echo -e "      ${DGRAY}├─${NC} Utiliser des secrets managers (Vault, AWS Secrets Manager)"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}NE JAMAIS monter ~/.aws ou ~/.config/gcloud${NC}"
                echo
            fi
            
            if [[ $CONTAINERS_WITH_CGROUP_ACCESS -gt 0 ]]; then
                echo -e "  ${LRED}[CRITIQUE]${NC} Configuration à risque pour manipulation cgroups :"
                echo -e "      ${DGRAY}├─${NC} ${LRED}Risque d'échappement de conteneur via release_agent (CVE-2022-0492)${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Supprimer CAP_SYS_ADMIN : docker run --cap-drop=SYS_ADMIN${NC}"
                echo -e "      ${DGRAY}├─${NC} ${LYELLOW}Activer AppArmor/SELinux : docker run --security-opt apparmor=docker-default${NC}"
                echo -e "      ${DGRAY}└─${NC} ${LYELLOW}Ne PAS utiliser --privileged${NC}"
                echo
            fi
            
            echo -e "  ${LBLUE}[INFO]${NC} Ressources utiles :"
            echo -e "      ${DGRAY}├─${NC} CIS Docker Benchmark : https://www.cisecurity.org/benchmark/docker"
            echo -e "      ${DGRAY}├─${NC} ANSSI - Recommandations Docker : https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-au-deploiement-de-conteneurs-docker"
            echo -e "      ${DGRAY}├─${NC} OWASP Docker Security : https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
            echo -e "      ${DGRAY}└─${NC} Docker Security Best Practices : https://docs.docker.com/engine/security/"
            echo
        fi
        
        if [[ $SECURITY_SCORE -lt 50 ]]; then
            echo -e "  ${LRED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "  ${LRED}║${NC} ${LRED}[!]  ACTION REQUISE : Problèmes de sécurité critiques détectés${NC}    ${LRED}║${NC}"
            echo -e "  ${LRED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        elif [[ $SECURITY_SCORE -lt 80 ]]; then
            echo -e "  ${LYELLOW}╔═══════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "  ${LYELLOW}║${NC} ${LYELLOW}[!]  ATTENTION : Améliorations de sécurité recommandées${NC}          ${LYELLOW}║${NC}"
            echo -e "  ${LYELLOW}╚═══════════════════════════════════════════════════════════════════╝${NC}"
        fi
    else
        echo -e "  ${LGREEN}[+]${NC} ${LGREEN}Aucun problème de sécurité majeur détecté${NC}"
    fi
    echo
fi

# Section Recommandations d'optimisation
STOPPED_CONTAINERS=$($DOCKER_CMD ps -aq -f status=exited | wc -l)

# Récupérer les informations d'espace récupérable via docker system df
SYSTEM_DF_OUTPUT=$($DOCKER_CMD system df 2>/dev/null)
IMAGES_RECLAIMABLE=$(echo "$SYSTEM_DF_OUTPUT" | grep "^Images" | awk '{print $5}')
CONTAINERS_RECLAIMABLE=$(echo "$SYSTEM_DF_OUTPUT" | grep "^Containers" | awk '{print $5}')
VOLUMES_RECLAIMABLE=$(echo "$SYSTEM_DF_OUTPUT" | grep "^Local Volumes" | awk '{print $5}')
BUILD_CACHE_RECLAIMABLE=$(echo "$SYSTEM_DF_OUTPUT" | grep "^Build Cache" | awk '{print $5}')

if [[ $DANGLING_IMAGES -gt 0 ]] || [[ $UNUSED_VOLUMES -gt 0 ]] || [[ $STOPPED_CONTAINERS -gt 0 ]]; then
    print_section "RECOMMANDATIONS D'OPTIMISATION"
    echo
    
    echo -e "  ${LBLUE}[OPTIMISATION]${NC} Libération d'espace disque :"
    
    if [[ $DANGLING_IMAGES -gt 0 ]] && [[ -n "$IMAGES_RECLAIMABLE" ]]; then
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker image prune -a${NC} ${DGRAY}(${LYELLOW}$DANGLING_IMAGES${DGRAY} image(s) · ${LGREEN}~$IMAGES_RECLAIMABLE${DGRAY} récupérables)${NC}"
    fi
    
    if [[ $UNUSED_VOLUMES -gt 0 ]] && [[ -n "$VOLUMES_RECLAIMABLE" ]]; then
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker volume prune${NC} ${DGRAY}(${LYELLOW}$UNUSED_VOLUMES${DGRAY} volume(s) · ${LGREEN}~$VOLUMES_RECLAIMABLE${DGRAY} récupérables)${NC}"
    fi
    
    if [[ $STOPPED_CONTAINERS -gt 0 ]] && [[ -n "$CONTAINERS_RECLAIMABLE" ]]; then
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker container prune${NC} ${DGRAY}(${LYELLOW}$STOPPED_CONTAINERS${DGRAY} conteneur(s) · ${LGREEN}~$CONTAINERS_RECLAIMABLE${DGRAY} récupérables)${NC}"
    fi
    
    if [[ -n "$BUILD_CACHE_RECLAIMABLE" ]] && [[ "$BUILD_CACHE_RECLAIMABLE" != "0B" ]] && [[ "$BUILD_CACHE_RECLAIMABLE" != "0" ]]; then
        echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker builder prune${NC} ${DGRAY}(cache de build · ${LGREEN}~$BUILD_CACHE_RECLAIMABLE${DGRAY} récupérables)${NC}"
    fi
    
    echo -e "      ${DGRAY}├─${NC} ${LYELLOW}docker network prune${NC} ${DGRAY}(supprimer les réseaux non utilisés)${NC}"
    echo -e "      ${DGRAY}└─${NC} ${LYELLOW}docker system prune -a --volumes${NC} ${DGRAY}(nettoyage complet - ${LRED}ATTENTION aux données${DGRAY})${NC}"
    echo
fi
