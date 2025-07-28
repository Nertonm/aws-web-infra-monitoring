#!/bin/env bash

# Realiza a instalação e configuração do Nginx de forma automatizada,
# adaptando-se a diferentes distribuições Linux. As tarefas incluem:
#   1. Detecção do sistema operacional (famílias Debian e Red Hat).
#   2. Instalação do Nginx usando o gerenciador de pacotes nativo (apt, dnf, yum).
#   3. Habilitação e configuração do firewall UFW para permitir tráfego HTTP.
#   4. Criação de uma página de teste, com backup da página original.
#   5. Habilitação, inicialização e verificação do serviço Nginx via systemd.
#   6. Configuração para reinicialização automática caso o serviço pare.
#
# USO:
#   sudo ./instalador_nginx.sh
#
#   Modo Não-Interativo (Automático):
#     sudo ./instalador_nginx.sh -y
#
#   Modo Não-Interativo com Webhooks para Monitoramento:
#     sudo ./instalador_nginx.sh -y \
#       --discord-webhook "URL_DISCORD" \
#       --slack-webhook "URL_SLACK" \
#       --telegram-token "TOKEN_BOT" \
#       --telegram-chat-id "CHAT_ID"
#
# Autor:           Thiago Nerton Macedo Alves
# Versão:          3.3
# Compatibilidade: Debian, Ubuntu, RHEL, CentOS, Fedora, Amazon Linux
# Dependências:    systemd, ufw, e um dos seguintes: (apt | dnf | yum)

set -euo pipefail
# -e: Termina a execução imediatamente no caso de erro.
# -u: Trata variáveis não definidas como erro.
# -o pipefail: faz com que o código de retorno, seja o do último comando que falhou.

readonly REPO_URL="https://github.com/Nertonm/aws-web-infra-monitoring"
readonly CLONE_DIR="/opt/aws-web-infra-monitoring"

readonly MONITOR_SCRIPT_NAME="service_status_check.sh" 
readonly MONITOR_SCRIPT_PATH="/usr/local/bin/service_status_check.sh"
readonly MONITOR_CONFIG_DIR="/etc/service_monitor"
readonly MONITOR_CONFIG_FILE="${MONITOR_CONFIG_DIR}/config.env"
readonly MONITOR_SERVICE_FILE="/etc/systemd/system/monitor-nginx.service"

readonly NGINX_PACKAGE="nginx"
NGINX_ROOT_DIR=""
PKG_MANAGER=""
AUTO_YES=0
INSTALL_MONITOR_FLAG=0

DISCORD_WEBHOOK_ARG=""
SLACK_WEBHOOK_ARG=""
TELEGRAM_TOKEN_ARG=""
TELEGRAM_CHAT_ID_ARG=""

if [[ -t 1 ]]; then
    readonly COLOR_RESET="\e[0m"
    readonly COLOR_GREEN="\e[0;32m"
    readonly COLOR_BLUE="\e[0;34m"
    readonly COLOR_RED="\e[0;31m"
    readonly COLOR_YELLOW="\e[0;33m"
else
    readonly COLOR_RESET=""
    readonly COLOR_GREEN=""
    readonly COLOR_BLUE=""
    readonly COLOR_RED=""
    readonly COLOR_YELLOW=""
fi

log_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1";}
log_success() { echo -e "${COLOR_GREEN}[SUCESSO]${COLOR_RESET} $1";}
log_error() { echo -e "${COLOR_RED}[ERRO]${COLOR_RESET} $1" >&2;}
log_warn() { echo -e "${COLOR_YELLOW}[AVISO]${COLOR_RESET} $1";}

cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "O script falhou com o código de saída: ${exit_code}"
    fi
}
trap cleanup EXIT

verificar_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Este script precisa ser executado como root. Use 'sudo $0'"
        exit 1
    fi
}

configurar_webhooks() {
    log_info "Configurando credenciais de notificação..."
    mkdir -p "${MONITOR_CONFIG_DIR}"
    
    > "${MONITOR_CONFIG_FILE}"

    local DISCORD_WEBHOOK_URL=""
    local SLACK_WEBHOOK_URL=""
    local TELEGRAM_BOT_TOKEN=""
    local TELEGRAM_CHAT_ID=""

    if [[ -n "${DISCORD_WEBHOOK_ARG}" ]]; then
        DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_ARG}"
        log_info "  -> Usando URL do Discord fornecida por parâmetro."
    elif [[ ${AUTO_YES} -eq 0 ]]; then
        read -p "  -> URL do Webhook do Discord (deixe em branco para pular): " DISCORD_WEBHOOK_URL
    fi

    if [[ -n "${SLACK_WEBHOOK_ARG}" ]]; then
        SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_ARG}"
        log_info "  -> Usando URL do Slack fornecida por parâmetro."
    elif [[ ${AUTO_YES} -eq 0 ]]; then
        read -p "  -> URL do Webhook do Slack (deixe em branco para pular): " SLACK_WEBHOOK_URL
    fi
    
    if [[ -n "${TELEGRAM_TOKEN_ARG}" ]]; then
        TELEGRAM_BOT_TOKEN="${TELEGRAM_TOKEN_ARG}"
        log_info "  -> Usando Token do Telegram fornecido por parâmetro."
        
        if [[ -n "${TELEGRAM_CHAT_ID_ARG}" ]]; then
            TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID_ARG}"
            log_info "  -> Usando Chat ID do Telegram fornecido por parâmetro."
        elif [[ ${AUTO_YES} -eq 0 ]]; then
            while [[ -z "${TELEGRAM_CHAT_ID-}" ]]; do
                read -p "  -> Chat ID do Telegram (obrigatório): " TELEGRAM_CHAT_ID
                if [[ -z "${TELEGRAM_CHAT_ID}" ]]; then
                    log_warn "O Chat ID do Telegram é obrigatório quando o token é fornecido."
                fi
            done
        else #
            log_error "O parâmetro '--telegram-chat-id' é obrigatório quando '--telegram-token' é usado no modo não-interativo."
            exit 1
        fi
    elif [[ ${AUTO_YES} -eq 0 ]]; then 
        read -p "  -> Token do Bot do Telegram (deixe em branco para pular): " TELEGRAM_BOT_TOKEN
        if [[ -n "${TELEGRAM_BOT_TOKEN}" ]]; then
            while [[ -z "${TELEGRAM_CHAT_ID-}" ]]; do
                read -p "  -> Chat ID do Telegram (obrigatório): " TELEGRAM_CHAT_ID
                if [[ -z "${TELEGRAM_CHAT_ID}" ]]; then
                    log_warn "O Chat ID do Telegram é obrigatório quando o token é fornecido."
                fi
            done
        fi
    fi

    echo "DISCORD_WEBHOOK_URL='${DISCORD_WEBHOOK_URL}'" >> "${MONITOR_CONFIG_FILE}"
    echo "SLACK_WEBHOOK_URL='${SLACK_WEBHOOK_URL}'" >> "${MONITOR_CONFIG_FILE}"
    echo "TELEGRAM_BOT_TOKEN='${TELEGRAM_BOT_TOKEN}'" >> "${MONITOR_CONFIG_FILE}"
    echo "TELEGRAM_CHAT_ID='${TELEGRAM_CHAT_ID:-}'" >> "${MONITOR_CONFIG_FILE}"

    chmod 600 "${MONITOR_CONFIG_FILE}"
    log_success "Credenciais salvas em ${MONITOR_CONFIG_FILE}"
}


clonar_repositorio() {
    if ! command -v git &>/dev/null; then
        log_error "O comando 'git' é necessário, mas não foi encontrado."
        log_info "Por favor, instale o git (ex: sudo apt install git) e execute novamente."
        exit 1
    fi

    local CLONE_NECESSARIO=0 

    if [[ ! -d "${CLONE_DIR}" ]]; then
        CLONE_NECESSARIO=1
    else
        log_warn "O diretório de destino '${CLONE_DIR}' já existe."
        if [[ ${AUTO_YES} -eq 1 ]]; then
            log_info "Modo automático: Removendo o diretório para um clone limpo."
            rm -rf "${CLONE_DIR}"
            CLONE_NECESSARIO=1
        else
            read -p "Deseja remover e clonar novamente? (s/N): " -r RESPOSTA
            if [[ "$RESPOSTA" =~ ^[sS]$ ]]; then
                log_info "Removendo diretório existente."
                rm -rf "${CLONE_DIR}"
                CLONE_NECESSARIO=1
            else
                log_info "Usando a versão existente no diretório. A clonagem será pulada."
                CLONE_NECESSARIO=0
            fi
        fi
    fi

    if [[ ${CLONE_NECESSARIO} -eq 1 ]]; then
        log_info "Clonando repositório de ${REPO_URL}..."
        if ! git clone --depth 1 "${REPO_URL}" "${CLONE_DIR}"; then
            log_error "O comando 'git clone' falhou."
            log_error "Verifique sua conexão com a internet e se a URL do repositório está correta."
            exit 1
        fi
    fi
    
    local SCRIPT_ORIGEM="${CLONE_DIR}/${MONITOR_SCRIPT_NAME}"
    if [[ ! -f "${SCRIPT_ORIGEM}" ]]; then
        log_error "O script esperado '${MONITOR_SCRIPT_NAME}' não foi encontrado em '${CLONE_DIR}'."
        log_error "A clonagem pode ter falhado ou o repositório não contém o arquivo."
        exit 1
    fi
    
    log_info "Instalando '${MONITOR_SCRIPT_NAME}' em '${MONITOR_SCRIPT_PATH}'..."
    if ! cp "${SCRIPT_ORIGEM}" "${MONITOR_SCRIPT_PATH}"; then
        log_error "Falha ao copiar o script para '${MONITOR_SCRIPT_PATH}'. Verifique as permissões."
        exit 1
    fi

    if ! chmod +x "${MONITOR_SCRIPT_PATH}"; then
         log_error "Falha ao tornar o script executável em '${MONITOR_SCRIPT_PATH}'. Verifique as permissões."
         exit 1
    fi
    
    log_success "Script de monitoramento instalado com sucesso."
}

instalar_monitor_systemd() {
    log_info "Configurando o monitor como um serviço systemd..."
    cat <<EOF > "${MONITOR_SERVICE_FILE}"
[Unit]
Description=Monitor de Serviço Nginx (clonado de Git)
After=nginx.service

[Service]
ExecStart=${MONITOR_SCRIPT_PATH} -c -i 60 -s nginx
User=root
Restart=always
RestartSec=30s

[Install]
WantedBy=multi-user.target
EOF
    local service_name
service_name=$(basename "${MONITOR_SERVICE_FILE}")


    systemctl daemon-reload
    systemctl enable "${service_name}" --now >/dev/null
    log_success "Serviço de monitoramento '${service_name}' habilitado e iniciado."
    log_info "Use 'systemctl status ${service_name}' para ver o status."
}

instalar_monitor_cron() {
    log_info "Configurando o monitor via cron @reboot..."

    (crontab -l 2>/dev/null | grep -vF "${MONITOR_SCRIPT_PATH}" || true ; echo "* * * * * ${MONITOR_SCRIPT_PATH} &>> /var/log/monitor_nginx.log") | crontab -

    log_success "Tarefa cron configurada. O monitor será executado a cada minuto."
    log_warn "Logs serão gravados em /var/log/monitor_nginx.log. Considere configurar a rotação de logs."
}

instalar_monitor() {
    if [[ ${INSTALL_MONITOR_FLAG} -eq 0 && ${AUTO_YES} -eq 0 ]]; then
        read -p "Deseja instalar o script de monitoramento via Git? (s/N): " -r RESPOSTA
        if [[ ! "$RESPOSTA" =~ ^[sS]$ ]]; then
            log_info "Instalação do monitor pulada."; return;
        fi
    elif [[ ${INSTALL_MONITOR_FLAG} -eq 0 ]]; then
        return 
    fi
    
    configurar_webhooks
    clonar_repositorio

    local ESCOLHA="1" 
    if [[ ${AUTO_YES} -eq 0 ]]; then
        read -p "Como deseja executar o monitor? [1] systemd (recomendado), [2] cron: " -r ESCOLHA
    fi

    case "${ESCOLHA}" in
        1) instalar_monitor_systemd;;
        2) instalar_monitor_cron;;
        *) log_warn "Opção inválida. Pulando configuração de inicialização automática.";;
    esac
}

confirmar_execucao() {
    if [[ ${AUTO_YES} -eq 1 ]]; then
        return 0
    fi

    log_info "Este script irá realizar as seguintes ações:"
    echo "  1. Instalar o pacote Nginx ('${NGINX_PACKAGE}')."
    echo "  2. Configurar o firewall (UFW ou firewalld) para permitir tráfego HTTP."
    echo "  3. Criar uma página de teste no diretório padrão do Nginx (${NGINX_ROOT_DIR})."
    echo "  4. Habilitar e iniciar o serviço Nginx."
    echo "  5. Configuração para reinicialização automática caso o serviço pare."

    read -p "Você deseja continuar? (s/N): " -r RESPOSTA
    if [[ ! "$RESPOSTA" =~ ^[sS]$ ]]; then
        log_info "Operação cancelada pelo usuário."
        exit 0
    fi
}

detectar_distro_e_configurar() {
    log_info "Detectando o sistema operacional e configurando variáveis..."
    if ! source /etc/os-release; then
        log_error "Não foi possível encontrar o arquivo /etc/os-release para detectar a distro."
        exit 1
    fi
    
    case "${ID_LIKE:-$ID}" in
        debian)
            log_info "Sistema da família Debian detectado."
            PKG_MANAGER="apt-get"
            NGINX_ROOT_DIR="/var/www/html"
        ;;
        rhel|fedora)
            log_info "Sistema da família Red Hat detectado."
            NGINX_ROOT_DIR="/usr/share/nginx/html"
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
            elif command -v yum &>/dev/null; then
                PKG_MANAGER="yum"
            else
                log_error "Nem 'dnf' nem 'yum' foram encontrados neste sistema RHEL-like."
                exit 1
            fi
        ;;
        *)
            log_error "Distribuição Linux não suportada: '${ID}'. Não é possível continuar."
            exit 1
        ;;
    esac
    log_success "Configurações para '${ID}' definidas."
}

instalar_pacotes() {

    log_info "Verificando se o Nginx já está instalado..."
    if ( [[ "$PKG_MANAGER" == "apt-get" ]] && dpkg -s "${NGINX_PACKAGE}" &>/dev/null ) || \
       ( [[ "$PKG_MANAGER" != "apt-get" ]] && rpm -q "${NGINX_PACKAGE}" &>/dev/null ); then
        log_info "O pacote '${NGINX_PACKAGE}' já está instalado."
        return 0
    fi

    log_info "Instalando o pacotes '${NGINX_PACKAGE}', git, curl e iproute2 com '${PKG_MANAGER}'..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        apt-get update -qq
        apt-get install -y -qq "${NGINX_PACKAGE}" git curl iproute2
    else
        "$PKG_MANAGER" install -y "${NGINX_PACKAGE}" git curl iproute2
    fi
    log_success "Nginx, Git, Curl e iproute2 instalados com sucesso."
}


configurar_firewall() {
    log_info "Configurando o firewall..."
    if command -v ufw &>/dev/null; then
        log_info "Firewall UFW detectado."
        log_info "Verificando e permitindo tráfego na porta padrão do SSH (22/tcp)..."
        ufw allow 22/tcp
        if ! ufw status | grep -q "Status: active"; then
            log_info "Ativando o UFW..."
            ufw --force enable
        fi
        log_info "Permitindo tráfego 'Nginx HTTP' no UFW..."
        ufw allow "Nginx HTTP"
        log_success "UFW configurado."
        ufw status
    elif command -v firewall-cmd &>/dev/null; then
        log_info "Firewall firewalld detectado."
        if ! systemctl is-active --quiet firewalld; then
            log_info "Iniciando e habilitando o firewalld..."
            systemctl start firewalld
            systemctl enable firewalld
        fi
        log_info "Permitindo tráfego 'http' no firewalld..."
        firewall-cmd --add-service=http --permanent
        firewall-cmd --reload
        log_success "firewalld configurado."
        firewall-cmd --list-services
    else
        log_info "Nenhum firewall (UFW ou firewalld) encontrado. Pulando esta etapa."
    fi
}


criar_pagina_teste() {
    local NGINX_INDEX_FILE="${NGINX_ROOT_DIR}/index.html"

    if [[ -f "${NGINX_INDEX_FILE}" ]]; then
        local backup_file="${NGINX_INDEX_FILE}.bak.$(date +%F-%T)"
        log_info "Arquivo '${NGINX_INDEX_FILE}' existente. Criando backup em '${backup_file}'."
        mv "${NGINX_INDEX_FILE}" "${backup_file}"
    fi

    log_info "Criando arquivo de teste em '${NGINX_INDEX_FILE}'..."
    cat <<EOF > "${NGINX_INDEX_FILE}"
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Olá Mundo com Nginx</title>
</head>
<body>
    <h1>Instalação do Nginx bem-sucedida!</h1>
    <p>Esta página foi gerada automaticamente pelo script de instalação em um sistema <strong>${PRETTY_NAME:-Linux}</strong>.</p>
</body>
</html>
EOF
    log_success "Página de teste criada com sucesso."
}

finalizar_e_verificar() {
    log_info "Habilitando o serviço Nginx para iniciar com o sistema..."
    systemctl enable "${NGINX_PACKAGE}"

    log_info "Reiniciando o Nginx para aplicar as configurações..."
    systemctl restart "${NGINX_PACKAGE}"

    log_info "Verificando o status do serviço Nginx..."
    if ! systemctl is-active --quiet "${NGINX_PACKAGE}"; then
        log_error "O serviço Nginx falhou ao iniciar. Verifique o status detalhado abaixo:"
        systemctl status "${NGINX_PACKAGE}" --no-pager
        exit 1
    else
        log_success "O serviço Nginx está ativo e rodando."
    fi

    local ip_address
    ip_address=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d'/' -f1 | head -n 1)
    log_success "Instalação concluída!"
    log_info "Acesse http://${ip_address} no seu navegador para testar."
}

configurar_restart(){
    log_info "Configurando o serviço Nginx para reiniciar automaticamente"
    OVERRIDE_DIR="/etc/systemd/system/nginx.service.d"
    OVERRIDE_FILE="$OVERRIDE_DIR/override.conf"
    log_info "Criando o diretório de override: $OVERRIDE_DIR"
mkdir -p "$OVERRIDE_DIR"
    cat <<EOF > "${OVERRIDE_FILE}"
[Service]
Restart=on-failure
RestartSec=5s
EOF

    log_info "Recarregando a configuração do systemd..."
    systemctl daemon-reload
    log_success "Configuração de reinício automático aplicada."
}

main() {
    verificar_root

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes)
                AUTO_YES=1
                INSTALL_MONITOR_FLAG=1
                shift
                ;;
            --install-monitor)
                INSTALL_MONITOR_FLAG=1
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            --discord-webhook)
                DISCORD_WEBHOOK_ARG="${2-}"
                shift 2
                ;;
            --slack-webhook)
                SLACK_WEBHOOK_ARG="${2-}"
                shift 2
                ;;
            --telegram-token)
                TELEGRAM_TOKEN_ARG="${2-}"
                shift 2
                ;;
            --telegram-chat-id)
                TELEGRAM_CHAT_ID_ARG="${2-}"
                shift 2
                ;;
            *)
                log_error "Opção desconhecida: $1"
                print_usage
                exit 1
                ;;
        esac
    done

    detectar_distro_e_configurar
    confirmar_execucao
    instalar_pacotes
    configurar_firewall
    criar_pagina_teste
    configurar_restart
    instalar_monitor
    finalizar_e_verificar
}

main "$@"
