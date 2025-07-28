#!/bin/env bash

# Verificador de Status para Serviços Web (padrão: Nginx)
#
# Realiza uma verificação completa de um serviço web, testando:
#   1. O status do processo via systemd.
#   2. Se a porta TCP está aberta e em modo de escuta (LISTEN).
#   3. Se o serviço retorna um código de status HTTP válido (2xx ou 3xx).
#
# USO:
#   sudo ./service_status_check.sh [OPÇÕES]
#
# OPÇÕES:
#   -s, --service <nome>    Define o serviço a ser verificado no systemd (padrão: nginx).
#   -h, --host <host>       Host para o teste de conexão HTTP (padrão: localhost).
#   -p, --port <porta>      Porta para o teste TCP e HTTP (padrão: 80).
#   -l, --log-file <path>   Caminho do arquivo para registrar a saída (padrão: /var/log/nginx_check.log).
#   -c, --continuous        Ativa o modo de verificação contínua.
#   -i, --interval <segs>   Intervalo em segundos para o modo contínuo (padrão: 60).
#       --help              Mostra esta mensagem de ajuda e sai.
#
# EXEMPLOS DE USO:
#   # Verificar o serviço nginx padrão na porta 80
#   sudo ./service_status_check.sh
#
#   # Verificar o serviço apache2 em modo contínuo a cada 5 minutos
#   sudo ./service_status_check.sh --service apache2 -c -i 300
#
#   # Salvar o log em um local personalizado
#   sudo ./service_status_check.sh -l /tmp/my_check.log
#
# -----------------------------------------------------------------------------
# Autor:    Thiago Nerton Macedo Alves
# Versão:   3.1

### Configuração e variáveis ###
#set -euo pipefail

### Valores Padrão
SERVICE_NAME="nginx"
PORT="80"
HOST="localhost"
LOG_FILE=""

CONTINUOUS_MODE=0
INTERVAL=60 
CYCLE=0
HAD_ERROR=false

readonly MONITOR_CONFIG_DIR="/etc/service_monitor"
readonly MONITOR_CONFIG_FILE="${MONITOR_CONFIG_DIR}/config.env"

### Configuração de Notificações
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

#### Cores para saída no terminal
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
 
### Função de ajuda ###
usage(){
    cat << EOF
Verificador de Status para Serviços Web

Realiza uma verificação completa de um serviço web, testando:
  1. O status do processo via systemd.
  2. Se a porta TCP está aberta e em modo de escuta (LISTEN).
  3. Se o serviço retorna um código de status HTTP válido (2xx ou 3xx).

USO:
  sudo $0 [OPÇÕES]

OPÇÕES:
  -s, --service <nome>    Define o serviço a ser verificado no systemd (padrão: nginx).
  -h, --host <host>       Host para o teste de conexão HTTP (padrão: localhost).
  -p, --port <porta>      Porta para o teste TCP e HTTP (padrão: 80).
  -l, --log-file <path>   Caminho do arquivo para registrar a saída (padrão: /var/log/<service>_check.log).
  -c, --continuous        Ativa o modo de verificação contínua.
  -i, --interval <segs>   Intervalo em segundos para o modo contínuo (padrão: 60).
      --help              Mostra esta mensagem de ajuda e sai.

NOTIFICAÇÕES:
  Para receber notificações de erro, configure as seguintes variáveis de ambiente:
  - DISCORD_WEBHOOK_URL
  - SLACK_WEBHOOK_URL
  - TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID

EOF
    exit 0
}

run_check_cycle() {
    log_info "Iniciando ciclo ${CYCLE} de verificação do serviço '${SERVICE_NAME}'..."
    ((CYCLE++))

    if run_all_checks; then
        if [[ "${HAD_ERROR}" = true ]]; then
            local recovery_message="O serviço '${SERVICE_NAME}' voltou a operar normalmente."
            log_success "${recovery_message}"
            send_notification "${recovery_message}" "RECOVERY"
            HAD_ERROR=false
        fi
    else
        HAD_ERROR=true
    fi
}

# Função de notificação
# Argumentos: 1=Mensagem de erro
send_notification() {
    local message="$1"
    local type="${2:-ERROR}"
    local hostname
    hostname=$(hostname)
    local full_message

    if [[ "${type}" == "RECOVERY" ]]; then
        full_message="✅ **Recuperação de Serviço**\n> **Servidor:** ${hostname}\n> **Serviço:** ${SERVICE_NAME}\n> **Info:** ${message}"
    else
        full_message="🚨 **Alerta de Monitoramento**\n> **Servidor:** ${hostname}\n> **Serviço:** ${SERVICE_NAME}\n> **Erro:** ${message}"
    fi

    # Discord
    if [[ -n "${DISCORD_WEBHOOK_URL}" ]]; then
        curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
        -d "{\"content\": \"${full_message}\"}" "${DISCORD_WEBHOOK_URL}" || log_warn "Falha ao enviar notificação para o Discord."
    fi

    # Slack
    if [[ -n "${SLACK_WEBHOOK_URL}" ]]; then
        curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
        -d "{\"text\": \"${full_message}\"}" "${SLACK_WEBHOOK_URL}" || log_warn "Falha ao enviar notificação para o Slack."
    fi

    # Telegram
    if [[ -n "${TELEGRAM_BOT_TOKEN}" && -n "${TELEGRAM_CHAT_ID}" ]]; then
        local telegram_url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
        curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
        -d "{\"chat_id\": \"${TELEGRAM_CHAT_ID}\", \"text\": \"${full_message}\", \"parse_mode\": \"Markdown\"}" "${telegram_url}" || log_warn "Falha ao enviar notificação para o Telegram."
    fi
}

# Função de erro
# Argumentos: 1=Mensagem de erro
# Envia uma notificação e encerra o script com erro.
die() {
    local error_message="$1"
    log_error "${error_message}"
    send_notification "${error_message}" "ERROR"

    if [[ "${CONTINUOUS_MODE}" = 1 ]]; then
        return 1
    else
        exit 1
    fi
}

check_dependencies(){
    local dependencies=("systemctl" "ss" "curl" "date" "dirname" "mkdir" "touch")
        for dep in "${dependencies[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            echo "A dependência '${dep}' não está instalada. Por favor, instale-a e tente novamente."
            exit 1
        fi
    done
}

# Função de logging
# Argumentos: 1=Nível, 2=Cor, 3=Mensagem
log() {
    local level="$1"
    local color="$2"
    local message="$3"
    
    # Formato para o arquivo de log (sem cor)
    local log_line
    log_line="[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}"
    
    # Formato para o console (com cores)
    local console_line
    console_line="${color}${log_line}${COLOR_RESET}"

    # Imprime no console e anexa ao arquivo de log
    echo -e "${console_line}"
    # Anexa no final do arquivo os logs sem cor.
    if [[ -n "${LOG_FILE}" ]]; then
        echo "${log_line}" >> "${LOG_FILE}"
    fi
}

# Funções auxiliares que usam a função 'log' central
log_info()    { log "INFO"    "${COLOR_BLUE}"   "$1"; }
log_success() { log "SUCCESS" "${COLOR_GREEN}"  "$1"; }
log_warn()    { log "WARN"    "${COLOR_YELLOW}" "$1"; }
log_error()   { log "ERROR"   "${COLOR_RED}"    "$1"; }

### Funções de Verificação ###
# Função que verifica o status do serviço via systemd
check_systemd_status() {
    log_info "Verificando o status do serviço '${SERVICE_NAME}' via systemd..."
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        die "O serviço '${SERVICE_NAME}' não está ativo."
    fi
    log_success "O serviço systemd está 'active (running)'."
}

# Função que verifica se a porta TCP está em modo LISTEN
check_port_listening() {
    log_info "Verificando se a porta TCP/${PORT} está em modo LISTEN..."
    # Comando 'ss' -H (sem cabeçalho), -l (escutando), -t (tcp), -n (numérico). A checagem verifica se a saída não é nula.
    if ! ss -Hltn "sport = :${PORT}" | grep -q 'LISTEN'; then
        die "Nenhum processo está escutando na porta TCP/${PORT}."
    fi
    log_success "Um processo está escutando na porta ${PORT}."
}

# Função que verifica a resposta HTTP
# Argumentos: 1=Host, 2=Porta
check_http_response() {
    log_info "Realizando uma requisição HTTP para http://${HOST}:${PORT}..."
    local http_code
    local curl_exit_code=0

    # -o /dev/null: Descarta o corpo da resposta HTML.
    # -s: modo quiet.
    # -w "%{http_code}": Instrução para o curl imprimir apenas o código de STATUS HTTP.
    # --max-time 5: Define um tempo limite de 5 segundos para a resposta.

    http_code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 5 "http://${HOST}:${PORT}") || curl_exit_code=$?

    if [[ ${curl_exit_code} -ne 0 ]]; then
        die "Falha ao executar a requisição com cURL (código de saída: ${curl_exit_code})."
    fi

    if [[ "${http_code}" =~ ^(2..|3..)$ ]]; then
    # Se o código de status for 2XX ou 3XX ele registra como funcional 
        log_success "O servidor respondeu com um código funcional: ${http_code}."
    else
        die "O servidor respondeu com um código de erro ou inesperado: ${http_code}."
    fi
}

run_all_checks() {
    check_systemd_status && check_port_listening && check_http_response
}

cleanup() {
    log_info "Script interrompido pelo usuário."
    exit 0
}
trap cleanup INT TERM

# Função Principal
main() {
    if [ ${CYCLE} -eq 0 ]; then
        log_info "Iniciando verificação do ${SERVICE_NAME}"
    fi
    log_info "Host: ${HOST}, Porta: ${PORT}, Log: ${LOG_FILE}"

    if [[ "${CONTINUOUS_MODE}" = 1 ]]; then
        log_info "Modo contínuo ativado. Verificando a cada ${INTERVAL} segundos. Pressione [Ctrl+C] para parar."
        while true; do
            run_check_cycle
            log_info "Aguardando ${INTERVAL}s para o próximo ciclo..."
            sleep "${INTERVAL}"
        done
    else
        run_all_checks
        log_success "Verificação concluída. O serviço '${SERVICE_NAME}' está operando normalmente."
    fi
}

validate_arg() {
    if [[ -z "${2-}" || "${2-}" =~ ^- ]]; then
        echo "ERRO: A opção '$1' requer um argumento válido." >&2
        exit 1
    fi
}

load_config_file() {
    if [[ -f "${MONITOR_CONFIG_FILE}" ]]; then
        # shellcheck disable=SC1090
        source "${MONITOR_CONFIG_FILE}"
        log_info "Configurações personalizadas carregadas de ${MONITOR_CONFIG_FILE}"
    fi
}

load_config_file


check_dependencies


# Tratamento de argumentos da linha de comando
while [[ $# -gt 0 ]]; do
    case "$1" in
    -s|--service)
        validate_arg "$1" "$2"
        SERVICE_NAME="$2"
        shift 2
    ;;

    -h|--host)
        validate_arg "$1" "$2"
        HOST="$2"
        shift 2
    ;;
    -c|--continuous)
        CONTINUOUS_MODE=1;
        shift 1
    ;;
    -i|--interval)
        validate_arg "$1" "$2"
        if ! [[ "$2" =~ ^[0-9]+$ ]]; then
            die "O valor para o intervalo ('$2') não é um número válido."
        fi
        INTERVAL="$2"
        shift 2
    ;;
    -p|--port)
        validate_arg "$1" "$2"
        # Validação: Se o argumento é um número inteiro
        if ! [[ "$2" =~ ^[0-9]+$ ]]; then
            die "O valor para a porta ('$2') não é um número válido."
        fi

        # Validação: O número da porta está no intervalo correto (1-65535)
        if (( $2 < 1 || $2 > 65535 )); then
            die "A porta '$2' está fora do intervalo válido (1-65535)."
        fi
        PORT="$2"
        shift 2
    ;;

    -l|--log-file)
        validate_arg "$1" "$2"
        LOG_FILE="$2"
        shift 2
    ;;

    --help)
        usage
    ;;
    
    *)
        die "Opção desconhecida: '$1'. Use --help para ver as opções."
    ;;
  esac
done

if [[ -z "${LOG_FILE}" ]]; then
    DEFAULT_LOG_FILE="/var/log/${SERVICE_NAME}_check.log"
    log_dir=$(dirname "${DEFAULT_LOG_FILE}")
    
    if [[ -w "${log_dir}" ]]; then
        LOG_FILE="${DEFAULT_LOG_FILE}"
    else
        log_warn "Sem permissão de escrita em '${log_dir}'. Os logs não serão salvos em arquivo. Execute como root ou use -l."
    fi
fi

if [[ -n "${LOG_FILE}" ]]; then
    log_dir=$(dirname "${LOG_FILE}")
    if ! mkdir -p "${log_dir}"; then
        log_error "Não foi possível criar o diretório de log em '${log_dir}'. Verifique as permissões."
        exit 1
    fi

    if ! touch "${LOG_FILE}"; then
        log_error "Não foi possível criar ou acessar o arquivo de log em '${LOG_FILE}'. Verifique as permissões."
        exit 1
    fi
fi

main
