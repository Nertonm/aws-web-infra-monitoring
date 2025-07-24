#!/bin/bash

# Health Check do Nginx com Log
# Verifica o status do serviço Nginx e registra eventos em log estruturado.
# Uso:          sudo XXXX 
#
# Autor:        Thiago Nerton Macedo Alves
# Versão:       1.1


set -euo pipefail
# -e: Para o script no caso de qualquer erro.
# -u: Torna variáveis não definidas como um erro.
# -o pipefail: Numa sequência de pipe a saida vai ser a do último comando com erro.

# Variáveis de Configuração 
readonly SERVICE_NAME="nginx"
readonly PORT="80"
readonly HOST="localhost"

# Localização do arquivo de log. 
readonly LOG_FILE="/var/log/nginx_check.log"

# Cores do Log
readonly COLOR_RESET="\e[0m"
readonly COLOR_GREEN="\e[0;32m"
readonly COLOR_BLUE="\e[0;34m"
readonly COLOR_RED="\e[0;31m"
readonly COLOR_YELLOW="\e[0;33m"

# Função de logging
# Argumentos: 1=Nível, 2=Cor, 3=Mensagem
log() {
    local level="$1"
    local color="$2"
    local message="$3"
    
    # Formato para o arquivo de log 
    local log_line
    log_line="[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}"
    
    # Formato para o console (com cores)
    local console_line
    console_line="${color}${log_line}${COLOR_RESET}"

    # Imprime no console e anexa ao arquivo de log
    echo -e "${console_line}"
    # Anexa no final do arquivo os logs sem cor.
    echo "${log_line}" >> "${LOG_FILE}"
}

# Funções auxiliares que usam a função 'log' central
log_info()    { log "INFO"    "${COLOR_BLUE}"   "$1"; }
log_success() { log "SUCCESS" "${COLOR_GREEN}"  "$1"; }
log_warn()    { log "WARN"    "${COLOR_YELLOW}" "$1"; }
log_error()   { 
    log "ERROR"   "${COLOR_RED}"    "$1"
    # Erros são enviados para stderr para serem capturados por outras ferramentas.
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1" >&2
}

# Função Principal
main() {
    # Garante que o arquivo de log existe e o script tem permissão para escrever nele
    touch "${LOG_FILE}" || { echo "ERRO: Não foi possível criar ou acessar o arquivo de log em ${LOG_FILE}. Execute como Administrador." >&2; exit 1; }
    log_info "Iniciando verificação do ${SERVICE_NAME}"
    
    # Nível 1: Status do serviço
    log_info "Verificando o status do serviço '${SERVICE_NAME}' via systemd..."
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_error "O serviço '${SERVICE_NAME}' não está ativo."
        exit 1
    fi
    log_success "O serviço systemd está 'active (running)'."

    # Nível 2: Porta em modo LISTEN
    log_info "Verificando se a porta TCP/${PORT} está em modo LISTEN..."
    if ! ss -tlpn | grep -q ":${PORT}\b"; then
        log_error "Nenhum processo está escutando na porta ${PORT}."
        exit 1
    fi
    log_success "Um processo está escutando na porta ${PORT}."

    # Nível 3: Resposta HTTP
    log_info "Realizando uma requisição HTTP para http://${HOST}:${PORT}..."
    local http_code
    http_code=$(curl -o /dev/null -s -w "%{http_code}" --max-time 5 "http://${HOST}:${PORT}")
    # -o /dev/null: Descarta o corpo da resposta HTML.
    # -s: modo quiet.
    # -w "%{http_code}": Instrução para o curl imprimir apenas o código de STATUS HTTP.
    # --max-time 5: Define um tempo limite de 5 segundos para a resposta.

    if [[ "${http_code}" =~ ^(2..|3..)$ ]]; then
    # Se o código de status for 2XX ou 3XX ele registra como funcional 
        log_success "O servidor respondeu com um código funcional: ${http_code}."
    else
        log_error "O servidor respondeu com um código de erro: ${http_code}."
        exit 1
    fi

    log_info "Verificação concluída com sucesso"
}

# Executa a função principal
main
