#!/bin/env bash

# Verificador de Status para Serviços Web (padrão: Nginx)
#
# Realiza uma verificação completa de um serviço web, testando:
#   1. O status do processo via systemd.
#   2. Se a porta TCP está aberta e em modo de escuta (LISTEN).
#   3. Se o serviço retorna um código de status HTTP válido (2xx ou 3xx).
#
# USO:
#   sudo ./checking_nginx.sh [OPÇÕES]
#
# OPÇÕES:
#   -s, --service <nome>    Define o serviço a ser verificado no systemd (padrão: nginx).
#   -h, --host <host>       Host para o teste de conexão HTTP (padrão: localhost).
#   -p, --port <porta>      Porta para o teste TCP e HTTP (padrão: 80).
#   -l, --log-file <path>   Caminho do arquivo para registrar a saída (padrão: /var/log/nginx_check.log).
#       --help              Mostra esta mensagem de ajuda e sai.
#
# EXEMPLOS DE USO:
#   # Verificar o serviço nginx padrão na porta 80
#   sudo ./checking_nginx.sh
#
#   # Verificar o serviço apache2 em uma porta diferente
#   sudo ./checking_nginx.sh --service apache2 --port 8080
#
#   # Salvar o log em um local personalizado
#   sudo ./checking_nginx.sh -l /tmp/my_check.log
#
# -----------------------------------------------------------------------------
# Autor:    Thiago Nerton Macedo Alves
# Versão:   2.1


set -euo pipefail
# -e: Para o script no caso de qualquer erro.
# -u: Torna variáveis não definidas como um erro.
# -o pipefail: Numa sequência de pipe a saida vai ser a do último comando com erro.

# Cores do Log
# Usa cores somente se o terminal suportar
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

# Valores Padrão (podem ser sobrescritos por argumentos)
SERVICE_NAME="nginx"
PORT="80"
HOST="localhost"
# Localização do arquivo de log. 
LOG_FILE="/var/log/nginx_check.log"

usage(){
    # Extrai a seção de comentários
    sed -n 's/^# //p; /^set -euo pipefail/q' "$0"
    exit 0
}


die() {
  echo "Erro: $1" >&2
  echo "Use --help para mais informações." >&2
  exit 1
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
    echo "${log_line}" >> "${LOG_FILE}"
}

# Funções auxiliares que usam a função 'log' central
log_info()    { log "INFO"    "${COLOR_BLUE}"   "$1"; }
log_success() { log "SUCCESS" "${COLOR_GREEN}"  "$1"; }
log_warn()    { log "WARN"    "${COLOR_YELLOW}" "$1"; }
log_error()   { log "ERROR"   "${COLOR_RED}"    "$1"
    # Erros são enviados para stderr para serem capturados por outras ferramentas.
    echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1" >&2
}

# Função Principal
main() {
    # Garante que o arquivo de log existe e o script tem permissão para escrever nele
    touch "${LOG_FILE}" || { echo "ERRO: Não foi possível criar ou acessar o arquivo de log em ${LOG_FILE}. Execute como root." >&2; exit 1; }
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


# Tratamento de argumentos da linha de comando
while [[ $# -gt 0 ]]; do
    case "$1" in
    -s|--service)
        # Validação: O segundo argumento existe e não é outra opção
        if [[ -z "$2" || "$2" =~ ^- ]]; then
            die "A opção '$1' requer um nome de serviço como argumento."
        fi
        SERVICE_NAME="$2"
        shift 2
    ;;

    -h|--host)
        if [[ -z "$2" || "$2" =~ ^- ]]; then
            die "A opção '$1' requer um host como argumento."
        fi
        HOST="$2"
        shift 2
    ;;

    -p|--port)
        if [[ -z "$2" || "$2" =~ ^- ]]; then
            die "A opção '$1' requer um número de porta como argumento."
        fi
      
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
        if [[ -z "$2" || "$2" =~ ^- ]]; then
            die "A opção '$1' requer um caminho para o arquivo de log."
        fi

        # Validação: O diretório do arquivo de log existe e temos permissão para escrever nele?
        log_dir=$(dirname "$2")
        if ! [[ -d "$log_dir" && -w "$log_dir" ]]; then
            die "O diretório do arquivo de log ('$log_dir') não existe ou não tem permissão de escrita."
        fi
        LOG_FILE="$2"
        shift 2
    ;;

    --help)
        usage
    ;;
    
    *)
        # Caso Base
        die "Opção desconhecida '$1'."
    ;;
  esac
done

# Função principal
main
