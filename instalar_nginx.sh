#!/bin/env bash

# Realiza a instalação e configuração do Nginx de forma automatizada,
# adaptando-se a diferentes distribuições Linux. As tarefas incluem:
#   1. Detecção do sistema operacional (famílias Debian e Red Hat).
#   2. Instalação do Nginx usando o gerenciador de pacotes nativo (apt, dnf, yum).
#   3. Habilitação e configuração do firewall UFW para permitir tráfego HTTP.
#   4. Criação de uma página de teste, com backup da página original.
#   5. Habilitação, inicialização e verificação do serviço Nginx via systemd.
#
# USO:
#   sudo ./instalador_nginx.sh
#
# -----------------------------------------------------------------------------
# Autor:           Thiago Nerton Macedo Alves
# Versão:          2.0
# Compatibilidade: Debian, Ubuntu, RHEL, CentOS, Fedora, Amazon Linux
# Dependências:    systemd, ufw, e um dos seguintes: (apt | dnf | yum)

set -euo pipefail
# -e: Termina a execução imediatamente no caso de erro.
# -u: Trata variáveis não definidas como erro.
# -o pipefail: faz com que o código de retorno, seja o do último comando que falhou.

# Constantes
readonly NGINX_PACKAGE="nginx"
NGINX_ROOT_DIR=""
PKG_MANAGER=""

# Usa cores somente se o terminal suportar
if [[ -t 1 ]]; then
    readonly COLOR_RESET="\e[0m"
    readonly COLOR_GREEN="\e[0;32m"
    readonly COLOR_BLUE="\e[0;34m"
    readonly COLOR_RED="\e[0;31m"
else
    readonly COLOR_RESET=""
    readonly COLOR_GREEN=""
    readonly COLOR_BLUE=""
    readonly COLOR_RED=""
fi

log_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1";}
log_success() { echo -e "${COLOR_GREEN}[SUCESSO]${COLOR_RESET} $1";}
log_error() { echo -e "${COLOR_RED}[ERRO]${COLOR_RESET} $1" >&2;}

cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "O script falhou com o código de saída: ${exit_code}"
    fi
}
# O comando 'trap' garante que esta função seja chamada ao final ou em caso de erro.
trap cleanup EXIT

# Funções Principais
verificar_root() {
    # $(id -u): retorna o ID numérico do usuário atual. O usuário root sempre tem o ID 0.
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Este script precisa ser executado como root. Use 'sudo $0'"
        exit 1
    fi
}

confirmar_execucao() {
    # Se o primeiro argumento for -y ou --yes, pula a confirmação
    if [[ "${1-}" == "-y" || "${1-}" == "--yes" ]]; then
        return 0
    fi

    log_info "Este script irá realizar as seguintes ações:"
    echo "  1. Instalar o pacote Nginx ('${NGINX_PACKAGE}')."
    echo "  2. Configurar o firewall (UFW ou firewalld) para permitir tráfego HTTP."
    echo "  3. Criar uma página de teste no diretório padrão do Nginx (${NGINX_ROOT_DIR})."
    echo "  4. Habilitar e iniciar o serviço Nginx."
    
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

    log_info "Instalando o pacote '${NGINX_PACKAGE}' com '${PKG_MANAGER}'..."
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        apt-get update -qq
        apt-get install -y -qq "${NGINX_PACKAGE}"
    else
        "$PKG_MANAGER" install -y "${NGINX_PACKAGE}"
    fi
    log_success "Nginx instalado com sucesso."
}


configurar_firewall() {
    log_info "Configurando o firewall..."
    if command -v ufw &>/dev/null; then
        log_info "Firewall UFW detectado."
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
    #ip_address=$(hostname -i | awk '{print $1}')
    ip_address=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d'/' -f1)
    log_success "Instalação concluída!"
    log_info "Acesse http://${ip_address} no seu navegador para testar."
}


# Função principal.
main() {
    verificar_root
    detectar_distro_e_configurar
    confirmar_execucao "$@" 
    instalar_pacotes
    configurar_firewall
    criar_pagina_teste
    finalizar_e_verificar
}

main "$@"
