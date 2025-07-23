#!/bin/bash

#  Instalador e Configurador do Nginx
#  Este script instala o Nginx, configura o firewall (UFW) 
#  para permitir tráfego HTTP e cria uma página de teste.
# Uso:          sudo ./instalador_nginx.sh 
#
# Autor:        Thiago Nerton Macedo Alves
# Versão:       1.5
# Dependências: UFW, apt.


set -euo pipefail
# -e: Termina a execução imediatamente no caso de erro.
# -u: Trata variáveis não definidas como erro.
# -o pipefail: faz com que o código de retorno, seja o do último comando que falhou.

# Constantes
readonly NGINX_PACKAGE="nginx"
readonly NGINX_ROOT_DIR="/var/www/html"
readonly NGINX_INDEX_FILE="${NGINX_ROOT_DIR}/index.html"
readonly FIREWALL_PROFILE="Nginx HTTP"

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


log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCESSO]${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERRO]${COLOR_RESET} $1" >&2
}

# O comando 'trap' garante que esta função seja chamada ao final ou em caso de erro.
cleanup() {
    local exit_code=$?
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "O script falhou com o código de saída: ${exit_code}"
    fi
    exit ${exit_code}
}

trap cleanup EXIT


# Funções Principais

verificar_root() {
    # $(id -u): retorna o ID numérico do usuário atual. O usuário root sempre tem o ID 0.
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Este script precisa ser executado como root. Use 'sudo $0'"
        exit 1
    fi
}

instalar_pacotes() {
    log_info "Detectando o sistema operacional..."
    source /etc/os-release
    
    # A variável ID vem do arquivo /etc/os-release (ex: "ubuntu", "amzn")
    case "${ID}" in
        ubuntu|debian)
            log_info "Sistema Debian/Ubuntu detectado. Usando 'apt-get'."
            if dpkg -s "${NGINX_PACKAGE}" &>/dev/null; then
            # dpkg -s retorna o status do pacote, se ele já estiver instalado retorna 0
                log_info "O pacote '${NGINX_PACKAGE}' já está instalado."
                return 0
            fi
            apt-get update -qq
            apt-get install -y -qq "${NGINX_PACKAGE}"
            ;;
        fedora|centos|rhel|amzn)
            log_info "Sistema Red Hat/Amazon/Fedora/CentOS detectado. Usando 'dnf' ou 'yum'."
            if rpm -q "${NGINX_PACKAGE}" &>/dev/null; then
                log_info "O pacote '${NGINX_PACKAGE}' já está instalado."
                return 0
            fi

            if command -v dnf &>/dev/null; then
                dnf install -y "${NGINX_PACKAGE}"
            else
                yum install -y "${NGINX_PACKAGE}"
            fi
            ;;
        *)
            log_error "Distribuição Linux não suportada: '${ID}'. Não é possível instalar pacotes."
            exit 1
            ;;
    esac
    log_success "Nginx instalado com sucesso."
}

configurar_firewall() {
    log_info "Configurando o firewall (UFW)..."

    if ! ufw status | grep -q "Status: active"; then
        log_info "Ativando o firewall (UFW)..."
        # --force para evitar interrupção para confirmação.
        ufw --force enable
    else
        log_info "O firewall (UFW) já está ativo."
    fi

    log_info "Permitindo tráfego para '${FIREWALL_PROFILE}'."
    ufw allow "${FIREWALL_PROFILE}"

    log_success "Firewall ativado e configurado."
    log_info "Status do Firewall:"
    ufw status 
}


criar_pagina_teste() {
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
            <title>Olá Mundo com Nginxom Nginx</title>
            <style>
            </style>
        </head>
        <body>
            <h1>Olá, Mundo!</h1>
            <p>Olá, Mundo!</p>
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
    instalar_pacotes
    configurar_firewall
    criar_pagina_teste
    finalizar_e_verificar
    exit 0
}

main
