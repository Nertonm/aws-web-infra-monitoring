#!/bin/bash

# Título:       Instalador e Configurador do Nginx
# Descrição:    Este script instala o Nginx, configura o firewall (UFW) 
#               para permitir tráfego HTTP e cria uma página de teste.
# Uso:          sudo ./instalador_nginx.sh 
#
# Autor:        Thiago Nerton Macedo Alves
# Versão:       1.3
# Dependências: UFW, apt.


set -eo pipefail
# -e: Termina a execução imediatamente no caso de erro.
# -o pipefail: faz com que o código de retorno, seja o do último comando que falhou.

# Constantes
readonly NGINX_PACKAGE="nginx"
readonly NGINX_ROOT_DIR="/var/www/html"
readonly NGINX_INDEX_FILE="${NGINX_ROOT_DIR}/index.html"
readonly FIREWALL_PROFILE="Nginx HTTP"

readonly COLOR_RESET="\e[0m"
readonly COLOR_GREEN="\e[0;32m"
readonly COLOR_BLUE="\e[0;34m"
readonly COLOR_RED="\e[0;31m"

log_info() {
    echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[SUCESSO]${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_RED}[ERRO]${COLOR_RESET} $1" >&2
}

# Funções Principais

verificar_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Este script precisa ser executado como root. Use 'sudo $0'"
        exit 1
    fi
}

instalar_pacotes() {
    log_info "Atualizando a lista de pacotes..."
    apt-get update -qq

    log_info "Instalando o pacote '${NGINX_PACKAGE}'..."
    apt-get install -y -qq "${NGINX_PACKAGE}"
    log_success "Nginx instalado com sucesso."
}

configurar_firewall() {
    log_info "Configurando o firewall (UFW)..."
    log_info "Permitindo tráfego para '${FIREWALL_PROFILE}'."
    ufw allow "${FIREWALL_PROFILE}"

    # --force para evitar interrupção para confirmação.
    ufw --force enable

    log_success "Firewall ativado e configurado."
    log_info "Status do Firewall:"
    ufw status 
}


criar_pagina_teste() {
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
    # O systemctl status pode retornar um código de erro se o serviço não estiver ativo.
    # `|| true` para não não dar trigger n o `set -e`.
    systemctl status "${NGINX_PACKAGE}" --no-pager || true

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
