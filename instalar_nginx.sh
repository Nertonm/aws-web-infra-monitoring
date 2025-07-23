#!/bin/bash

# Garante que o script pare a execução se algum comando falhar
set -e

# Verifica se o script está sendo executado como root
if [ "$(id -u)" -ne 0 ]; then
  echo "Este script precisa ser executado como root. Use 'sudo ./instalar_nginx.sh'" >&2
  exit 1
fi

apt-get update
apt-get install -y nginx
systemctl enable nginx
ufw allow 'Nginx HTTP'
ufw --force enable # Usamos --force para evitar a interrupção do script na confirmação
echo "Status do Firewall:"
ufw status

# Usa um 'Here Document' para escrever o conteúdo HTML no arquivo padrão do Nginx.
cat <<EOF > /var/www/html/index.html
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <title>Olá Mundo com Nginx</title>
    <style>
    </style>
</head>
<body>
    <h1>Olá, Mundo!</h1>
    <p>Olá, Mundo!</p>
</body>
</html>
EOF

echo "Arquivo /var/www/html/index.html criado com sucesso."
systemctl restart nginx
systemctl status nginx --no-pager

exit 0
