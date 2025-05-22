#!/bin/bash

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Este script requer privilégios de root. Execute com sudo."
        exit 1
    fi
}

display_menu() {
    clear
    echo -e "\e[36m================================================"
    echo -e "|                  MENU SHELL                   |" "\e[33m"
    echo -e "================================================" "\e[36m"
    echo "| 0.  Sair                                    |"
    echo "| 1.  Informações do Sistema                  |"
    echo "| 2.  Gerenciamento de Usuários               |"
    echo "| 3.  Monitoramento de Processos/Serviços     |"
    echo "| 4.  Ferramentas de Rede                     |"
    echo "| 5.  Gerenciamento de Disco/Arquivos         |"
    echo "| 6.  Tarefas Agendadas                       |"
    echo "| 7.  Atualizações do Sistema                 |"
    echo "| 8.  Auditoria e Logs                        |"
    echo "| 9.  Ferramentas de Backup                   |"
    echo "| 10. Otimização do Sistema                   |"
    echo "| 11. Gerenciamento de Impressoras            |"
    echo "| 12. Controle de Aplicativos                 |"
    echo "| 13. Gerenciamento de Serviços de Diretório  |"
    echo "| 14. Virtualização                           |"
    echo -e "================================================" "\e[36m"
    echo -e "\e[0m"
}

pause() {
    read -p "Pressione Enter para continuar..."
}

get_package_manager() {
    if command -v apt >/dev/null 2>&1; then
        echo "apt"
    elif command -v yum >/dev/null 2>&1; then
        echo "yum"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    else
        echo "none"
    fi
}

system_info() {
    clear
    echo -e "\n=== INFORMAÇÕES COMPLETAS DO SISTEMA ===\e[32m"
    
    echo -e "\n[SISTEMA OPERACIONAL]\e[33m"
    lsb_release -a 2>/dev/null || cat /etc/os-release
    echo -e "\n[KERNEL]\e[33m"
    uname -a
    echo -e "\n[CPU]\e[33m"
    lscpu | grep -E "Model name|Socket|Core|Thread"
    echo -e "\n[MEMÓRIA]\e[33m"
    free -h
    echo -e "\n[ARMAZENAMENTO]\e[33m"
    lsblk -f
    echo -e "\n[BIOS/FIRMWARE]\e[33m"
    dmidecode -t bios 2>/dev/null || echo "dmidecode não disponível ou requer privilégios."
    
    pause
}

user_management() {
    while true; do
        clear
        echo -e "\n=== GERENCIAMENTO DE USUÁRIOS ===\e[32m"
        echo "1. Listar usuários locais"
        echo "2. Criar novo usuário local"
        echo "3. Remover usuário local"
        echo "4. Alterar senha de usuário"
        echo "5. Adicionar usuário a grupo local"
        echo "6. Listar grupos locais"
        echo "7. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                cut -d: -f1 /etc/passwd
                pause
                ;;
            2)
                read -p "Digite o nome do novo usuário: " username
                read -p "Digite a descrição do usuário: " description
                if adduser --comment "$description" "$username"; then
                    echo "Usuário $username criado com sucesso!"
                else
                    echo "Erro ao criar usuário."
                fi
                pause
                ;;
            3)
                read -p "Digite o nome do usuário a ser removido: " username
                if deluser --remove-home "$username"; then
                    echo "Usuário $username removido com sucesso!"
                else
                    echo "Erro ao remover usuário."
                fi
                pause
                ;;
            4)
                read -p "Digite o nome do usuário: " username
                if passwd "$username"; then
                    echo "Senha alterada com sucesso!"
                else
                    echo "Erro ao alterar senha."
                fi
                pause
                ;;
            5)
                read -p "Digite o nome do usuário: " username
                read -p "Digite o nome do grupo: " group
                if usermod -aG "$group" "$username"; then
                    echo "Usuário $username adicionado ao grupo $group!"
                else
                    echo "Erro ao adicionar usuário ao grupo."
                fi
                pause
                ;;
            6)
                cut -d: -f1 /etc/group
                pause
                ;;
            7)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


process_services() {
    while true; do
        clear
        echo -e "\n=== PROCESSOS E SERVIÇOS ===\e[32m"
        echo "1. Listar processos (top 10 por CPU)"
        echo "2. Listar processos (top 10 por Memória)"
        echo "3. Encerrar processo"
        echo "4. Listar serviços em execução"
        echo "5. Listar todos os serviços"
        echo "6. Iniciar/Parar serviço"
        echo "7. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 11
                pause
                ;;
            2)
                ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 11
                pause
                ;;
            3)
                read -p "Digite o nome ou PID do processo: " process
                if kill "$process" 2>/dev/null || pkill "$process"; then
                    echo "Processo $process encerrado!"
                else
                    echo "Erro ao encerrar processo."
                fi
                pause
                ;;
            4)
                systemctl list-units --type=service --state=running
                pause
                ;;
            5)
                systemctl list-units --type=service
                pause
                ;;
            6)
                read -p "Digite o nome do serviço: " service
                read -p "Deseja (1) Iniciar ou (2) Parar? " action
                if [[ "$action" == "1" ]]; then
                    if systemctl start "$service"; then
                        echo "Serviço $service iniciado!"
                    else
                        echo "Erro ao iniciar serviço."
                    fi
                elif [[ "$action" == "2" ]]; then
                    if systemctl stop "$service"; then
                        echo "Serviço $service parado!"
                    else
                        echo "Erro ao parar serviço."
                    fi
                else
                    echo "Opção inválida!"
                fi
                pause
                ;;
            7)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


network_tools() {
    while true; do
        clear
        echo -e "\n=== FERRAMENTAS DE REDE ===\e[32m"
        echo "1. Configuração de rede"
        echo "2. Testar conectividade"
        echo "3. Testar porta específica"
        echo "4. Analisar conexões ativas"
        echo "5. Reiniciar interfaces de rede"
        echo "6. Limpar cache DNS"
        echo "7. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                ip addr show
                ip route
                cat /etc/resolv.conf 2>/dev/null
                pause
                ;;
            2)
                read -p "Digite o host para testar (ex: google.com): " hostname
                ping -c 4 "$hostname"
                pause
                ;;
            3)
                read -p "Digite o host/IP: " hostname
                read -p "Digite a porta: " port
                if nc -zv "$hostname" "$port" 2>/dev/null; then
                    echo "Porta $port aberta!"
                else
                    echo "Porta $port fechada ou host inacessível."
                fi
                pause
                ;;
            4)
                netstat -tulnp 2>/dev/null || ss -tulnp
                pause
                ;;
            5)
                read -p "Digite a interface de rede (ex: eth0): " interface
                if ip link set "$interface" down && ip link set "$interface" up; then
                    echo "Interface $interface reiniciada!"
                else
                    echo "Erro ao reiniciar interface."
                fi
                pause
                ;;
            6)
                if systemd-resolve --flush-caches 2>/dev/null; then
                    echo "Cache DNS limpo!"
                else
                    echo "Comando de limpeza de cache DNS não disponível."
                fi
                pause
                ;;
            7)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}

disk_file_management() {
    while true; do
        clear
        echo -e "\n=== GERENCIAMENTO DE DISCO/ARQUIVOS ===\e[32m"
        echo "1. Espaço em disco"
        echo "2. Listar arquivos grandes"
        echo "3. Limpar arquivos temporários"
        echo "4. Procurar arquivos"
        echo "5. Verificar integridade do disco"
        echo "6. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                df -h | grep -v tmpfs
                pause
                ;;
            2)
                read -p "Digite o caminho (ex: /home): " path
                read -p "Tamanho mínimo em MB (ex: 100): " size
                find "$path" -type f -size +"$size"M -exec ls -lh {} \; 2>/dev/null | awk '{print $9 " " $5}'
                pause
                ;;
            3)
                rm -rf /tmp/* /var/tmp/* 2>/dev/null
                echo "Arquivos temporários limpos!"
                pause
                ;;
            4)
                read -p "Digite o caminho (ex: /home): " path
                read -p "Digite o filtro (ex: *.log): " filter
                find "$path" -type f -name "$filter" -exec ls -lh {} \; 2>/dev/null | awk '{print $9 " " $5 " " $6 " " $7 " " $8}'
                pause
                ;;
            5)
                read -p "Digite o dispositivo (ex: /dev/sda1): " device
                if fsck "$device" 2>/dev/null; then
                    echo "Verificação concluída!"
                else
                    echo "Erro ao verificar disco. Pode ser necessário desmontar."
                fi
                pause
                ;;
            6)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}

scheduled_tasks() {
    clear
    echo -e "\n=== TAREFAS AGENDADAS ===\e[32m"
    crontab -l 2>/dev/null || echo "Nenhum cronjob configurado."
    echo "Para editar: crontab -e"
    pause
}

system_updates() {
    clear
    echo -e "\n=== ATUALIZAÇÕES DO SISTEMA ===\e[32m"
    pkg_manager=$(get_package_manager)
    case $pkg_manager in
        apt)
            apt update && apt upgrade -y && echo "Atualizações concluídas!" || echo "Erro ao atualizar."
            ;;
        yum)
            yum update -y && echo "Atualizações concluídas!" || echo "Erro ao atualizar."
            ;;
        dnf)
            dnf update -y && echo "Atualizações concluídas!" || echo "Erro ao atualizar."
            ;;
        *)
            echo "Gerenciador de pacotes não suportado."
            ;;
    esac
    pause
}

audit_logs() {
    while true; do
        clear
        echo -e "\n=== AUDITORIA E LOGS ===\e[32m"
        echo "1. Visualizar logs de sistema"
        echo "2. Visualizar logs de autenticação"
        echo "3. Procurar por erro nos logs"
        echo "4. Limpar logs"
        echo "5. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                tail -n 20 /var/log/syslog 2>/dev/null || tail -n 20 /var/log/messages 2>/dev/null
                pause
                ;;
            2)
                tail -n 20 /var/log/auth.log 2>/dev/null || echo "Log de autenticação não disponível."
                pause
                ;;
            3)
                read -p "Digite o termo para pesquisar: " term
                grep -i "$term" /var/log/syslog 2>/dev/null || grep -i "$term" /var/log/messages 2>/dev/null
                pause
                ;;
            4)
                truncate -s 0 /var/log/syslog 2>/dev/null || truncate -s 0 /var/log/messages 2>/dev/null
                truncate -s 0 /var/log/auth.log 2>/dev/null
                echo "Logs limpos!"
                pause
                ;;
            5)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


backup_tools() {
    while true; do
        clear
        echo -e "\n=== FERRAMENTAS DE BACKUP ===\e[32m"
        echo "1. Criar backup de arquivos"
        echo "2. Restaurar backup"
        echo "3. Verificar backups existentes"
        echo "4. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                read -p "Digite o caminho de origem (ex: /home/user): " source
                read -p "Digite o caminho de destino (ex: /backup): " dest
                backup_name="backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                if [ ! -d "$dest" ]; then
                    mkdir -p "$dest"
                fi
                if tar -czf "$dest/$backup_name" "$source" 2>/dev/null; then
                    echo "Backup criado em $dest/$backup_name"
                else
                    echo "Erro ao criar backup."
                fi
                pause
                ;;
            2)
                read -p "Digite o caminho do arquivo de backup (ex: /backup/backup.tar.gz): " backup_file
                read -p "Digite o caminho para restauração (ex: /restore): " dest
                if [ ! -d "$dest" ]; then
                    mkdir -p "$dest"
                fi
                if tar -xzf "$backup_file" -C "$dest" 2>/dev/null; then
                    echo "Backup restaurado para $dest"
                else
                    echo "Erro ao restaurar backup."
                fi
                pause
                ;;
            3)
                read -p "Digite o caminho dos backups (ex: /backup): " backup_dir
                ls -lh "$backup_dir"/*.tar.gz 2>/dev/null || echo "Nenhum backup encontrado."
                pause
                ;;
            4)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


system_optimization() {
    while true; do
        clear
        echo -e "\n=== OTIMIZAÇÃO DO SISTEMA ===\e[32m"
        echo "1. Limpar cache do sistema"
        echo "2. Remover pacotes órfãos"
        echo "3. Limpar logs antigos"
        echo "4. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                sync && sysctl -w vm.drop_caches=3
                echo "Cache do sistema limpo!"
                pause
                ;;
            2)
                pkg_manager=$(get_package_manager)
                case $pkg_manager in
                    apt)
                        apt autoremove -y && apt autoclean
                        echo "Pacotes órfãos removidos!"
                        ;;
                    yum)
                        yum autoremove -y
                        echo "Pacotes órfãos removidos!"
                        ;;
                    dnf)
                        dnf autoremove -y
                        echo "Pacotes órfãos removidos!"
                        ;;
                    *)
                        echo "Gerenciador de pacotes não suportado."
                        ;;
                esac
                pause
                ;;
            3)
                find /var/log -type f -name "*.log" -mtime +30 -delete
                echo "Logs antigos removidos!"
                pause
                ;;
            4)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


printer_management() {
    while true; do
        clear
        echo -e "\n=== GERENCIAMENTO DE IMPRESSORAS ===\e[32m"
        echo "1. Listar impressoras instaladas"
        echo "2. Adicionar impressora"
        echo "3. Remover impressora"
        echo "4. Limpar fila de impressão"
        echo "5. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                lpstat -p -d 2>/dev/null || echo "Nenhuma impressora configurada."
                pause
                ;;
            2)
                read -p "Digite o nome da impressora: " printer_name
                read -p "Digite o URI da impressora (ex: ipp://192.168.1.100): " uri
                if lpadmin -p "$printer_name" -E -v "$uri" 2>/dev/null; then
                    echo "Impressora $printer_name adicionada!"
                else
                    echo "Erro ao adicionar impressora."
                fi
                pause
                ;;
            3)
                read -p "Digite o nome da impressora: " printer_name
                if lpadmin -x "$printer_name" 2>/dev/null; then
                    echo "Impressora $printer_name removida!"
                else
                    echo "Erro ao remover impressora."
                fi
                pause
                ;;
            4)
                cancel -a 2>/dev/null && echo "Fila de impressão limpa!" || echo "Erro ao limpar fila."
                pause
                ;;
            5)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


app_control() {
    while true; do
        clear
        echo -e "\n=== CONTROLE DE APLICATIVOS ===\e[32m"
        echo "1. Listar pacotes instalados"
        echo "2. Desinstalar pacote"
        echo "3. Executar aplicativo"
        echo "4. Ver aplicativos em execução"
        echo "5. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                pkg_manager=$(get_package_manager)
                case $pkg_manager in
                    apt)
                        dpkg -l | grep ^ii | awk '{print $2 " " $3}'
                        ;;
                    yum|dnf)
                        rpm -qa
                        ;;
                    *)
                        echo "Gerenciador de pacotes não suportado."
                        ;;
                esac
                pause
                ;;
            2)
                read -p "Digite o nome do pacote: " package
                pkg_manager=$(get_package_manager)
                case $pkg_manager in
                    apt)
                        apt remove -y "$package" && echo "Pacote $package removido!" || echo "Erro ao remover pacote."
                        ;;
                    yum)
                        yum remove -y "$package" && echo "Pacote $package removido!" || echo "Erro ao remover pacote."
                        ;;
                    dnf)
                        dnf remove -y "$package" && echo "Pacote $package removido!" || echo "Erro ao remover pacote."
                        ;;
                    *)
                        echo "Gerenciador de pacotes não suportado."
                        ;;
                esac
                pause
                ;;
            3)
                read -p "Digite o comando do aplicativo (ex: firefox): " app
                if command -v "$app" >/dev/null; then
                    "$app" &
                    echo "Aplicativo $app iniciado!"
                else
                    echo "Aplicativo $app não encontrado."
                fi
                pause
                ;;
            4)
                ps -eo pid,cmd | grep -v "ps -eo"
                pause
                ;;
            5)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


directory_services() {
    while true; do
        clear
        echo -e "\n=== GERENCIAMENTO DE SERVIÇOS DE DIRETÓRIO ===\e[32m"
        echo "1. Buscar usuário por nome"
        echo "2. Listar usuários"
        echo "3. Adicionar usuário ao LDAP"
        echo "4. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                read -p "Digite o nome do usuário: " username
                if command -v ldapsearch >/dev/null; then
                    ldapsearch -x "uid=$username" | grep -E "uid|cn|mail"
                else
                    echo "Comando ldapsearch não disponível. Instale o pacote openldap-clients."
                fi
                pause
                ;;
            2)
                if command -v ldapsearch >/dev/null; then
                    ldapsearch -x "objectClass=person" | grep -E "uid|cn"
                else
                    echo "Comando ldapsearch não disponível. Instale o pacote openldap-clients."
                fi
                pause
                ;;
            3)
                echo "Adição de usuário ao LDAP requer configuração manual do LDIF. Consulte a documentação do seu servidor LDAP."
                pause
                ;;
            4)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


virtualization_tools() {
    while true; do
        clear
        echo -e "\n=== FERRAMENTAS DE VIRTUALIZAÇÃO ===\e[32m"
        echo "1. Listar máquinas virtuais"
        echo "2. Iniciar VM"
        echo "3. Parar VM"
        echo "4. Ver status de VMs"
        echo "5. Voltar"
        
        read -p "Selecione uma opção: " choice
        case $choice in
            1)
                if command -v virsh >/dev/null; then
                    virsh list --all
                else
                    echo "Libvirt não instalado."
                fi
                pause
                ;;
            2)
                read -p "Digite o nome da VM: " vm_name
                if command -v virsh >/dev/null; then
                    virsh start "$vm_name" && echo "VM $vm_name iniciada!" || echo "Erro ao iniciar VM."
                else
                    echo "Libvirt não instalado."
                fi
                pause
                ;;
            3)
                read -p "Digite o nome da VM: " vm_name
                if command -v virsh >/dev/null; then
                    virsh shutdown "$vm_name" && echo "VM $vm_name parada!" || echo "Erro ao parar VM."
                else
                    echo "Libvirt não instalado."
                fi
                pause
                ;;
            4)
                if command -v virsh >/dev/null; then
                    virsh list --all
                else
                    echo "Libvirt não instalado."
                fi
                pause
                ;;
            5)
                break
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}


main_menu() {
    check_root
    while true; do
        display_menu
        read -p "Digite a opção desejada (0-14): " choice
        case $choice in
            0)
                echo "Saindo..."
                exit 0
                ;;
            1)
                system_info
                ;;
            2)
                user_management
                ;;
            3)
                process_services
                ;;
            4)
                network_tools
                ;;
            5)
                disk_file_management
                ;;
            6)
                scheduled_tasks
                ;;
            7)
                system_updates
                ;;
            8)
                audit_logs
                ;;
            9)
                backup_tools
                ;;
            10)
                system_optimization
                ;;
            11)
                printer_management
                ;;
            12)
                app_control
                ;;
            13)
                directory_services
                ;;
            14)
                virtualization_tools
                ;;
            *)
                echo "Opção inválida!"
                pause
                ;;
        esac
    done
}

# RUN
main_menu