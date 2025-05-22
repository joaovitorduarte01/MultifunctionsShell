# Verificar se o script está sendo executado como administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Este script requer privilégios administrativos. Execute como administrador." -ForegroundColor Red
    exit
}

# Importar módulo ActiveDirectory, se disponível
if (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

function Show-MainMenu {
    Clear-Host
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "|           SUPER MENU POWERSHELL             |" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "| 0.  Sair                                    |"
    Write-Host "| 1.  Informações do Sistema                  |"
    Write-Host "| 2.  Gerenciamento de Usuários               |"
    Write-Host "| 3.  Monitoramento de Processos/Serviços     |"
    Write-Host "| 4.  Ferramentas de Rede                     |"
    Write-Host "| 5.  Gerenciamento de Disco/Arquivos         |"
    Write-Host "| 6.  Tarefas Agendadas                       |"
    Write-Host "| 7.  Atualizações do Windows                 |"
    Write-Host "| 8.  Auditoria e Logs                        |"
    Write-Host "| 9.  Ferramentas de Backup                   |"
    Write-Host "| 10. Otimização do Sistema                   |"
    Write-Host "| 11. Gerenciamento de Impressoras            |"
    Write-Host "| 12. Controle de Aplicativos                 |"
    Write-Host "| 13. Ferramentas AD (Active Directory)       |"
    Write-Host "| 14. Virtualização                           |"
    Write-Host "================================================" -ForegroundColor Cyan
}

function System-Info {
    Clear-Host
    Write-Host "`n=== INFORMAÇÕES COMPLETAS DO SISTEMA ===" -ForegroundColor Green
    
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption, Version, OSArchitecture, BuildNumber, CSName
        $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
        $memInfo = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | Measure-Object -Property Capacity -Sum | Select-Object @{Name="TotalGB";Expression={[math]::Round($_.Sum/1GB,2)}}
        
        Write-Host "`n[SO]" -ForegroundColor Yellow
        $osInfo | Format-List
        
        Write-Host "`n[CPU]" -ForegroundColor Yellow
        $cpuInfo | Format-List
        
        Write-Host "`n[MEMÓRIA]" -ForegroundColor Yellow
        $memInfo | Format-List
        
        Write-Host "`n[ARMAZENAMENTO]" -ForegroundColor Yellow
        Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName, MediaType, @{Name="SizeGB";Expression={[math]::Round($_.Size/1GB,2)}}, HealthStatus | Format-Table -AutoSize
        
        Write-Host "`n[BIOS]" -ForegroundColor Yellow
        Get-CimInstance Win32_BIOS -ErrorAction Stop | Select-Object Manufacturer, Name, Version, SerialNumber | Format-List
    } catch {
        Write-Host "Erro ao coletar informações do sistema: $_" -ForegroundColor Red
    }
    
    Wait-ForKey
}

function User-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE USUÁRIOS ===" -ForegroundColor Green
        Write-Host "1. Listar usuários locais"
        Write-Host "2. Criar novo usuário local"
        Write-Host "3. Remover usuário local"
        Write-Host "4. Alterar senha de usuário"
        Write-Host "5. Adicionar usuário a grupo local"
        Write-Host "6. Listar grupos locais"
        Write-Host "7. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, Description | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar usuários: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $username = Read-Host "Digite o nome do novo usuário"
                    $description = Read-Host "Digite a descrição do usuário"
                    $password = Read-Host "Digite a senha" -AsSecureString
                    New-LocalUser -Name $username -Description $description -Password $password -ErrorAction Stop
                    Write-Host "Usuário $username criado com sucesso!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao criar usuário: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $username = Read-Host "Digite o nome do usuário a ser removido"
                    Remove-LocalUser -Name $username -ErrorAction Stop
                    Write-Host "Usuário $username removido com sucesso!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao remover usuário: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    $username = Read-Host "Digite o nome do usuário"
                    $password = Read-Host "Digite a nova senha" -AsSecureString
                    Set-LocalUser -Name $username -Password $password -ErrorAction Stop
                    Write-Host "Senha alterada com sucesso para $username!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao alterar senha: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '5' {
                try {
                    $username = Read-Host "Digite o nome do usuário"
                    $group = Read-Host "Digite o nome do grupo (ex: Administradores)"
                    Add-LocalGroupMember -Group $group -Member $username -ErrorAction Stop
                    Write-Host "Usuário $username adicionado ao grupo $group!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao adicionar usuário ao grupo: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '6' {
                try {
                    Get-LocalGroup -ErrorAction Stop | Select-Object Name, Description | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar grupos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '7')
}

function Process-Services {
    do {
        Clear-Host
        Write-Host "`n=== PROCESSOS E SERVIÇOS ===" -ForegroundColor Green
        Write-Host "1. Listar processos (top 10 por CPU)"
        Write-Host "2. Listar processos (top 10 por Memória)"
        Write-Host "3. Encerrar processo"
        Write-Host "4. Listar serviços em execução"
        Write-Host "5. Listar todos os serviços"
        Write-Host "6. Iniciar/Parar serviço"
        Write-Host "7. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-Process -ErrorAction Stop | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, CPU, WorkingSet -AutoSize
                } catch {
                    Write-Host "Erro ao listar processos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    Get-Process -ErrorAction Stop | Sort-Object WS -Descending | Select-Object -First 10 | Format-Table Name, CPU, WorkingSet -AutoSize
                } catch {
                    Write-Host "Erro ao listar processos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $process = Read-Host "Digite o nome ou ID do processo"
                    Stop-Process -Name $process -Force -ErrorAction SilentlyContinue
                    Stop-Process -Id $process -Force -ErrorAction SilentlyContinue
                    Write-Host "Processo $process encerrado!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao encerrar processo: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    Get-Service -ErrorAction Stop | Where-Object { $_.Status -eq 'Running' } | Select-Object DisplayName, Status, StartType | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar serviços: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '5' {
                try {
                    Get-Service -ErrorAction Stop | Select-Object DisplayName, Status, StartType | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar serviços: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '6' {
                try {
                    $service = Read-Host "Digite o nome do serviço"
                    $action = Read-Host "Deseja (1) Iniciar ou (2) Parar?"
                    if ($action -eq '1') {
                        Start-Service -Name $service -ErrorAction Stop
                        Write-Host "Serviço $service iniciado!" -ForegroundColor Green
                    } elseif ($action -eq '2') {
                        Stop-Service -Name $service -ErrorAction Stop
                        Write-Host "Serviço $service parado!" -ForegroundColor Green
                    } else {
                        Write-Host "Opção inválida!" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Erro ao gerenciar serviço: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '7')
}

function Network-Tools {
    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE REDE ===" -ForegroundColor Green
        Write-Host "1. Configuração de rede"
        Write-Host "2. Testar conectividade"
        Write-Host "3. Testar porta específica"
        Write-Host "4. Analisar conexões ativas"
        Write-Host "5. Liberar/renovar DHCP"
        Write-Host "6. Flush DNS"
        Write-Host "7. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-NetIPConfiguration -ErrorAction Stop | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao obter configuração de rede: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $hostname = Read-Host "Digite o host para testar (ex: google.com)"
                    Test-NetConnection -ComputerName $hostname -InformationLevel Detailed -ErrorAction Stop
                } catch {
                    Write-Host "Erro ao testar conectividade: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $hostname = Read-Host "Digite o host/IP"
                    $port = Read-Host "Digite a porta"
                    Test-NetConnection -ComputerName $hostname -Port $port -ErrorAction Stop
                } catch {
                    Write-Host "Erro ao testar porta: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Established' } | 
                        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar conexões: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '5' {
                try {
                    ipconfig /release
                    ipconfig /renew
                    Write-Host "Endereço IP renovado!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao renovar DHCP: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '6' {
                try {
                    ipconfig /flushdns
                    Write-Host "Cache DNS limpo!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao limpar cache DNS: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '7')
}

function Disk-File-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE DISCO/ARQUIVOS ===" -ForegroundColor Green
        Write-Host "1. Espaço em disco"
        Write-Host "2. Listar arquivos grandes"
        Write-Host "3. Limpar arquivos temporários"
        Write-Host "4. Procurar arquivos"
        Write-Host "5. Verificar integridade do disco"
        Write-Host "6. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-Volume -ErrorAction Stop | Select-Object DriveLetter, FileSystemLabel, SizeRemaining, Size | 
                        ForEach-Object {
                            $used = $_.Size - $_.SizeRemaining
                            $percentUsed = ($used / $_.Size) * 100
                            [PSCustomObject]@{
                                Unidade = $_.DriveLetter
                                Rótulo = $_.FileSystemLabel
                                "Total (GB)" = [math]::Round($_.Size/1GB, 2)
                                "Usado (GB)" = [math]::Round($used/1GB, 2)
                                "Livre (GB)" = [math]::Round($_.SizeRemaining/1GB, 2)
                                "% Usado" = [math]::Round($percentUsed, 2)
                            }
                        } | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar discos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $path = Read-Host "Digite o caminho (ex: C:\)"
                    $size = Read-Host "Tamanho mínimo em MB (ex: 100)"
                    Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                        Where-Object { $_.Length -gt ([int]$size * 1MB) } | 
                        Sort-Object Length -Descending | 
                        Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}} | 
                        Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar arquivos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $tempFolders = @("$env:TEMP", "$env:WINDIR\Temp", "$env:USERPROFILE\AppData\Local\Temp")
                    $totalFreed = 0
                    
                    foreach ($folder in $tempFolders) {
                        if (Test-Path $folder) {
                            $files = Get-ChildItem $folder -Recurse -Force -ErrorAction SilentlyContinue
                            $size = ($files | Measure-Object -Property Length -Sum).Sum / 1MB
                            $totalFreed += $size
                            $files | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                            Write-Host "Limpos $([math]::Round($size, 2)) MB de $folder"
                        }
                    }
                    Write-Host "`nTotal liberado: $([math]::Round($totalFreed, 2)) MB" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao limpar arquivos temporários: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    $path = Read-Host "Digite o caminho (ex: C:\)"
                    $filter = Read-Host "Digite o filtro (ex: *.log ou relatorio*)"
                    Get-ChildItem -Path $path -Filter $filter -Recurse -ErrorAction SilentlyContinue | 
                        Select-Object FullName, LastWriteTime, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}} | 
                        Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao procurar arquivos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '5' {
                try {
                    $drive = Read-Host "Digite a letra do disco (ex: C)"
                    Write-Host "A verificação será agendada para o próximo reinício." -ForegroundColor Yellow
                    Start-Process -FilePath "chkdsk" -ArgumentList "$drive /f" -NoNewWindow -Wait
                } catch {
                    Write-Host "Erro ao agendar verificação de disco: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '6')
}

function Scheduled-Tasks {
    Clear-Host
    Write-Host "`n=== TAREFAS AGENDADAS ===" -ForegroundColor Green
    try {
        Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName, State, Author | Format-Table -AutoSize
    } catch {
        Write-Host "Erro ao listar tarefas agendadas: $_" -ForegroundColor Red
    }
    Wait-ForKey
}

function Windows-Updates {
    Clear-Host
    Write-Host "`n=== ATUALIZAÇÕES DO WINDOWS ===" -ForegroundColor Green
    
    if (-not (Get-Module -ListAvailable PSWindowsUpdate -ErrorAction SilentlyContinue)) {
        Write-Host "Módulo PSWindowsUpdate não encontrado. Instale manualmente com 'Install-Module PSWindowsUpdate'." -ForegroundColor Red
        Wait-ForKey
        return
    }
    
    Write-Host "1. Verificar atualizações disponíveis"
    Write-Host "2. Instalar atualizações"
    Write-Host "3. Histórico de atualizações"
    Write-Host "4. Voltar"
    
    $choice = Read-Host "`nSelecione uma opção"
    
    switch ($choice) {
        '1' {
            try {
                Get-WindowsUpdate -Verbose -ErrorAction Stop
            } catch {
                Write-Host "Erro ao verificar atualizações: $_" -ForegroundColor Red
            }
            Wait-ForKey
        }
        '2' {
            try {
                Install-WindowsUpdate -AcceptAll -AutoReboot -ErrorAction Stop
                Write-Host "Atualizações instaladas com sucesso!" -ForegroundColor Green
            } catch {
                Write-Host "Erro ao instalar atualizações: $_" -ForegroundColor Red
            }
            Wait-ForKey
        }
        '3' {
            try {
                Get-WUHistory -ErrorAction Stop | Select-Object Date, Title, Result | Format-Table -AutoSize
            } catch {
                Write-Host "Erro ao listar histórico de atualizações: $_" -ForegroundColor Red
            }
            Wait-ForKey
        }
    }
}

function Audit-Logs {
    do {
        Clear-Host
        Write-Host "`n=== AUDITORIA E LOGS ===" -ForegroundColor Green
        Write-Host "1. Visualizar logs de sistema"
        Write-Host "2. Visualizar logs de aplicação"
        Write-Host "3. Visualizar logs de segurança"
        Write-Host "4. Procurar por erro nos logs"
        Write-Host "5. Limpar logs"
        Write-Host "6. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-EventLog -LogName System -Newest 20 -ErrorAction Stop | 
                        Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize
                } catch {
                    Write-Host "Erro ao visualizar logs de sistema: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    Get-EventLog -LogName Application -Newest 20 -ErrorAction Stop | 
                        Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize
                } catch {
                    Write-Host "Erro ao visualizar logs de aplicação: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    Get-EventLog -LogName Security -Newest 20 -ErrorAction Stop | 
                        Select-Object TimeGenerated, EntryType, Source, Message | Format-Table -Wrap -AutoSize
                } catch {
                    Write-Host "Erro ao visualizar logs de segurança: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    $logName = Read-Host "Digite o nome do log (System, Application, Security)"
                    $searchTerm = Read-Host "Digite o termo para pesquisar"
                    Get-EventLog -LogName $logName -Newest 1000 -ErrorAction Stop | 
                        Where-Object { $_.Message -like "*$searchTerm*" } | 
                        Select-Object TimeGenerated, Source, Message | Format-Table -Wrap -AutoSize
                } catch {
                    Write-Host "Erro ao procurar nos logs: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '5' {
                try {
                    Clear-EventLog -LogName System, Application, Security -ErrorAction Stop
                    Write-Host "Logs limpos com sucesso!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao limpar logs: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '6')
}

function Backup-Tools {
    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE BACKUP ===" -ForegroundColor Green
        Write-Host "1. Criar backup de arquivos"
        Write-Host "2. Restaurar backup"
        Write-Host "3. Verificar backups existentes"
        Write-Host "4. Fazer backup de drivers"
        Write-Host "5. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    $source = Read-Host "Digite o caminho de origem (ex: C:\Pasta)"
                    $destination = Read-Host "Digite o caminho de destino (ex: D:\Backup)"
                    $backupName = "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
                    
                    if (-not (Test-Path $destination)) {
                        New-Item -ItemType Directory -Path $destination -Force -ErrorAction Stop
                    }
                    
                    Compress-Archive -Path $source -DestinationPath "$destination\$backupName" -CompressionLevel Optimal -ErrorAction Stop
                    Write-Host "Backup criado em $destination\$backupName" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao criar backup: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $backupFile = Read-Host "Digite o caminho do arquivo de backup (ex: D:\Backup\arquivo.zip)"
                    $destination = Read-Host "Digite o caminho para restauração (ex: C:\Restore)"
                    
                    if (-not (Test-Path $destination)) {
                        New-Item -ItemType Directory -Path $destination -Force -ErrorAction Stop
                    }
                    
                    Expand-Archive -Path $backupFile -DestinationPath $destination -Force -ErrorAction Stop
                    Write-Host "Backup restaurado para $destination" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao restaurar backup: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $backupDir = Read-Host "Digite o caminho dos backups (ex: D:\Backup)"
                    Get-ChildItem -Path $backupDir -Filter *.zip -ErrorAction Stop | 
                        Select-Object Name, LastWriteTime, @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}} | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar backups: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    $destination = Read-Host "Digite o caminho para salvar o backup dos drivers (ex: D:\Backup\Drivers)"
                    
                    if (-not (Test-Path $destination)) {
                        New-Item -ItemType Directory -Path $destination -Force -ErrorAction Stop
                    }
                    
                    Write-Host "`nColetando informações de drivers..."
                    $drivers = Get-WindowsDriver -Online -All -ErrorAction Stop
                    
                    $backupFile = "$destination\DriversBackup_$(Get-Date -Format 'yyyyMMdd').txt"
                    $drivers | Out-File -FilePath $backupFile -ErrorAction Stop
                    
                    Write-Host "`nExportando drivers para arquivo..."
                    Export-WindowsDriver -Online -Destination $destination -ErrorAction Stop
                    
                    Write-Host "`nBackup dos drivers concluído com sucesso!" -ForegroundColor Green
                    Write-Host "Local: $destination" -ForegroundColor Yellow
                    Write-Host "Arquivo de informações: $backupFile" -ForegroundColor Yellow
                } catch {
                    Write-Host "Erro ao fazer backup de drivers: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '5')
}

function System-Optimization {
    do {
        Clear-Host
        Write-Host "`n=== OTIMIZAÇÃO DO SISTEMA ===" -ForegroundColor Green
        Write-Host "1. Desfragmentar disco"
        Write-Host "2. Limpar disco (Cleanmgr)"
        Write-Host "3. Otimizar unidades"
        Write-Host "4. Desativar programas de inicialização"
        Write-Host "5. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Optimize-Volume -DriveLetter C -Defrag -Verbose -ErrorAction Stop
                    Write-Host "Desfragmentação concluída!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao desfragmentar disco: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    Start-Process -FilePath "cleanmgr" -ArgumentList "/sagerun:1" -Wait -ErrorAction Stop
                    Write-Host "Limpeza de disco executada!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao executar limpeza de disco: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' } | Optimize-Volume -Verbose -ErrorAction Stop
                    Write-Host "Otimização concluída para todas as unidades!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao otimizar unidades: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    $startupApps = Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Select-Object Name, Command, Location, User
                    $startupApps | Format-Table -AutoSize
                    
                    $disable = Read-Host "Deseja desativar algum? (S/N)"
                    if ($disable -eq 'S') {
                        $appName = Read-Host "Digite o nome do aplicativo para desativar"
                        $app = $startupApps | Where-Object { $_.Name -like "*$appName*" }
                        if ($app) {
                            if ($app.Location -like "*Registry*") {
                                $keyPath = $app.Location.Split(':')[1]
                                Remove-ItemProperty -Path $keyPath -Name $app.Name -ErrorAction Stop
                                Write-Host "Aplicativo removido da inicialização!" -ForegroundColor Green
                            } else {
                                Remove-Item $app.Command -ErrorAction Stop
                                Write-Host "Atalho removido da pasta de inicialização!" -ForegroundColor Green
                            }
                        } else {
                            Write-Host "Aplicativo não encontrado!" -ForegroundColor Red
                        }
                    }
                } catch {
                    Write-Host "Erro ao gerenciar programas de inicialização: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '5')
}

function Printer-Management {
    do {
        Clear-Host
        Write-Host "`n=== GERENCIAMENTO DE IMPRESSORAS ===" -ForegroundColor Green
        Write-Host "1. Listar impressoras instaladas"
        Write-Host "2. Adicionar impressora"
        Write-Host "3. Remover impressora"
        Write-Host "4. Limpar fila de impressão"
        Write-Host "5. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-Printer -ErrorAction Stop | Select-Object Name, Type, PortName, Shared, Published | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar impressoras: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $printerName = Read-Host "Digite o nome da impressora"
                    $driverName = Read-Host "Digite o nome do driver"
                    $portName = Read-Host "Digite a porta (ex: IP_192.168.1.100)"
                    $ipAddress = Read-Host "Digite o endereço IP da impressora"
                    
                    if (Get-PrinterDriver -Name $driverName -ErrorAction SilentlyContinue) {
                        Add-PrinterPort -Name $portName -PrinterHostAddress $ipAddress -ErrorAction Stop
                        Add-Printer -Name $printerName -DriverName $driverName -PortName $portName -ErrorAction Stop
                        Write-Host "Impressora $printerName adicionada com sucesso!" -ForegroundColor Green
                    } else {
                        Write-Host "Driver $driverName não encontrado. Instale o driver primeiro." -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Erro ao adicionar impressora: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $printerName = Read-Host "Digite o nome da impressora para remover"
                    Remove-Printer -Name $printerName -ErrorAction Stop
                    Write-Host "Impressora $printerName removida com sucesso!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao remover impressora: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    Get-Printer -ErrorAction Stop | Where-Object { $_.JobCount -gt 0 } | ForEach-Object {
                        Write-Host "Limpando fila da impressora $($_.Name)..."
                        Remove-PrintJob -PrinterName $_.Name -ID * -ErrorAction Stop
                    }
                    Write-Host "Filas de impressão limpas!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao limpar filas de impressão: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '5')
}

function App-Control {
    do {
        Clear-Host
        Write-Host "`n=== CONTROLE DE APLICATIVOS ===" -ForegroundColor Green
        Write-Host "1. Listar aplicativos instalados"
        Write-Host "2. Desinstalar aplicativo"
        Write-Host "3. Executar aplicativo como administrador"
        Write-Host "4. Ver aplicativos em execução"
        Write-Host "5. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction Stop | 
                        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
                        Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar aplicativos: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $appName = Read-Host "Digite parte do nome do aplicativo"
                    $apps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction Stop | 
                        Where-Object { $_.DisplayName -like "*$appName*" } | 
                        Select-Object DisplayName, UninstallString
                    
                    if ($apps) {
                        $apps | Format-Table -AutoSize
                        $uninstall = Read-Host "Deseja desinstalar algum? (S/N)"
                        if ($uninstall -eq 'S') {
                            $appToRemove = Read-Host "Digite o nome exato do aplicativo"
                            $uninstallString = ($apps | Where-Object { $_.DisplayName -eq $appToRemove }).UninstallString
                            if ($uninstallString) {
                                Start-Process "cmd.exe" -ArgumentList "/c $uninstallString /quiet" -Wait -ErrorAction Stop
                                Write-Host "Aplicativo $appToRemove desinstalado!" -ForegroundColor Green
                            } else {
                                Write-Host "Comando de desinstalação não encontrado!" -ForegroundColor Red
                            }
                        }
                    } else {
                        Write-Host "Nenhum aplicativo encontrado!" -ForegroundColor Red
                    }
                } catch {
                    Write-Host "Erro ao desinstalar aplicativo: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $appPath = Read-Host "Digite o caminho completo do aplicativo (ex: C:\app\app.exe)"
                    Start-Process -FilePath $appPath -Verb RunAs -ErrorAction Stop
                    Write-Host "Aplicativo iniciado como administrador!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao executar aplicativo: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    Get-Process -ErrorAction Stop | Where-Object { $_.MainWindowTitle } | 
                        Select-Object Name, MainWindowTitle | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar aplicativos em execução: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '5')
}

function AD-Tools {
    if (-not (Get-Module ActiveDirectory -ErrorAction SilentlyContinue)) {
        Write-Host "Módulo ActiveDirectory não disponível. Execute em um servidor com AD DS ou instale o RSAT." -ForegroundColor Red
        Wait-ForKey
        return
    }

    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS AVANÇADAS ACTIVE DIRECTORY ===" -ForegroundColor Cyan
        Write-Host "| 1.  Busca de Usuários                      |"
        Write-Host "| 2.  Gerenciamento de Contas                |"
        Write-Host "| 3.  Gerenciamento de Grupos                |"
        Write-Host "| 4.  Gerenciamento de Computadores          |"
        Write-Host "| 5.  Relatórios e Exportação                |"
        Write-Host "| 6.  Políticas e Segurança                  |"
        Write-Host "| 7.  Ferramentas de Migração                |"
        Write-Host "| 8.  Limpeza e Manutenção                   |"
        Write-Host "| 9.  Voltar ao Menu Principal               |"
        Write-Host "================================================" -ForegroundColor Cyan
        
        $mainChoice = Read-Host "`nSelecione uma categoria"
        
        switch ($mainChoice) {
            '1' {
                do {
                    Clear-Host
                    Write-Host "`n=== BUSCA DE USUÁRIOS ===" -ForegroundColor Green
                    Write-Host "1. Buscar usuário por nome/login"
                    Write-Host "2. Buscar usuários inativos"
                    Write-Host "3. Buscar usuários desabilitados"
                    Write-Host "4. Buscar por departamento"
                    Write-Host "5. Buscar usuários com senha expirada"
                    Write-Host "6. Buscar usuários que nunca logaram"
                    Write-Host "7. Voltar"
                    
                    $searchChoice = Read-Host "`nSelecione uma opção"
                    
                    switch ($searchChoice) {
                        '1' {
                            try {
                                $searchTerm = Read-Host "Digite nome, sobrenome ou login"
                                $filter = "Name -like '*$searchTerm*' -or SamAccountName -like '*$searchTerm*' -or GivenName -like '*$searchTerm*' -or Surname -like '*$searchTerm*' -or UserPrincipalName -like '*$searchTerm*' -or DisplayName -like '*$searchTerm*'"
                                $users = Get-ADUser -Filter $filter -Properties * -ErrorAction Stop
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar usuários: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '2' {
                            try {
                                $days = Read-Host "Número de dias para considerar inativo (padrão 90)"
                                if (-not $days) { $days = 90 }
                                $date = (Get-Date).AddDays(-$days)
                                $users = Get-ADUser -Filter {LastLogonDate -lt $date -and Enabled -eq $true} -Properties LastLogonDate -ErrorAction Stop
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar usuários inativos: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '3' {
                            try {
                                $users = Get-ADUser -Filter {Enabled -eq $false} -Properties Enabled -ErrorAction Stop
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar usuários desabilitados: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '4' {
                            try {
                                $dept = Read-Host "Digite o departamento"
                                $users = Get-ADUser -Filter {Department -like "*$dept*"} -Properties Department -ErrorAction Stop
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar por departamento: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '5' {
                            try {
                                $users = Search-ADAccount -PasswordExpired -ErrorAction Stop | Where-Object { $_.ObjectClass -eq 'user' }
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar usuários com senha expirada: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '6' {
                            try {
                                $users = Get-ADUser -Filter {LastLogonDate -notlike "*"} -Properties LastLogonDate -ErrorAction Stop
                                Show-ADUserResults $users
                            } catch {
                                Write-Host "Erro ao buscar usuários que nunca logaram: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                    }
                } while ($searchChoice -ne '7')
            }
            '2' {
                do {
                    Clear-Host
                    Write-Host "`n=== GERENCIAMENTO DE CONTAS ===" -ForegroundColor Green
                    Write-Host "1. Criar novo usuário"
                    Write-Host "2. Desbloquear conta"
                    Write-Host "3. Resetar senha"
                    Write-Host "4. Habilitar/Desabilitar conta"
                    Write-Host "5. Mover usuário para outra OU"
                    Write-Host "6. Adicionar aos grupos do usuário"
                    Write-Host "7. Remover dos grupos do usuário"
                    Write-Host "8. Configurar propriedades da conta"
                    Write-Host "9. Voltar"
                    
                    $accountChoice = Read-Host "`nSelecione uma opção"
                    
                    switch ($accountChoice) {
                        '1' {
                            try {
                                New-ADUserWizard
                            } catch {
                                Write-Host "Erro ao criar usuário: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '2' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                Unlock-ADAccount -Identity $username -ErrorAction Stop
                                Write-Host "Conta $username desbloqueada com sucesso!" -ForegroundColor Green
                                Get-ADUser -Identity $username -Properties LockedOut -ErrorAction Stop | 
                                    Select-Object Name, SamAccountName, LockedOut | Format-Table -AutoSize
                            } catch {
                                Write-Host "Erro ao desbloquear conta: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '3' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $newPass = Read-Host "Digite a nova senha" -AsSecureString
                                Set-ADAccountPassword -Identity $username -NewPassword $newPass -Reset -ErrorAction Stop
                                Write-Host "Senha alterada com sucesso!" -ForegroundColor Green
                                
                                $changePass = Read-Host "Forçar mudança de senha no próximo login? (S/N)"
                                if ($changePass -eq 'S') {
                                    Set-ADUser -Identity $username -ChangePasswordAtLogon $true -ErrorAction Stop
                                    Write-Host "Usuário deverá alterar a senha no próximo login." -ForegroundColor Yellow
                                }
                                
                                $unlock = Read-Host "Deseja desbloquear a conta também? (S/N)"
                                if ($unlock -eq 'S') {
                                    Unlock-ADAccount -Identity $username -ErrorAction Stop
                                    Write-Host "Conta desbloqueada!" -ForegroundColor Green
                                }
                            } catch {
                                Write-Host "Erro ao resetar senha: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '4' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $user = Get-ADUser -Identity $username -Properties Enabled -ErrorAction Stop
                                $newStatus = !$user.Enabled
                                Set-ADUser -Identity $username -Enabled $newStatus -ErrorAction Stop
                                Write-Host "Status da conta alterado para: $(if ($newStatus) {'Habilitada'} else {'Desabilitada'})" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao alterar status da conta: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '5' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $user = Get-ADUser -Identity $username -ErrorAction Stop | Select-Object DistinguishedName
                                Write-Host "OU atual: $($user.DistinguishedName)"
                                $newOU = Read-Host "Digite a OU de destino (ex: OU=Usuarios,DC=dominio,DC=com)"
                                Move-ADObject -Identity $user.DistinguishedName -TargetPath $newOU -ErrorAction Stop
                                Write-Host "Usuário movido com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao mover usuário: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '6' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $currentGroups = Get-ADPrincipalGroupMembership -Identity $username -ErrorAction Stop | 
                                    Select-Object Name | Sort-Object Name
                                Write-Host "`nGrupos atuais do usuário:"
                                $currentGroups | Format-Table -AutoSize
                                
                                $groupName = Read-Host "`nDigite o nome do grupo para adicionar"
                                Add-ADGroupMember -Identity $groupName -Members $username -ErrorAction Stop
                                Write-Host "Usuário adicionado ao grupo $groupName com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao adicionar ao grupo: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '7' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $currentGroups = Get-ADPrincipalGroupMembership -Identity $username -ErrorAction Stop | 
                                    Select-Object Name | Sort-Object Name
                                Write-Host "`nGrupos atuais do usuário:"
                                $currentGroups | Format-Table -AutoSize
                                
                                $groupName = Read-Host "`nDigite o nome do grupo para remover"
                                Remove-ADGroupMember -Identity $groupName -Members $username -Confirm:$false -ErrorAction Stop
                                Write-Host "Usuário removido do grupo $groupName com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao remover do grupo: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '8' {
                            try {
                                $username = Read-Host "Digite o login do usuário"
                                $user = Get-ADUser -Identity $username -Properties * -ErrorAction Stop
                                
                                Write-Host "`nEditando propriedades de $($user.Name)"
                                $newDesc = Read-Host "Descrição [atual: $($user.Description)]"
                                $newOffice = Read-Host "Escritório [atual: $($user.Office)]"
                                $newDept = Read-Host "Departamento [atual: $($user.Department)]"
                                $newTitle = Read-Host "Cargo [atual: $($user.Title)]"
                                $newEmail = Read-Host "Email [atual: $($user.EmailAddress)]"
                                
                                $params = @{}
                                if ($newDesc) { $params.Description = $newDesc }
                                if ($newOffice) { $params.Office = $newOffice }
                                if ($newDept) { $params.Department = $newDept }
                                if ($newTitle) { $params.Title = $newTitle }
                                if ($newEmail) { $params.EmailAddress = $newEmail }
                                
                                Set-ADUser -Identity $username @params -ErrorAction Stop
                                Write-Host "Propriedades atualizadas com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao configurar propriedades: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                    }
                } while ($accountChoice -ne '9')
            }
            '3' {
                do {
                    Clear-Host
                    Write-Host "`n=== GERENCIAMENTO DE GRUPOS ===" -ForegroundColor Green
                    Write-Host "1. Listar todos os grupos"
                    Write-Host "2. Criar novo grupo"
                    Write-Host "3. Remover grupo"
                    Write-Host "4. Listar membros de um grupo"
                    Write-Host "5. Adicionar membros a um grupo"
                    Write-Host "6. Remover membros de um grupo"
                    Write-Host "7. Configurar permissões do grupo"
                    Write-Host "8. Voltar"
                    
                    $groupChoice = Read-Host "`nSelecione uma opção"
                    
                    switch ($groupChoice) {
                        '1' {
                            try {
                                Get-ADGroup -Filter * -Properties * -ErrorAction Stop | 
                                    Select-Object Name, GroupScope, GroupCategory, Description | 
                                    Sort-Object Name | Format-Table -AutoSize
                            } catch {
                                Write-Host "Erro ao listar grupos: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '2' {
                            try {
                                $groupName = Read-Host "Digite o nome do novo grupo"
                                $groupScope = Read-Host "Escopo (Global/Universal/DomainLocal)"
                                $groupCategory = Read-Host "Categoria (Security/Distribution)"
                                $description = Read-Host "Descrição"
                                
                                New-ADGroup -Name $groupName -GroupScope $groupScope -GroupCategory $groupCategory -Description $description -ErrorAction Stop
                                Write-Host "Grupo $groupName criado com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao criar grupo: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '3' {
                            try {
                                $groupName = Read-Host "Digite o nome do grupo para remover"
                                Remove-ADGroup -Identity $groupName -Confirm:$false -ErrorAction Stop
                                Write-Host "Grupo $groupName removido com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao remover grupo: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '4' {
                            try {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop | 
                                    Select-Object Name, SamAccountName, ObjectClass | Sort-Object Name
                                
                                Write-Host "`nMembros do grupo $groupName"
                                $members | Format-Table -AutoSize
                                
                                $export = Read-Host "Deseja exportar para CSV? (S/N)"
                                if ($export -eq 'S') {
                                    $csvPath = "$env:USERPROFILE\Desktop\$($groupName)_Members_$(Get-Date -Format 'yyyyMMdd').csv"
                                    $members | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                                    Write-Host "Lista exportada para $csvPath" -ForegroundColor Green
                                }
                            } catch {
                                Write-Host "Erro ao listar membros: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '5' {
                            try {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $membersToAdd = Read-Host "Digite os logins dos usuários a adicionar (separados por vírgula)"
                                $membersArray = $membersToAdd -split ',' | ForEach-Object { $_.Trim() }
                                Add-ADGroupMember -Identity $groupName -Members $membersArray -ErrorAction Stop
                                Write-Host "Usuários adicionados ao grupo $groupName com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao adicionar membros: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '6' {
                            try {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $membersToRemove = Read-Host "Digite os logins dos usuários a remover (separados por vírgula)"
                                $membersArray = $membersToRemove -split ',' | ForEach-Object { $_.Trim() }
                                Remove-ADGroupMember -Identity $groupName -Members $membersArray -Confirm:$false -ErrorAction Stop
                                Write-Host "Usuários removidos do grupo $groupName com sucesso!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao remover membros: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                        '7' {
                            try {
                                $groupName = Read-Host "Digite o nome do grupo"
                                $managedBy = Read-Host "Digite o login do responsável pelo grupo"
                                $description = Read-Host "Digite a nova descrição"
                                
                                Set-ADGroup -Identity $groupName -ManagedBy $managedBy -Description $description -ErrorAction Stop
                                Write-Host "Configurações do grupo $groupName atualizadas!" -ForegroundColor Green
                            } catch {
                                Write-Host "Erro ao configurar grupo: $_" -ForegroundColor Red
                            }
                            Wait-ForKey
                        }
                    }
                } while ($groupChoice -ne '8')
            }
            '4' {
                Write-Host "Gerenciamento de Computadores: Funcionalidade não implementada." -ForegroundColor Yellow
                Wait-ForKey
            }
            '5' {
                Write-Host "Relatórios e Exportação: Funcionalidade não implementada." -ForegroundColor Yellow
                Wait-ForKey
            }
            '6' {
                Write-Host "Políticas e Segurança: Funcionalidade não implementada." -ForegroundColor Yellow
                Wait-ForKey
            }
            '7' {
                Write-Host "Ferramentas de Migração: Funcionalidade não implementada." -ForegroundColor Yellow
                Wait-ForKey
            }
            '8' {
                Write-Host "Limpeza e Manutenção: Funcionalidade não implementada." -ForegroundColor Yellow
                Wait-ForKey
            }
        }
    } while ($mainChoice -ne '9')
}

function Virtualization-Tools {
    if (-not (Get-Module Hyper-V -ErrorAction SilentlyContinue)) {
        Write-Host "Módulo Hyper-V não disponível. Instale o recurso Hyper-V." -ForegroundColor Red
        Wait-ForKey
        return
    }

    do {
        Clear-Host
        Write-Host "`n=== FERRAMENTAS DE VIRTUALIZAÇÃO ===" -ForegroundColor Green
        Write-Host "1. Listar máquinas virtuais Hyper-V"
        Write-Host "2. Iniciar VM"
        Write-Host "3. Parar VM"
        Write-Host "4. Ver status de VMs"
        Write-Host "5. Voltar"
        
        $choice = Read-Host "`nSelecione uma opção"
        
        switch ($choice) {
            '1' {
                try {
                    Get-VM -ErrorAction Stop | Select-Object Name, State, CPUUsage, MemoryAssigned | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar VMs: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '2' {
                try {
                    $vmName = Read-Host "Digite o nome da VM para iniciar"
                    Start-VM -Name $vmName -ErrorAction Stop
                    Write-Host "VM $vmName iniciada!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao iniciar VM: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '3' {
                try {
                    $vmName = Read-Host "Digite o nome da VM para parar"
                    Stop-VM -Name $vmName -Force -ErrorAction Stop
                    Write-Host "VM $vmName parada!" -ForegroundColor Green
                } catch {
                    Write-Host "Erro ao parar VM: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
            '4' {
                try {
                    Get-VM -ErrorAction Stop | Select-Object Name, State, Status, Uptime | Format-Table -AutoSize
                } catch {
                    Write-Host "Erro ao listar status de VMs: $_" -ForegroundColor Red
                }
                Wait-ForKey
            }
        }
    } while ($choice -ne '5')
}

function Show-ADUserResults {
    param($users)
    
    if ($users) {
        try {
            $users | Select-Object Name, SamAccountName, UserPrincipalName, Enabled, LastLogonDate, EmailAddress, Department, Title | 
                Sort-Object Name | Format-Table -AutoSize
            
            $count = ($users | Measure-Object).Count
            Write-Host "`nTotal encontrado: $count" -ForegroundColor Yellow
            
            $export = Read-Host "Deseja exportar para CSV? (S/N)"
            if ($export -eq 'S') {
                $csvPath = "$env:USERPROFILE\Desktop\ADUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $users | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
                Write-Host "Dados exportados para $csvPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "Erro ao exibir resultados: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Nenhum resultado encontrado." -ForegroundColor Yellow
    }
}

function New-ADUserWizard {
    Clear-Host
    Write-Host "`n=== ASSISTENTE DE CRIAÇÃO DE USUÁRIO ===" -ForegroundColor Cyan
    
    try {
        $firstName = Read-Host "Nome"
        $lastName = Read-Host "Sobrenome"
        $samAccount = Read-Host "Login (SamAccountName)"
        $password = Read-Host "Senha" -AsSecureString
        $ou = Read-Host "OU (ex: OU=Usuarios,DC=dominio,DC=com)"
        $email = Read-Host "Email"
        $department = Read-Host "Departamento"
        $title = Read-Host "Cargo"
        $company = Read-Host "Empresa"
        
        $userParams = @{
            GivenName = $firstName
            Surname = $lastName
            Name = "$firstName $lastName"
            SamAccountName = $samAccount
            UserPrincipalName = "$samAccount@$((Get-ADDomain -ErrorAction Stop).DNSRoot)"
            AccountPassword = $password
            Path = $ou
            Enabled = $true
            EmailAddress = $email
            Department = $department
            Title = $title
            Company = $company
            ChangePasswordAtLogon = $true
        }
        
        New-ADUser @userParams -ErrorAction Stop
        Write-Host "Usuário $samAccount criado com sucesso!" -ForegroundColor Green
        
        $addGroups = Read-Host "Deseja adicionar a grupos padrão? (S/N)"
        if ($addGroups -eq 'S') {
            $defaultGroups = "Domain Users"
            Add-ADGroupMember -Identity $defaultGroups -Members $samAccount -ErrorAction Stop
            Write-Host "Usuário adicionado aos grupos padrão." -ForegroundColor Green
        }
    } catch {
        Write-Host "Erro ao criar usuário: $_" -ForegroundColor Red
    }
}

function Wait-ForKey {
    Write-Host "`nPressione Enter para continuar..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# Main loop
do {
    Show-MainMenu
    $selection = Read-Host "`nSelecione uma opção"
    
    switch ($selection) {
        '0' { exit }
        '1' { System-Info }
        '2' { User-Management }
        '3' { Process-Services }
        '4' { Network-Tools }
        '5' { Disk-File-Management }
        '6' { Scheduled-Tasks }
        '7' { Windows-Updates }
        '8' { Audit-Logs }
        '9' { Backup-Tools }
        '10' { System-Optimization }
        '11' { Printer-Management }
        '12' { App-Control }
        '13' { AD-Tools }
        '14' { Virtualization-Tools }
        default { Write-Host "Opção inválida" -ForegroundColor Red; Wait-ForKey }
    }
} while ($true)