# Script de PowerShell para Hardenización avanzada de Windows 11 optimizado

# Función para deshabilitar servicios innecesarios
Function Disable-UnnecessaryServices {
    $services = @(
        'HomeGroupListener',
        'HomeGroupProvider',
        'BluetoothSupport',
        'RemoteRegistry',
        'RemoteDesktop',
        'XboxGipSvc',
        'XblAuthManager',
        'XblGameSave',
        'WMPNetworkSvc',
        'PeerDistSvc',
        'SSDPDiscovery',
        'upnphost',
        'NetTcpPortSharing'
    )

    Get-Service -Name $services | Where-Object {$_.Status -ne 'Stopped'} | ForEach-Object {
        Set-Service -Name $_.Name -StartupType Disabled
    }
}

# Desactivar la cuenta de administrador local
Function Disable-LocalAdminAccount {
    $adminAccount = Get-LocalUser -Name "Administrator"
    if ($adminAccount.Enabled -eq $true) {
        Disable-LocalUser -Name "Administrator"
    }
}

# Establecer política de contraseñas fuertes
Function Set-PasswordPolicy {
    secedit /export /cfg $env:TEMP\secpol.cfg
    $secpol = Get-Content "$env:TEMP\secpol.cfg"
    $secpol = $secpol -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 14'
    $secpol = $secpol -replace 'PasswordComplexity = \d+', 'PasswordComplexity = 1'
    $secpol = $secpol -replace 'LockoutBadCount = \d+', 'LockoutBadCount = 5'
    $secpol | Set-Content "$env:TEMP\secpol.cfg"
    secedit /configure /db %windir%\security\database\secedit.sdb /cfg $env:TEMP\secpol.cfg /areas SECURITYPOLICY
}

# Deshabilitar la compartición administrativa
Function Disable-AdminShares {
    $autoShare = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks"
    if ($autoShare.AutoShareWks -ne 0) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Force
    }
}

# Configurar actualizaciones automáticas
Function Set-AutomaticUpdates {
    $autoUpdate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions"
    if ($autoUpdate.AUOptions -ne 4) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4 -Force
    }
}

# Habilitar BitLocker para cifrado de discos
Function Enable-BitLocker {
    $bitLockerStatus = Get-BitLockerVolume -MountPoint "C:"
    if ($bitLockerStatus.ProtectionStatus -ne 'On') {
        Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -RecoveryPasswordProtector
    }
}

# Habilitar Cortafuegos de Windows con logs independientes y comunicación cifrada
Function Configure-WindowsFirewall {
    $firewallProfiles = @('Domain', 'Public', 'Private')

    foreach ($profile in $firewallProfiles) {
        Set-NetFirewallProfile -Profile $profile -Enabled True
        Set-NetFirewallProfile -Profile $profile -LogFileName "C:\Windows\System32\LogFiles\Firewall\$profile`Firewall.log" -LogMaxSizeKilobytes 16384 -LogAllowed True -LogBlocked True
        Set-NetFirewallProfile -Profile $profile -DefaultInboundAction Block
        Set-NetFirewallProfile -Profile $profile -DefaultOutboundAction Allow
    }

    New-NetFirewallRule -DisplayName "Bloquear SMB en redes públicas" -Profile Public -Direction Inbound -Action Block -Protocol TCP -LocalPort 445,137,138,139
    New-NetFirewallRule -DisplayName "Bloquear ICMP entrante" -Protocol ICMPv4 -Direction Inbound -Action Block
    New-NetFirewallRule -DisplayName "Bloquear RDP en redes públicas" -Profile Public -Direction Inbound -Action Block -Protocol TCP -LocalPort 3389
    New-NetFirewallRule -DisplayName "Bloquear tráfico no autorizado" -Direction Inbound -Action Block

    # Configurar IPsec para comunicaciones cifradas
    $ipsecRules = @(
        @{ DisplayName = "Cifrar tráfico saliente"; Direction = "Outbound"; Action = "Require"; Profile = "Any" },
        @{ DisplayName = "Cifrar tráfico entrante"; Direction = "Inbound"; Action = "Require"; Profile = "Any" }
    )

    foreach ($rule in $ipsecRules) {
        New-NetIPsecRule @rule
    }
}

# Configuración avanzada de SMB/CIFS
Function Harden-SMB {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true -EncryptData $true -MaxConnectionsPerShare 10
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
    New-NetFirewallRule -DisplayName "Bloquear puertos SMB no autorizados" -Direction Inbound -Action Block -Protocol TCP -LocalPort 139,445
}

# Configuración avanzada de restricciones de ejecución de scripts y macros
Function Restrict-ScriptAndMacroExecution {
    Set-ExecutionPolicy AllSigned -Force

    $officeApps = @("Word", "Excel", "PowerPoint")
    foreach ($app in $officeApps) {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\$app\Security" -Name "DisableAllMacros" -Value 1
    }
}

# Deshabilitar el uso de USB
Function Disable-USBDevices {
    $usbStatus = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start"
    if ($usbStatus.Start -ne 4) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4 -Force
    }
}

# Deshabilitar la autorun de medios extraíbles
Function Disable-AutoRun {
    $autoRunStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun"
    if ($autoRunStatus.NoDriveTypeAutoRun -ne 255) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
    }
}

# Deshabilitar Cortana
Function Disable-Cortana {
    $cortanaStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana"
    if ($cortanaStatus.AllowCortana -ne 0) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Force
    }
}

# Deshabilitar Telemetría
Function Disable-Telemetry {
    $telemetryStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry"
    if ($telemetryStatus.AllowTelemetry -ne 0) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
        Stop-Service -Name "DiagTrack"
        Stop-Service -Name "dmwappushservice"
        Set-Service -Name "DiagTrack" -StartupType Disabled
        Set-Service -Name "dmwappushservice" -StartupType Disabled
    }
}

# Configurar auditoría avanzada
Function Configure-Auditing {
    $auditCategories = @(
        "Logon/Logoff",
        "Account Logon",
        "Object Access",
        "Privilege Use",
        "Policy Change",
        "System",
        "Detailed Tracking"
    )

    foreach ($category in $auditCategories) {
        Auditpol /set /category:$category /success:enable /failure:enable
    }
}

# Configuración para aislamiento del kernel y mitigación de memory leaks
Function Configure-KernelIsolation {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettings" -Value 1

    # Activar Memory Integrity (integridad de memoria) para aislamiento del kernel
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1

    Write-Output "Aislamiento del kernel y mitigación de memory leaks configurados."
}

# Ejecutar funciones para hardenización avanzada
Disable-UnnecessaryServices
Disable-LocalAdminAccount
Set-PasswordPolicy
Disable-AdminShares
Set-AutomaticUpdates
Enable-BitLocker
Configure-WindowsFirewall
Harden-SMB
Restrict-ScriptAndMacroExecution
Disable-USBDevices
Disable-AutoRun
Disable-Cortana
Disable-Telemetry
Configure-Auditing
Configure-KernelIsolation

Write-Output "Hardenización avanzada de Windows 11 completada."