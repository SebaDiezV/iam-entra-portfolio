#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Automated IAM Onboarding Script — Phase 1
    Portfolio Project: IGA with Microsoft Entra ID

.DESCRIPTION
    Creates users from CSV, assigns attributes, applies least-privilege
    group membership, and generates GDPR-compliant audit logs.

.GDPR COMPLIANCE
    Art. 5(1)(f) - Integrity and confidentiality (passwords, secure creation)
    Art. 25      - Data protection by design (minimum privilege)
    Art. 30      - Records of processing activities (audit log)

.AUTHOR
    Sebastián Diez | SC-300 Certified | IAM Engineer

.NOTES
    Requires: Microsoft.Graph PowerShell SDK
    Permissions needed: User.ReadWrite.All, GroupMember.ReadWrite.All
#>

# ============================================================
# REGION 1: CONFIGURATION
# ============================================================

# Timestamp global de sesión — un solo archivo de log por ejecución
$script:LogTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

# Rutas absolutas usando $PSScriptRoot (directorio donde está el script)
# Esto garantiza que funciona sin importar desde dónde se ejecute
$script:LogDir  = Join-Path $PSScriptRoot "logs"
$script:LogFile = Join-Path $script:LogDir "onboarding_$($script:LogTimestamp).log"

# Crear directorio de logs si no existe
if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}

# Crear el archivo de log vacío para garantizar que existe antes de escribir
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

$Config = @{
    TenantId       = "25de3db3-c870-4699-be4e-bc4322e9d249"
    CsvPath        = Join-Path $PSScriptRoot "sample-users.csv"  # ruta absoluta
    DefaultDomain  = "proyectoiam.onmicrosoft.com"
    PasswordLength = 16
}

# Mapeo Departamento → Grupo de Seguridad (Least Privilege — GDPR Art. 25)
$DepartmentGroupMap = @{
    "Finance" = "SG-Finance-Users"
    "IT"      = "SG-IT-Users"
    "Legal"   = "SG-Legal-Users"
    "HR"      = "SG-HR-Users"
}

# Códigos de países UE — usuarios con estos códigos van al grupo GDPR
$EUCountryCodes = @("DE", "FR", "IT", "ES", "PT", "NL", "BE", "AT", "PL", "SE")

# ============================================================
# REGION 2: AUDIT LOG FUNCTION (GDPR Art. 30)
# ============================================================
# Una sola definición, usando $script:LogFile (ruta absoluta)
# Art. 30 GDPR: registro de actividades de tratamiento con timestamp ISO 8601

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $LogEntry  = "[$Timestamp] [$Level] $Message"

    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "Cyan" }
    }

    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $script:LogFile -Value $LogEntry -Encoding UTF8
}

# ============================================================
# REGION 3: HELPER FUNCTIONS
# ============================================================

# Remove-Diacritics: convierte González→gonzalez, Müller→muller
# Necesario porque Entra ID no acepta caracteres no-ASCII en UPNs
function Remove-Diacritics {
    param([string]$Text)
    $Normalized = $Text.Normalize([System.Text.NormalizationForm]::FormD)
    $Builder = [System.Text.StringBuilder]::new()
    foreach ($Char in $Normalized.ToCharArray()) {
        $Category = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($Char)
        if ($Category -ne [System.Globalization.UnicodeCategory]::NonSpacingMark) {
            [void]$Builder.Append($Char)
        }
    }
    return $Builder.ToString().Normalize([System.Text.NormalizationForm]::FormC)
}

# New-SecureTemporaryPassword: generador criptográficamente seguro
# Art. 5(1)(f) GDPR: integridad y confidencialidad
# Usamos RNGCryptoServiceProvider — Math.Random() NO es seguro para passwords
function New-SecureTemporaryPassword {
    $Chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@#$%^&*"
    $Bytes = New-Object Byte[] $Config.PasswordLength
    $Rng   = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $Rng.GetBytes($Bytes)
    $Password = ($Bytes | ForEach-Object { $Chars[$_ % $Chars.Length] }) -join ''
    return ConvertTo-SecureString $Password -AsPlainText -Force
}

# ============================================================
# REGION 4: USER CREATION FUNCTION
# ============================================================

function New-OnboardingUser {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$UserData
    )

    # Normalizar nombre y apellido para construir UPN válido
    $FirstName = (Remove-Diacritics $UserData.FirstName.Trim()).ToLower()
    $LastName  = (Remove-Diacritics $UserData.LastName.Trim()).ToLower()
    $UPN       = "$FirstName.$LastName@$($Config.DefaultDomain)"

    Write-AuditLog "Processing user: $UPN | Dept: $($UserData.Department) | Country: $($UserData.Country)"

    # Idempotencia: verificar si el usuario ya existe antes de crear
    # GDPR Art. 5(d): exactitud — evitamos duplicados
    try {
        $ExistingUser = Get-MgUser -UserId $UPN -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            Write-AuditLog "User $UPN already exists. Skipping creation." -Level "WARNING"
            return $ExistingUser
        }
    } catch {
        if ($_.Exception.Message -notmatch "Request_ResourceNotFound") {
            Write-AuditLog "Unexpected error checking $UPN`: $_" -Level "ERROR"
            return $null
        }
    }

    # FIX CRÍTICO: $TempPassword se genera ANTES del hashtable $UserParams
    # Una asignación de variable dentro de @{} es sintaxis inválida en PowerShell
    $TempPassword = New-SecureTemporaryPassword | ConvertFrom-SecureString -AsPlainText

    $UserParams = @{
        DisplayName       = "$($UserData.FirstName.Trim()) $($UserData.LastName.Trim())"
        GivenName         = $UserData.FirstName.Trim()
        Surname           = $UserData.LastName.Trim()
        UserPrincipalName = $UPN
        MailNickname      = "$FirstName.$LastName"
        Department        = $UserData.Department
        JobTitle          = $UserData.JobTitle
        OfficeLocation    = $UserData.OfficeLocation
        UsageLocation     = $UserData.CountryCode.Trim().ToUpper()
        Country           = $UserData.Country.Trim()
        AccountEnabled    = $true
        PasswordProfile   = @{
            Password                      = $TempPassword
            ForceChangePasswordNextSignIn = $true
        }
    }

    try {
        $NewUser = New-MgUser @UserParams
        Write-AuditLog "User created: $UPN | ObjectId: $($NewUser.Id)" -Level "SUCCESS"
        return $NewUser
    } catch {
        Write-AuditLog "FAILED to create $UPN`: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ============================================================
# REGION 5: GROUP ASSIGNMENT (LEAST PRIVILEGE — GDPR Art. 25)
# ============================================================

function Add-UserToGroups {
    param(
        [string]$UserId,
        [string]$Department,
        [string]$CountryCode
    )

    $GroupsToAssign = @()

    # Grupo por departamento
    if ($DepartmentGroupMap.ContainsKey($Department)) {
        $GroupsToAssign += $DepartmentGroupMap[$Department]
    } else {
        Write-AuditLog "No group mapping for '$Department'. Minimal access applied." -Level "WARNING"
    }

    # Grupo regional Chile
    if ($CountryCode -eq "CL") {
        $GroupsToAssign += "SG-Region-Chile"
    }

    # Grupo GDPR para residentes UE
    if ($EUCountryCodes -contains $CountryCode) {
        $GroupsToAssign += "SG-GDPR-EUResidents"
        Write-AuditLog "EU resident detected ($CountryCode). Adding to GDPR group." -Level "INFO"
    }

    foreach ($GroupName in $GroupsToAssign) {
        try {
            $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop

            if (-not $Group) {
                Write-AuditLog "Group '$GroupName' not found. Skipping." -Level "ERROR"
                continue
            }

            $ExistingMember = Get-MgGroupMember -GroupId $Group.Id |
                              Where-Object { $_.Id -eq $UserId }

            if ($ExistingMember) {
                Write-AuditLog "User already member of '$GroupName'. Skipping." -Level "WARNING"
                continue
            }

            $MemberRef = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$UserId"
            }

            New-MgGroupMember -GroupId $Group.Id -BodyParameter $MemberRef
            Write-AuditLog "User $UserId added to group '$GroupName'" -Level "SUCCESS"

        } catch {
            Write-AuditLog "Failed to add $UserId to '$GroupName'`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# ============================================================
# REGION 6: MAIN EXECUTION
# ============================================================

Write-AuditLog "=== ONBOARDING SESSION STARTED ===" -Level "INFO"
Write-AuditLog "Log file: $($script:LogFile)" -Level "INFO"

# Conectar a Microsoft Graph con mínimos permisos necesarios
$RequiredScopes = @(
    "User.ReadWrite.All",
    "GroupMember.ReadWrite.All"
)

try {
    Write-AuditLog "Connecting to Microsoft Graph..." -Level "INFO"
    Connect-MgGraph -TenantId $Config.TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Authenticated as: $((Get-MgContext).Account)" -Level "SUCCESS"
} catch {
    Write-AuditLog "FATAL: Cannot connect to Graph: $_" -Level "ERROR"
    exit 1
}

# Importar CSV
try {
    $Users = Import-Csv -Path $Config.CsvPath -ErrorAction Stop
    Write-AuditLog "CSV loaded: $($Users.Count) users to process from $($Config.CsvPath)" -Level "INFO"
} catch {
    Write-AuditLog "FATAL: Cannot read CSV: $_" -Level "ERROR"
    exit 1
}

# Contadores
$Stats = @{ Success = 0; Skipped = 0; Failed = 0 }

# Procesar cada usuario
foreach ($UserRow in $Users) {

    $RequiredFields = @("FirstName", "LastName", "Department", "Country", "CountryCode")
    $MissingFields  = $RequiredFields | Where-Object { [string]::IsNullOrWhiteSpace($UserRow.$_) }

    if ($MissingFields) {
        Write-AuditLog "Skipping incomplete row: missing [$($MissingFields -join ', ')] for $($UserRow.FirstName) $($UserRow.LastName)" -Level "WARNING"
        $Stats.Skipped++
        continue
    }

    $NewUser = New-OnboardingUser -UserData $UserRow

    if ($NewUser) {
        Add-UserToGroups -UserId $NewUser.Id `
                         -Department $UserRow.Department `
                         -CountryCode $UserRow.CountryCode.Trim().ToUpper()
        $Stats.Success++
    } else {
        $Stats.Failed++
    }

    Start-Sleep -Milliseconds 500
}

# Resumen final
Write-AuditLog "=== ONBOARDING SESSION COMPLETED ===" -Level "INFO"
Write-AuditLog "Results — Success: $($Stats.Success) | Skipped: $($Stats.Skipped) | Failed: $($Stats.Failed)" -Level "INFO"
Write-AuditLog "Audit log: $($script:LogFile)" -Level "INFO"

Disconnect-MgGraph
Write-AuditLog "Graph session disconnected." -Level "INFO"