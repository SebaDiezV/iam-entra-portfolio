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
# Centralizamos toda la configuración en un bloque.
# Esto es una buena práctica: si cambias el tenant o rutas,
# solo modificas este bloque, no todo el script.

$Config = @{
    TenantId       = "25de3db3-c870-4699-be4e-bc4322e9d249"
    LogPath        = ".\logs\onboarding_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    CsvPath        = ".\sample-users.csv"
    DefaultDomain  = "proyectoiam.onmicrosoft.com"
    PasswordLength = 16
}

# Mapeo Departamento → Grupo de Seguridad
# Esto implementa LEAST PRIVILEGE: cada depto tiene exactamente
# los permisos que necesita, sin más. Es el corazón del Art. 25 GDPR.
$DepartmentGroupMap = @{
    "Finance" = "SG-Finance-Users"
    "IT"      = "SG-IT-Users"
    "Legal"   = "SG-Legal-Users"
    "HR"      = "SG-HR-Users"
}

# Países de la UE relevantes para GDPR
# Cualquier usuario con estos códigos irá TAMBIÉN al grupo SG-GDPR-EUResidents
$EUCountryCodes = @("DE", "FR", "IT", "ES", "PT", "NL", "BE", "AT", "PL", "SE")

# ============================================================
# REGION 2: LOGGING FUNCTION (GDPR Art. 30)
# ============================================================
# Art. 30 GDPR exige un "registro de actividades de tratamiento".
# Esta función escribe CADA acción en un archivo de log con timestamp.
# En una auditoría, este log demuestra QUÉ datos se procesaron,
# CUÁNDO y CON QUÉ resultado.

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
}

# ============================================================
# REGION 2: LOGGING FUNCTION (GDPR Art. 30)
# ============================================================
# Art. 30 GDPR exige un "registro de actividades de tratamiento".
# Esta función escribe CADA acción en un archivo de log con timestamp.
# En una auditoría, este log demuestra QUÉ datos se procesaron,
# CUÁNDO y CON QUÉ resultado.

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

        # Escribir en consola con color según severidad
    $Color = switch ($Level) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "Cyan" }
    }
        Write-Host $LogEntry -ForegroundColor $Color

    # Escribir en archivo (persistencia para auditoría)
    # GDPR requiere que estos logs se mantengan y protejan
    Add-Content -Path $Config.LogPath -Value $LogEntry
}

# ============================================================
# REGION 3: PASSWORD GENERATION (GDPR Art. 5 - Confidentiality)
# ============================================================
# Art. 5(1)(f) requiere "integridad y confidencialidad".
# Generamos passwords seguros con complejidad suficiente.
# NUNCA hardcodeamos passwords en el script (mala práctica crítica).

function New-SecureTemporaryPassword {
    # Usamos RNGCryptoServiceProvider — generador criptográficamente seguro.
    # Math.Random() o Get-Random simple NO son seguros para passwords.
    $Chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@#$%^&*"
    $Bytes = New-Object Byte[] $Config.PasswordLength
    $Rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $Rng.GetBytes($Bytes)

    # Mapeamos cada byte a un carácter del set permitido
    $Password = ($Bytes | ForEach-Object { $Chars[$_ % $Chars.Length] }) -join ''

    # Convertimos a SecureString — PowerShell nunca expone el valor en memoria
    return ConvertTo-SecureString $Password -AsPlainText -Force
}

# ============================================================
# REGION 4: USER CREATION FUNCTION
# ============================================================
# Esta función crea UN usuario. La llamaremos en bucle desde el main.
# Separar la lógica en funciones es crucial para:
# - Reutilización (puedes llamarla desde otros scripts)
# - Testing (puedes probar con un solo usuario)
# - Mantenibilidad (si Entra ID cambia una API, solo editas aquí)

function New-OnboardingUser {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$UserData  # Un objeto con los campos del CSV
    )
        # --- Construimos el UPN (User Principal Name) ---
    # Formato estándar empresarial: nombre.apellido@dominio
    # Convertimos a minúsculas y eliminamos espacios (normalize)
    $FirstName = $UserData.FirstName.Trim().ToLower()
    $LastName = $UserData.LastName.Trim().ToLower()
    $UPN = "$FirstName.$LastName@$($Config.DefaultDomain)"

    Write-AuditLog "Processing user: $UPN | Dept: $($UserData.Department) | Country: $($UserData.Country)"

    # --- Verificar si el usuario ya existe ---
    # Idempotencia: el script puede correr múltiples veces sin duplicar usuarios.
    # Esto es importante para GDPR: no queremos crear datos duplicados (Art. 5 - exactitud).
    try {
        $ExistingUser = Get-MgUser -UserId $UPN -ErrorAction SilentlyContinue
        if ($ExistingUser) {
            Write-AuditLog "User $UPN already exists. Skipping creation." -Level "WARNING"
            return $ExistingUser  # Retornamos el usuario existente para asignarlo a grupos
        }
    } catch {
        # Si el error NO es "user not found", lo registramos
        if ($_.Exception.Message -notmatch "Request_ResourceNotFound") {
            Write-AuditLog "Unexpected error checking user $UPN`: $_" -Level "ERROR"
            return $null
        }
    }

    # --- Construir el objeto de usuario para Microsoft Graph ---
    # Cada propiedad tiene un propósito específico:
    $TempPassword = New-SecureTemporaryPassword | ConvertFrom-SecureString -AsPlainText
    $UserParams = @{
        DisplayName         = "$($UserData.FirstName) $($UserData.LastName)"
        GivenName           = $UserData.FirstName.Trim()
        Surname             = $UserData.LastName.Trim()
        UserPrincipalName   = $UPN
        MailNickname        = "$FirstName.$LastName"  # alias interno sin @dominio

        Department          = $UserData.Department
        JobTitle            = $UserData.JobTitle
        OfficeLocation      = $UserData.OfficeLocation

        # UsageLocation es OBLIGATORIO para asignar licencias M365.
        # Para GDPR: determina la jurisdicción del usuario (UE vs no-UE).
        # Formato: ISO 3166-1 alpha-2 (CL, DE, FR, etc.)
        UsageLocation       = $UserData.CountryCode.Trim().ToUpper()

        # Country es el nombre completo (para display), CountryCode para lógica
        Country             = $UserData.Country.Trim()

        AccountEnabled      = $true

        $TempPassword = New-SecureTemporaryPassword | ConvertFrom-SecureString -AsPlainText
        PasswordProfile     = @{
            Password                             = $TempPassword
            ForceChangePasswordNextSignIn        = $true   # Obligatorio por seguridad
        }
    }

    # --- Crear el usuario via Microsoft Graph ---
    try {
        $NewUser = New-MgUser @UserParams
        Write-AuditLog "User created: $UPN | ObjectId: $($NewUser.Id)" -Level "SUCCESS"
        return $NewUser

    } catch {
        # Capturamos el error específico y lo registramos en el audit log
        Write-AuditLog "FAILED to create user $UPN`: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# ============================================================
# REGION 5: GROUP ASSIGNMENT (LEAST PRIVILEGE — GDPR Art. 25)
# ============================================================
# Art. 25 GDPR: "Privacy by Design and by Default"
# Significa que el acceso mínimo es el DEFAULT, no una opción.
# Un usuario nuevo NO tiene acceso a nada hasta que se le asigna explícitamente.

function Add-UserToGroups {
    param(
        [string]$UserId,        # ObjectId del usuario en Entra ID
        [string]$Department,
        [string]$CountryCode
    )

    # Lista de grupos a los que asignaremos al usuario
    $GroupsToAssign = @()

    # 1. Grupo por departamento (Least Privilege por rol)
    if ($DepartmentGroupMap.ContainsKey($Department)) {
        $GroupsToAssign += $DepartmentGroupMap[$Department]
    } else {
        Write-AuditLog "No group mapping for department '$Department'. User will have minimal access." -Level "WARNING"
    }

    # 2. Grupo regional (para políticas de Acceso Condicional por ubicación)
    if ($CountryCode -eq "CL") {
        $GroupsToAssign += "SG-Region-Chile"
    }
        # 3. Grupo GDPR si es residente en la UE (crítico para políticas diferenciadas)
    if ($EUCountryCodes -contains $CountryCode) {
        $GroupsToAssign += "SG-GDPR-EUResidents"
        Write-AuditLog "User $UserId identified as EU resident. Adding GDPR group." -Level "INFO"
    }

    # --- Procesar cada grupo ---
    foreach ($GroupName in $GroupsToAssign) {

        try {
            # Buscamos el grupo por displayName para obtener su ObjectId
            # No hardcodeamos ObjectIds porque cambian entre tenants
            $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction Stop

            if (-not $Group) {
                Write-AuditLog "Group '$GroupName' not found in tenant. Skipping." -Level "ERROR"
                continue  # Salta a la siguiente iteración del foreach
            }

            # Verificar si ya es miembro (idempotencia)
            $ExistingMember = Get-MgGroupMember -GroupId $Group.Id |
                              Where-Object { $_.Id -eq $UserId }

            if ($ExistingMember) {
                Write-AuditLog "User $UserId already member of '$GroupName'. Skipping." -Level "WARNING"
                continue
            }

            # Construimos la referencia al usuario según la API de Graph
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
# REGION 6: MAIN EXECUTION BLOCK
# ============================================================
# Aquí está el flujo principal. PowerShell usa el bloque principal
# como punto de entrada. Todo lo anterior son definiciones (funciones),
# esto es la ejecución real.

# --- Crear directorio de logs si no existe ---
$LogDir = Split-Path $Config.LogPath -Parent
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
Write-AuditLog "=== ONBOARDING SESSION STARTED ===" -Level "INFO"
Write-AuditLog "Operator initiating bulk onboarding process" -Level "INFO"

# --- Conectar a Microsoft Graph ---
# Definimos SOLO los permisos que necesitamos (Least Privilege también para el script)
$RequiredScopes = @(
    "User.ReadWrite.All",       # Crear y editar usuarios
    "GroupMember.ReadWrite.All" # Agregar miembros a grupos
)

try {
    Write-AuditLog "Connecting to Microsoft Graph..." -Level "INFO"

    # Connect-MgGraph abre una ventana de autenticación interactiva.
    # En producción, usarías -ClientId y -CertificateThumbprint (App Registration)
    # Para el portfolio está bien el flujo interactivo.
    Connect-MgGraph -TenantId $Config.TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Successfully authenticated to Microsoft Graph" -Level "SUCCESS"

} catch {
    Write-AuditLog "FATAL: Cannot connect to Microsoft Graph: $_" -Level "ERROR"
    exit 1  # Terminamos el script. Sin conexión, nada funciona.
}

# --- Importar y validar CSV ---
try {
    # Import-Csv convierte cada fila en un PSCustomObject
    # Cada columna del CSV se convierte en una propiedad del objeto
    $Users = Import-Csv -Path $Config.CsvPath -ErrorAction Stop
    Write-AuditLog "CSV loaded: $($Users.Count) users to process" -Level "INFO"

} catch {
    Write-AuditLog "FATAL: Cannot read CSV file: $_" -Level "ERROR"
    exit 1
}

# --- Contadores para el resumen final ---
$Stats = @{ Success = 0; Skipped = 0; Failed = 0 }

# --- Procesar cada usuario del CSV ---
foreach ($UserRow in $Users) {

    # Validación básica: campos obligatorios no pueden estar vacíos
    # GDPR Art. 5(d) - Exactitud: no procesamos datos incompletos
    $RequiredFields = @("FirstName", "LastName", "Department", "Country", "CountryCode")
    $MissingFields = $RequiredFields | Where-Object { [string]::IsNullOrWhiteSpace($UserRow.$_) }

    if ($MissingFields) {
        Write-AuditLog "Skipping row: missing fields [$($MissingFields -join ', ')] for $($UserRow.FirstName) $($UserRow.LastName)" -Level "WARNING"
        $Stats.Skipped++
        continue
    }

    # Crear usuario
    $NewUser = New-OnboardingUser -UserData $UserRow

    if ($NewUser) {
        # Si el usuario fue creado (o ya existía), asignar grupos
        Add-UserToGroups -UserId $NewUser.Id `
                         -Department $UserRow.Department `
                         -CountryCode $UserRow.CountryCode.Trim().ToUpper()
        $Stats.Success++
    } else {
        $Stats.Failed++
    }

    # Pequeña pausa para no saturar los rate limits de Graph API
    # Microsoft Graph tiene límites de solicitudes por segundo
    Start-Sleep -Milliseconds 500
}

# --- Resumen final en el log ---
Write-AuditLog "=== ONBOARDING SESSION COMPLETED ===" -Level "INFO"
Write-AuditLog "Results — Success: $($Stats.Success) | Skipped: $($Stats.Skipped) | Failed: $($Stats.Failed)" -Level "INFO"
Write-AuditLog "Audit log saved to: $($Config.LogPath)" -Level "INFO"

# Desconectar sesión de Graph (buena práctica de seguridad)
Disconnect-MgGraph
Write-AuditLog "Microsoft Graph session disconnected." -Level "INFO"
