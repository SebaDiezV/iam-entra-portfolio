#Requires -Modules Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Conditional Access Policy Deployment — Phase 2
    Portfolio Project: IGA with Microsoft Entra ID

.DESCRIPTION
    Deploys three Conditional Access policies using Microsoft Graph API:
    - CA-001: Require MFA for all users
    - CA-002: Block EU residents signing in from outside EU/Chile
    - CA-003: Require compliant device for Finance and Legal users

.GDPR COMPLIANCE
    Art. 32 — Technical measures for data security (MFA, device compliance)
    Art. 25 — Privacy by Design (access blocked by default from untrusted locations)
    Art. 5(1)(f) — Confidentiality through strong authentication controls

.NOTES
    All policies deploy in Report-Only mode first.
    This is mandatory — never deploy CA policies directly to production.
    Requires: Entra ID P1 or P2
    Permissions: Policy.ReadWrite.ConditionalAccess, Policy.Read.All
#>

# ============================================================
# REGION 1: CONFIGURATION
# ============================================================

$script:LogTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir       = Join-Path $PSScriptRoot "logs"
$script:LogFile      = Join-Path $script:LogDir "ca-deployment_$($script:LogTimestamp).log"

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

$Config = @{
    TenantId          = "25de3db3-c870-4699-be4e-bc4322e9d249"
    LocationsJsonPath = Join-Path $PSScriptRoot "named-locations.json"
}

# ============================================================
# REGION 2: AUDIT LOG (mismo patrón que Fase 1 — consistencia)
# ============================================================

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO","SUCCESS","WARNING","ERROR")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    $LogEntry  = "[$Timestamp] [$Level] $Message"
    $Color = switch ($Level) {
        "SUCCESS" { "Green" } "WARNING" { "Yellow" }
        "ERROR"   { "Red"   } default   { "Cyan"   }
    }
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $script:LogFile -Value $LogEntry -Encoding UTF8
}

# ============================================================
# REGION 3: NAMED LOCATIONS
# ============================================================
# Named Locations son zonas geográficas que Entra ID usa para
# evaluar condiciones de acceso. Las definimos una vez y las
# referenciamos en múltiples políticas.
#
# GDPR Art. 25: al bloquear acceso desde ubicaciones no autorizadas
# estamos aplicando "privacy by default" — el acceso está denegado
# a menos que la ubicación sea explícitamente permitida.

function New-NamedLocations {
    param([string]$JsonPath)

    Write-AuditLog "Loading named locations from: $JsonPath"

    $Locations    = Get-Content $JsonPath | ConvertFrom-Json
    $LocationsMap = @{}

    # FIX: traer TODAS las ubicaciones existentes de una vez
    # y filtrar en PowerShell — más confiable que -Filter en Graph
    $ExistingLocations = Get-MgIdentityConditionalAccessNamedLocation -All

    foreach ($Location in $Locations) {

        # Buscar por nombre en la lista que ya tenemos en memoria
        $Existing = $ExistingLocations | Where-Object { $_.DisplayName -eq $Location.name }

        if ($Existing) {
            Write-AuditLog "Named Location '$($Location.name)' already exists | Id: $($Existing.Id)" -Level "WARNING"
            # FIX: guardamos el ID correctamente en el mapa
            $LocationsMap[$Location.name] = $Existing.Id
            continue
        }

        $Body = @{
            "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
            displayName                       = $Location.name
            countriesAndRegions               = $Location.countriesAndRegions
            includeUnknownCountriesAndRegions = $Location.includeUnknownCountriesAndRegions
        }

        try {
            $NewLocation = New-MgIdentityConditionalAccessNamedLocation -BodyParameter $Body
            Write-AuditLog "Named Location created: '$($Location.name)' | Id: $($NewLocation.Id)" -Level "SUCCESS"
            $LocationsMap[$Location.name] = $NewLocation.Id
        } catch {
            Write-AuditLog "FAILED to create '$($Location.name)': $($_.Exception.Message)" -Level "ERROR"
        }
    }

    # FIX: verificar que el mapa quedó completo antes de retornar
    foreach ($Location in $Locations) {
        if (-not $LocationsMap.ContainsKey($Location.name)) {
            Write-AuditLog "WARNING: Location '$($Location.name)' missing from map. CA-002 may fail." -Level "ERROR"
        }
    }

    return $LocationsMap
}

# ============================================================
# REGION 4: POLICY HELPERS
# ============================================================
# Antes de crear una política necesitamos los Object IDs de los grupos.
# No los hardcodeamos porque cambian entre tenants.
# Esta función busca un grupo por nombre y retorna su ID.

function Get-GroupId {
    param([string]$GroupName)
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    if (-not $Group) {
        Write-AuditLog "Group '$GroupName' not found in tenant." -Level "ERROR"
        return $null
    }
    return $Group.Id
}

# ============================================================
# REGION 5: CA POLICY DEFINITIONS
# ============================================================
# Cada función crea UNA política. Separar en funciones permite:
# - Desplegar políticas individualmente si falla una
# - Entender cada política de forma aislada
# - Reutilizar en otros proyectos

# ----------------------------------------------------------
# CA-001: MFA para todos los usuarios
# ----------------------------------------------------------
# Esta es la política base de cualquier arquitectura Zero Trust.
# "Nunca confíes, siempre verifica" — el MFA es la verificación mínima.
#
# GDPR Art. 32: el MFA es una medida técnica de seguridad apropiada
# para proteger el acceso a datos personales.
#
# Report-Only: la activamos en modo observación primero.
# Esto nos permite ver en los logs de Entra ID qué usuarios
# habrían sido afectados, sin bloquear a nadie todavía.

function New-CA001-MFAAllUsers {

    $PolicyName = "CA-001-Require-MFA-AllUsers"

    $Existing = Get-MgIdentityConditionalAccessPolicy `
                -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-AuditLog "Policy '$PolicyName' already exists. Skipping." -Level "WARNING"
        return
    }

    # Estructura de una política de Conditional Access:
    # conditions → CUÁNDO se aplica (usuarios, apps, ubicaciones, dispositivos)
    # grantControls → QUÉ debe cumplir el usuario para acceder
    # sessionControls → QUÉ restricciones aplican durante la sesión
    $PolicyBody = @{
        displayName = $PolicyName
        state       = "enabledForReportingButNotEnforced"  # Report-Only — nunca "enabled" en el primer deploy

        conditions = @{
            users = @{
                includeUsers = @("All")   # Todos los usuarios del tenant
                excludeUsers = @()        # En producción excluirías la cuenta break-glass
            }
            applications = @{
                includeApplications = @("All")  # Todas las apps registradas en Entra ID
            }
            # No definimos locations ni platforms → aplica desde cualquier lugar y dispositivo
        }

        grantControls = @{
            operator        = "OR"   # OR = basta con cumplir UNO de los controles
                                     # AND = debe cumplir TODOS (más restrictivo)
            builtInControls = @("mfa")  # El usuario debe completar MFA para acceder
        }
    }

    try {
        $Policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody
        Write-AuditLog "Policy created: '$PolicyName' | Mode: Report-Only | Id: $($Policy.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$PolicyName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ----------------------------------------------------------
# CA-002: Bloquear acceso de EU Residents fuera de EU/Chile
# ----------------------------------------------------------
# Esta política protege los datos de ciudadanos europeos.
# Si un usuario marcado como residente UE intenta conectarse
# desde Asia, EEUU o cualquier otra región → acceso bloqueado.
#
# GDPR Art. 25 + Art. 32: restricción geográfica como medida
# técnica para garantizar que los datos personales de ciudadanos
# UE solo se acceden desde jurisdicciones controladas.

function New-CA002-BlockEUResidentsOutsideEU {
    param([hashtable]$LocationsMap)

    $PolicyName = "CA-002-Block-EUResidents-OutsideAllowedRegions"

    $Existing = Get-MgIdentityConditionalAccessPolicy `
                -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-AuditLog "Policy '$PolicyName' already exists. Skipping." -Level "WARNING"
        return
    }

    # Obtenemos el ID del grupo y las ubicaciones permitidas
    $EUGroupId  = Get-GroupId -GroupName "SG-GDPR-EUResidents"
    $EULocId    = $LocationsMap["Allowed-Region-EuropeanUnion"]
    $CLLocId    = $LocationsMap["Allowed-Region-Chile"]

    if (-not $EUGroupId -or -not $EULocId -or -not $CLLocId) {
        Write-AuditLog "Missing required resources for CA-002. Skipping." -Level "ERROR"
        return
    }

    $PolicyBody = @{
        displayName = $PolicyName
        state       = "enabledForReportingButNotEnforced"

        conditions = @{
            users = @{
                includeGroups = @($EUGroupId)  # Solo aplica a residentes UE
            }
            applications = @{
                includeApplications = @("All")
            }
            locations = @{
                includeLocations = @("All")           # Empieza desde cualquier ubicación
                excludeLocations = @($EULocId, $CLLocId)  # EXCEPTO UE y Chile (permitidas)
                # Lógica: si estás en UE o Chile → no aplica esta política
                # Si estás en cualquier otro lugar → se evalúa → bloqueo
            }
        }

        grantControls = @{
            operator        = "OR"
            builtInControls = @("block")  # Bloqueo total — sin excepción posible
        }
    }

    try {
        $Policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody
        Write-AuditLog "Policy created: '$PolicyName' | Mode: Report-Only | Id: $($Policy.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$PolicyName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ----------------------------------------------------------
# CA-003: Dispositivo compliant para Finance y Legal
# ----------------------------------------------------------
# Finance y Legal manejan los datos más sensibles de la organización.
# No basta con MFA — el dispositivo desde el que acceden también
# debe estar registrado y gestionado por la empresa.
#
# "Compliant device" significa que el dispositivo pasa las políticas
# de Intune: cifrado activo, antivirus actualizado, OS actualizado, etc.
#
# GDPR Art. 32: medidas técnicas proporcionales al riesgo.
# Finance y Legal tienen mayor riesgo → mayor control requerido.

function New-CA003-CompliantDeviceFinanceLegal {

    $PolicyName = "CA-003-Require-CompliantDevice-Finance-Legal"

    $Existing = Get-MgIdentityConditionalAccessPolicy `
                -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-AuditLog "Policy '$PolicyName' already exists. Skipping." -Level "WARNING"
        return
    }

    $FinanceGroupId = Get-GroupId -GroupName "SG-Finance-Users"
    $LegalGroupId   = Get-GroupId -GroupName "SG-Legal-Users"

    if (-not $FinanceGroupId -or -not $LegalGroupId) {
        Write-AuditLog "Missing required groups for CA-003. Skipping." -Level "ERROR"
        return
    }

    $PolicyBody = @{
        displayName = $PolicyName
        state       = "enabledForReportingButNotEnforced"

        conditions = @{
            users = @{
                # includeGroups acepta múltiples grupos — OR lógico entre ellos
                # Si eres miembro de Finance O Legal → aplica la política
                includeGroups = @($FinanceGroupId, $LegalGroupId)
            }
            applications = @{
                includeApplications = @("All")
            }
            # No filtramos por ubicación — aplica desde cualquier lugar
            # Un dispositivo no compliant es riesgoso desde cualquier red
        }

        grantControls = @{
            # AND significa que debe cumplir AMBOS controles para acceder:
            # 1. Completar MFA
            # 2. Usar un dispositivo compliant (gestionado por Intune)
            operator        = "AND"
            builtInControls = @("mfa", "compliantDevice")
        }
    }

    try {
        $Policy = New-MgIdentityConditionalAccessPolicy -BodyParameter $PolicyBody
        Write-AuditLog "Policy created: '$PolicyName' | Mode: Report-Only | Id: $($Policy.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$PolicyName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================
# REGION 6: MAIN EXECUTION
# ============================================================

Write-AuditLog "=== CONDITIONAL ACCESS DEPLOYMENT STARTED ===" -Level "INFO"
Write-AuditLog "All policies will deploy in Report-Only mode" -Level "INFO"

# Permisos necesarios — mínimo privilegio para el script
$RequiredScopes = @(
    "Policy.ReadWrite.ConditionalAccess",  # Crear/editar políticas CA
    "Policy.Read.All",                     # Leer políticas existentes
    "Group.Read.All",                      # Buscar grupos por nombre
    "Agreement.Read.All"                   # Requerido por algunos endpoints de CA
)

try {
    Connect-MgGraph -TenantId $Config.TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Authenticated as: $((Get-MgContext).Account)" -Level "SUCCESS"
} catch {
    Write-AuditLog "FATAL: Cannot connect to Graph: $_" -Level "ERROR"
    exit 1
}

# Paso 1: Crear Named Locations y obtener sus IDs
Write-AuditLog "--- Creating Named Locations ---" -Level "INFO"
$LocationsMap = New-NamedLocations -JsonPath $Config.LocationsJsonPath

# Paso 2: Desplegar las 3 políticas en orden
Write-AuditLog "--- Deploying Conditional Access Policies ---" -Level "INFO"

New-CA001-MFAAllUsers
New-CA002-BlockEUResidentsOutsideEU -LocationsMap $LocationsMap
New-CA003-CompliantDeviceFinanceLegal

Write-AuditLog "=== DEPLOYMENT COMPLETED ===" -Level "INFO"
Write-AuditLog "IMPORTANT: All policies are in Report-Only mode." -Level "WARNING"
Write-AuditLog "Review sign-in logs in Entra ID before enabling enforcement." -Level "WARNING"

Disconnect-MgGraph
Write-AuditLog "Graph session disconnected." -Level "INFO"