#Requires -Modules Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    PIM Configuration Script — Phase 3
    Portfolio Project: IGA with Microsoft Entra ID

.DESCRIPTION
    Configures Privileged Identity Management (PIM) for Just-In-Time access:
    - Assigns eligible roles to the IAM administrator
    - Configures role activation settings (MFA, justification, max duration)
    - Implements least standing privilege principle

.GDPR COMPLIANCE
    Art. 5(1)(f) — Confidentiality: minimal exposure window for privileged access
    Art. 25      — Privacy by Design: privileged access denied by default
    Art. 32      — Technical measures: JIT + MFA + justification for role activation

.NOTES
    Requires: Entra ID P2 (PIM is a P2 feature)
    Permissions: RoleManagement.ReadWrite.Directory, PrivilegedAccess.ReadWrite.AzureAD
#>

# ============================================================
# REGION 1: CONFIGURATION
# ============================================================

$script:LogTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir       = Join-Path $PSScriptRoot "logs"
$script:LogFile      = Join-Path $script:LogDir "pim-config_$($script:LogTimestamp).log"

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

$Config = @{
    TenantId         = "YOUR-TENANT-ID-HERE"
    RolesJsonPath    = Join-Path $PSScriptRoot "pim-roles.json"
    # UPN del usuario que recibirá las asignaciones elegibles
    # En producción esto vendría de un parámetro o CSV
    TargetUserUPN    = "sdiez@proyectoiam.onmicrosoft.com"
}

# ============================================================
# REGION 2: AUDIT LOG
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
# REGION 3: HELPER FUNCTIONS
# ============================================================

# Resuelve el nombre de un rol a su Object ID en Entra ID
# Los IDs de roles built-in son constantes entre tenants,
# pero los resolvemos dinámicamente para mayor robustez
function Get-RoleDefinitionId {
    param([string]$RoleName)

    $RoleDef = Get-MgRoleManagementDirectoryRoleDefinition `
               -Filter "displayName eq '$RoleName'" `
               -ErrorAction SilentlyContinue

    if (-not $RoleDef) {
        Write-AuditLog "Role '$RoleName' not found in directory." -Level "ERROR"
        return $null
    }
    return $RoleDef.Id
}

# Resuelve un UPN a su Object ID
# PIM trabaja con Object IDs, no UPNs
function Get-UserId {
    param([string]$UPN)

    $User = Get-MgUser -UserId $UPN -ErrorAction SilentlyContinue
    if (-not $User) {
        Write-AuditLog "User '$UPN' not found in directory." -Level "ERROR"
        return $null
    }
    return $User.Id
}

# ============================================================
# REGION 4: PIM ROLE SETTINGS
# ============================================================
# Antes de asignar roles, configuramos las REGLAS de activación.
# Esto define QUÉ debe hacer el usuario para activar el rol:
# - ¿Requiere MFA?
# - ¿Requiere justificación escrita?
# - ¿Cuánto tiempo máximo puede estar activo?
#
# En Graph API, estas reglas se llaman "role management policy rules"
# y están asociadas a cada rol en el scope del tenant.
#
# GDPR Art. 32: las reglas de activación son las medidas técnicas
# que garantizan que el acceso privilegiado sea controlado y auditable.

function Set-PIMRoleSettings {
    param(
        [string]$RoleDefinitionId,
        [string]$RoleName,
        [bool]$RequireMFA,
        [bool]$RequireJustification,
        [string]$MaxActivationDuration
    )

    Write-AuditLog "Configuring PIM settings for role: '$RoleName'"

    try {
        # Obtener la política asociada al rol
        $PolicyAssignment = Get-MgPolicyRoleManagementPolicyAssignment `
            -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$RoleDefinitionId'" `
            -ExpandProperty "policy(`$expand=rules)" `
            -ErrorAction Stop

        if (-not $PolicyAssignment) {
            Write-AuditLog "No policy found for '$RoleName'. Skipping." -Level "WARNING"
            return
        }

        $PolicyId = $PolicyAssignment.PolicyId

        # FIX: modificar reglas individualmente en lugar de enviar el conjunto
        # Cada regla se actualiza con su propio endpoint PATCH

        # Regla 1: Enablement (MFA + Justification)
        $EnabledControls = @()
        if ($RequireMFA)           { $EnabledControls += "MultiFactorAuthentication" }
        if ($RequireJustification) { $EnabledControls += "Justification" }

        $EnablementRule = @{
            "@odata.type"     = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
            "id"              = "Enablement_EndUser_Assignment"
            "enabledControls" = $EnabledControls
        }

        Update-MgPolicyRoleManagementPolicyRule `
            -UnifiedRoleManagementPolicyId $PolicyId `
            -UnifiedRoleManagementPolicyRuleId "Enablement_EndUser_Assignment" `
            -BodyParameter $EnablementRule `
            -ErrorAction Stop

        Write-AuditLog "  Enablement rule updated — MFA: $RequireMFA | Justification: $RequireJustification" -Level "SUCCESS"

        # Regla 2: Expiration (duración máxima)
        $ExpirationRule = @{
            "@odata.type"          = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
            "id"                   = "Expiration_EndUser_Assignment"
            "isExpirationRequired" = $true
            "maximumDuration"      = $MaxActivationDuration
        }

        Update-MgPolicyRoleManagementPolicyRule `
            -UnifiedRoleManagementPolicyId $PolicyId `
            -UnifiedRoleManagementPolicyRuleId "Expiration_EndUser_Assignment" `
            -BodyParameter $ExpirationRule `
            -ErrorAction Stop

        Write-AuditLog "  Expiration rule updated — Max duration: $MaxActivationDuration" -Level "SUCCESS"

    } catch {
        Write-AuditLog "FAILED to configure settings for '$RoleName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================
# REGION 5: ELIGIBLE ROLE ASSIGNMENT
# ============================================================
# Aquí asignamos el rol como ELIGIBLE — no activo.
# El usuario aparece en PIM como "elegible" para el rol,
# pero no tiene ningún permiso hasta que lo active manualmente.
#
# Esta es la diferencia fundamental con una asignación directa:
# - Asignación directa → permisos inmediatos y permanentes (Standing Privilege)
# - Asignación PIM eligible → sin permisos hasta activación JIT

function New-PIMEligibleAssignment {
    param(
        [string]$UserId,
        [string]$RoleDefinitionId,
        [string]$RoleName,
        [string]$Justification
    )

    Write-AuditLog "Creating eligible assignment: '$RoleName' → User: $($Config.TargetUserUPN)"

    # Verificar si ya existe una asignación eligible para este rol y usuario
    # Idempotencia: no creamos duplicados
    $ExistingAssignment = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
        -Filter "principalId eq '$UserId' and roleDefinitionId eq '$RoleDefinitionId'" `
        -ErrorAction SilentlyContinue

    if ($ExistingAssignment) {
        Write-AuditLog "Eligible assignment for '$RoleName' already exists. Skipping." -Level "WARNING"
        return
    }

    # Construimos la solicitud de asignación
    # action "adminAssign" = el admin asigna directamente (sin flujo de aprobación)
    # scheduleInfo define la vigencia de la asignación eligible:
    #   - startDateTime: ahora
    #   - expiration type "noExpiration": la elegibilidad no expira
    #     (el ROL sí expira al activarse, pero la ELEGIBILIDAD es permanente)
    $AssignmentBody = @{
        action           = "adminAssign"
        justification    = $Justification
        roleDefinitionId = $RoleDefinitionId
        directoryScopeId = "/"          # Scope: tenant completo
        principalId      = $UserId
        scheduleInfo     = @{
            startDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            expiration    = @{
                type = "noExpiration"   # La elegibilidad no expira
            }
        }
    }

    try {
        $Assignment = New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest `
                      -BodyParameter $AssignmentBody `
                      -ErrorAction Stop

        Write-AuditLog "Eligible assignment created: '$RoleName' | RequestId: $($Assignment.Id)" -Level "SUCCESS"

    } catch {
        Write-AuditLog "FAILED to assign '$RoleName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================
# REGION 6: MAIN EXECUTION
# ============================================================

Write-AuditLog "=== PIM CONFIGURATION STARTED ===" -Level "INFO"
Write-AuditLog "Target user: $($Config.TargetUserUPN)" -Level "INFO"
Write-AuditLog "Principle: Just-In-Time access — no standing privilege" -Level "INFO"

# Conectar a Graph con permisos PIM
$RequiredScopes = @(
    "RoleManagement.ReadWrite.Directory",    # Asignar roles en Entra ID
    "PrivilegedAccess.ReadWrite.AzureAD"     # Gestionar configuración PIM
)

try {
    Connect-MgGraph -TenantId $Config.TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Authenticated as: $((Get-MgContext).Account)" -Level "SUCCESS"
} catch {
    Write-AuditLog "FATAL: Cannot connect to Graph: $_" -Level "ERROR"
    exit 1
}

# Resolver el Object ID del usuario objetivo
$TargetUserId = Get-UserId -UPN $Config.TargetUserUPN
if (-not $TargetUserId) {
    Write-AuditLog "FATAL: Target user not found. Exiting." -Level "ERROR"
    exit 1
}
Write-AuditLog "Target user resolved | ObjectId: $TargetUserId" -Level "SUCCESS"

# Cargar definiciones de roles desde JSON
try {
    $RoleDefinitions = Get-Content $Config.RolesJsonPath | ConvertFrom-Json
    Write-AuditLog "Loaded $($RoleDefinitions.Count) role definitions from JSON" -Level "INFO"
} catch {
    Write-AuditLog "FATAL: Cannot read roles JSON: $_" -Level "ERROR"
    exit 1
}

# Procesar cada rol
foreach ($RoleDef in $RoleDefinitions) {

    Write-AuditLog "--- Processing role: $($RoleDef.roleName) ---" -Level "INFO"

    # Resolver ID del rol
    $RoleId = Get-RoleDefinitionId -RoleName $RoleDef.roleName
    if (-not $RoleId) { continue }

    Write-AuditLog "Role resolved | Id: $RoleId"

    # Paso 1: Configurar settings del rol (MFA, justificación, duración)
    Set-PIMRoleSettings `
        -RoleDefinitionId    $RoleId `
        -RoleName            $RoleDef.roleName `
        -RequireMFA          $RoleDef.requireMFA `
        -RequireJustification $RoleDef.requireJustification `
        -MaxActivationDuration $RoleDef.maxActivationDuration

    # Paso 2: Crear asignación eligible
    New-PIMEligibleAssignment `
        -UserId           $TargetUserId `
        -RoleDefinitionId $RoleId `
        -RoleName         $RoleDef.roleName `
        -Justification    $RoleDef.justification

    Start-Sleep -Milliseconds 500
}

# Resumen
Write-AuditLog "=== PIM CONFIGURATION COMPLETED ===" -Level "INFO"
Write-AuditLog "Roles configured with JIT access — no standing privilege assigned" -Level "INFO"
Write-AuditLog "User can activate roles via: https://aka.ms/myprivilegedaccess" -Level "INFO"

Disconnect-MgGraph
Write-AuditLog "Graph session disconnected." -Level "INFO"