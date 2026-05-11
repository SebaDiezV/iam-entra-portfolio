#Requires -Modules Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Access Reviews Configuration Script — Phase 4
    Portfolio Project: IGA with Microsoft Entra ID

.DESCRIPTION
    Creates recurring Access Reviews to enforce periodic certification
    of group memberships, PIM role assignments, and user activity.
    Closes the Permission Creep gap left by Phases 1-3.

.GDPR COMPLIANCE
    Art. 5(1)(a) — Lawfulness: every access has a certified responsible owner
    Art. 5(1)(e) — Storage limitation: access revoked when no longer justified
    Art. 25      — Privacy by Design: periodic review built into access lifecycle
    Art. 32      — Technical measures: formal certification process for all access

.NOTES
    Requires: Entra ID P2
    Permissions: AccessReview.ReadWrite.All, Group.Read.All,
                 RoleManagement.Read.Directory, User.Read.All
#>

# ============================================================
# REGION 1: CONFIGURATION
# ============================================================

$script:LogTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir       = Join-Path $PSScriptRoot "logs"
$script:LogFile      = Join-Path $script:LogDir "access-reviews_$($script:LogTimestamp).log"

if (-not (Test-Path $script:LogDir)) {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null
}
New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

$Config = @{
    TenantId        = "25de3db3-c870-4699-be4e-bc4322e9d249"
    ReviewsJsonPath = Join-Path $PSScriptRoot "access-reviews.json"
    # UPN del admin que actúa como revisor para AR-003
    AdminReviewerUPN = "sdiez@proyectoiam.onmicrosoft.com"
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

function Get-GroupId {
    param([string]$GroupName)
    # Traemos todos y filtramos en PowerShell — más confiable que -Filter
    # Lección aprendida en Fase 2 con Named Locations
    $Group = Get-MgGroup -All | Where-Object { $_.DisplayName -eq $GroupName }
    if (-not $Group) {
        Write-AuditLog "Group '$GroupName' not found." -Level "ERROR"
        return $null
    }
    return $Group.Id
}

function Get-RoleDefinitionId {
    param([string]$RoleName)
    $Role = Get-MgRoleManagementDirectoryRoleDefinition -All |
            Where-Object { $_.DisplayName -eq $RoleName }
    if (-not $Role) {
        Write-AuditLog "Role '$RoleName' not found." -Level "ERROR"
        return $null
    }
    return $Role.Id
}

function Get-UserId {
    param([string]$UPN)
    $User = Get-MgUser -UserId $UPN -ErrorAction SilentlyContinue
    if (-not $User) {
        Write-AuditLog "User '$UPN' not found." -Level "ERROR"
        return $null
    }
    return $User.Id
}

# ============================================================
# REGION 4: RECURRENCE BUILDER
# ============================================================
# Access Reviews usan el mismo modelo de recurrencia que
# Calendar Events en Graph API — reutilización de esquemas.
#
# Una recurrencia mensual con duración de 7 días significa:
# - El review se abre el día 1 de cada mes
# - Los revisores tienen 7 días para responder
# - Al día 8 se aplican los resultados automáticamente
# - El ciclo se repite el mes siguiente

function New-RecurrencePattern {
    param([string]$RecurrenceType)

    # startDate debe ser hoy o en el futuro
    # Usamos el primer día del mes siguiente para ciclos limpios
    $StartDate = (Get-Date -Day 1).AddMonths(1).ToString("yyyy-MM-dd")

    return @{
        pattern = @{
            type     = $RecurrenceType   # "monthly", "weekly", "absoluteMonthly"
            interval = 1                  # cada 1 mes/semana
        }
        range = @{
            type      = "noEnd"           # sin fecha de fin — revisión continua
            startDate = $StartDate
        }
    }
}

# ============================================================
# REGION 5: ACCESS REVIEW CREATORS
# ============================================================

# ----------------------------------------------------------
# AR-001: Review de grupos sensibles (Finance y Legal)
# ----------------------------------------------------------
# Estos grupos contienen usuarios que manejan datos personales.
# GDPR Art. 5(1)(e): los accesos deben revisarse periódicamente.
# El manager de cada usuario es el revisor natural — conoce
# si el empleado aún necesita ese acceso.
#
# defaultDecision "Deny": si el manager no responde en 7 días,
# el acceso se revoca automáticamente. Seguro por defecto.

function New-AR001-GroupReview {
    param([array]$GroupNames)

    $ReviewName = "AR-001-Monthly-Review-SensitiveDepts"

    # Idempotencia: verificar si ya existe
    $Existing = Get-MgIdentityGovernanceAccessReviewDefinition -All |
                Where-Object { $_.DisplayName -eq $ReviewName }
    if ($Existing) {
        Write-AuditLog "Review '$ReviewName' already exists. Skipping." -Level "WARNING"
        return
    }

    # Construimos el scope para múltiples grupos
    # Graph API acepta un scope de tipo "accessReviewQueryScope"
    # con una query que filtra los recursos a revisar
    $GroupIds   = $GroupNames | ForEach-Object { Get-GroupId -GroupName $_ } |
                  Where-Object { $_ -ne $null }

    if ($GroupIds.Count -eq 0) {
        Write-AuditLog "No valid groups found for AR-001. Skipping." -Level "ERROR"
        return
    }

    # Para revisar múltiples grupos usamos un scope combinado
    # Cada grupo genera su propio "instance scope"
    $Scopes = $GroupIds | ForEach-Object {
        @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/groups/$_/members"
            queryType     = "MicrosoftGraph"
        }
    }

    $ReviewBody = @{
        displayName             = $ReviewName
        descriptionForAdmins    = "Monthly review of Finance and Legal group memberships - GDPR Art. 5(1)(e)"
        descriptionForReviewers = "Please review and confirm that each user still requires access to this group. Deny if unsure."

        # Scope: qué se revisa
        # principalScopes define a quién aplica (todos los miembros)
        scope = @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/groups/$($GroupIds[0])/members"
            queryType     = "MicrosoftGraph"
        }

        # Reviewers: quién revisa
        # "managers" significa que el manager de cada usuario es el revisor
        # Si un usuario no tiene manager, el fallback es el admin del tenant
        reviewers = @(
            @{
                query     = "./manager"
                queryType = "MicrosoftGraph"
            }
        )

        # Fallback reviewer si el usuario no tiene manager asignado
        fallbackReviewers = @(
            @{
                query     = "/users/$((Get-UserId -UPN $Config.AdminReviewerUPN))"
                queryType = "MicrosoftGraph"
            }
        )

        settings = @{
            # Cuánto tiempo tienen los revisores para responder
            instanceDurationInDays  = 7

            # Qué pasa si el reviewer no responde → Deny = revocar acceso
            # GDPR: el acceso se revoca si no se certifica activamente
            defaultDecisionEnabled  = $true
            defaultDecision         = "Deny"

            # Aplicar resultados automáticamente al cerrar el review
            # Sin esto, alguien tendría que aplicar los cambios manualmente
            autoApplyDecisionsEnabled = $true

            # Mostrar recomendaciones al reviewer basadas en actividad del usuario
            # Si el usuario no ha iniciado sesión en 30 días → recomendación: Deny
            recommendationsEnabled  = $true

            # Justificación requerida para cada decisión
            # Crea un rastro auditable de por qué se aprobó o denegó
            justificationRequiredOnApproval = $true

            recurrence = New-RecurrencePattern -RecurrenceType "absoluteMonthly"
        }
    }

    try {
        $Review = New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter $ReviewBody
        Write-AuditLog "Access Review created: '$ReviewName' | Id: $($Review.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$ReviewName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ----------------------------------------------------------
# AR-002: Review de roles PIM elegibles
# ----------------------------------------------------------
# Los roles configurados en Fase 3 necesitan revisión periódica.
# ¿Sigue siendo necesario que este usuario tenga este rol elegible?
# El propio usuario es el revisor (self-review) — debe justificar
# por qué aún necesita acceso a ese rol.
#
# En producción, roles críticos como Global Administrator tendrían
# un revisor externo (su manager), no self-review.

function New-AR002-PIMRoleReview {
    param([array]$RoleNames)

    $ReviewName = "AR-002-Monthly-Review-PIMRoles"

    $Existing = Get-MgIdentityGovernanceAccessReviewDefinition -All |
                Where-Object { $_.DisplayName -eq $ReviewName }
    if ($Existing) {
        Write-AuditLog "Review '$ReviewName' already exists. Skipping." -Level "WARNING"
        return
    }

    # Para roles de directorio, el scope usa un query diferente
    # apuntando al roleAssignmentScheduleInstances de cada rol
    $RoleIds = $RoleNames | ForEach-Object { Get-RoleDefinitionId -RoleName $_ } |
               Where-Object { $_ -ne $null }

    if ($RoleIds.Count -eq 0) {
        Write-AuditLog "No valid roles found for AR-002. Skipping." -Level "ERROR"
        return
    }

    $ReviewBody = @{
        displayName          = $ReviewName
        descriptionForAdmins = "Monthly review of PIM eligible role assignments - GDPR Art. 32"
        descriptionForReviewers = "Confirm you still require this privileged role. Deny if no longer needed."

        scope = @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            # Query que apunta a las asignaciones elegibles de roles de directorio
            query         = "/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition&`$filter=roleDefinitionId eq '$($RoleIds[0])'"
            queryType     = "MicrosoftGraph"
        }

        # Self-review: el propio usuario revisa su acceso
        # Apropiado para roles de menor criticidad
        reviewers = @(
            @{
                query     = "/users/$((Get-UserId -UPN $Config.AdminReviewerUPN))"
                queryType = "MicrosoftGraph"
            }
        )

        settings = @{
            instanceDurationInDays          = 7
            defaultDecisionEnabled          = $true
            defaultDecision                 = "Deny"
            autoApplyDecisionsEnabled       = $true
            recommendationsEnabled          = $true
            justificationRequiredOnApproval = $true
            recurrence                      = New-RecurrencePattern -RecurrenceType "absoluteMonthly"
        }
    }

    try {
        $Review = New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter $ReviewBody
        Write-AuditLog "Access Review created: '$ReviewName' | Id: $($Review.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$ReviewName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ----------------------------------------------------------
# AR-003: Review de usuarios inactivos
# ----------------------------------------------------------
# Usuarios que no han iniciado sesión en mucho tiempo son un riesgo.
# Pueden ser exempleados, cuentas de servicio olvidadas, o cuentas
# comprometidas que el atacante no usa frecuentemente para no alertar.
#
# GDPR Art. 5(1)(e): los datos personales (incluyendo cuentas de usuario)
# no deben mantenerse más tiempo del necesario.
# Una cuenta inactiva = dato personal sin propósito activo = debe revisarse.

function New-AR003-InactiveUsersReview {

    $ReviewName = "AR-003-Monthly-Review-InactiveUsers"

    $Existing = Get-MgIdentityGovernanceAccessReviewDefinition -All |
                Where-Object { $_.DisplayName -eq $ReviewName }
    if ($Existing) {
        Write-AuditLog "Review '$ReviewName' already exists. Skipping." -Level "WARNING"
        return
    }

    $AdminId = Get-UserId -UPN $Config.AdminReviewerUPN
    if (-not $AdminId) {
        Write-AuditLog "Admin reviewer not found. Skipping AR-003." -Level "ERROR"
        return
    }

    $ReviewBody = @{
        displayName          = $ReviewName
        descriptionForAdmins = "Monthly review of all tenant users for inactivity - GDPR Art. 5(1)(e)"
        descriptionForReviewers = "Review inactive users. Deny access for accounts no longer required."

        # Scope: todos los usuarios del tenant
        scope = @{
            "@odata.type" = "#microsoft.graph.accessReviewQueryScope"
            query         = "/users"
            queryType     = "MicrosoftGraph"
        }

        # Revisor: el administrador IAM
        # En producción: HR + managers + Security team
        reviewers = @(
            @{
                query     = "/users/$AdminId"
                queryType = "MicrosoftGraph"
            }
        )

        settings = @{
            instanceDurationInDays          = 7
            defaultDecisionEnabled          = $true
            # Para usuarios: si nadie certifica la cuenta → se deshabilita
            defaultDecision                 = "Deny"
            autoApplyDecisionsEnabled       = $true
            # Las recomendaciones son especialmente útiles aquí:
            # Entra ID sugiere "Deny" para usuarios sin actividad reciente
            recommendationsEnabled          = $true
            justificationRequiredOnApproval = $true
            recurrence                      = New-RecurrencePattern -RecurrenceType "absoluteMonthly"
        }
    }

    try {
        $Review = New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter $ReviewBody
        Write-AuditLog "Access Review created: '$ReviewName' | Id: $($Review.Id)" -Level "SUCCESS"
    } catch {
        Write-AuditLog "FAILED to create '$ReviewName': $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================
# REGION 6: MAIN EXECUTION
# ============================================================

Write-AuditLog "=== ACCESS REVIEWS CONFIGURATION STARTED ===" -Level "INFO"
Write-AuditLog "Purpose: Close the Permission Creep gap — GDPR Art. 5(1)(e)" -Level "INFO"

$RequiredScopes = @(
    "AccessReview.ReadWrite.All",        # Crear y gestionar Access Reviews
    "Group.Read.All",                    # Leer grupos para scope de AR-001
    "RoleManagement.Read.Directory",     # Leer roles para scope de AR-002
    "User.Read.All"                      # Leer usuarios para AR-003 y resolución de IDs
)

try {
    Connect-MgGraph -TenantId $Config.TenantId -Scopes $RequiredScopes -ErrorAction Stop
    Write-AuditLog "Authenticated as: $((Get-MgContext).Account)" -Level "SUCCESS"
} catch {
    Write-AuditLog "FATAL: Cannot connect to Graph: $_" -Level "ERROR"
    exit 1
}

# Cargar definiciones desde JSON
try {
    $ReviewDefs = Get-Content $Config.ReviewsJsonPath | ConvertFrom-Json
    Write-AuditLog "Loaded $($ReviewDefs.Count) review definitions from JSON" -Level "INFO"
} catch {
    Write-AuditLog "FATAL: Cannot read reviews JSON: $_" -Level "ERROR"
    exit 1
}

# Desplegar cada review
Write-AuditLog "--- Deploying Access Reviews ---" -Level "INFO"

$AR001 = $ReviewDefs | Where-Object { $_.scope -eq "groups" }
$AR002 = $ReviewDefs | Where-Object { $_.scope -eq "roles" }
$AR003 = $ReviewDefs | Where-Object { $_.scope -eq "users" }

New-AR001-GroupReview  -GroupNames $AR001.groupNames
New-AR002-PIMRoleReview -RoleNames $AR002.roleNames
New-AR003-InactiveUsersReview

Write-AuditLog "=== ACCESS REVIEWS CONFIGURATION COMPLETED ===" -Level "INFO"
Write-AuditLog "Reviews will start on the 1st of next month" -Level "INFO"
Write-AuditLog "Default decision: Deny — access revoked if not actively certified" -Level "WARNING"
Write-AuditLog "Manage reviews at: https://aka.ms/myaccess" -Level "INFO"

Disconnect-MgGraph
Write-AuditLog "Graph session disconnected." -Level "INFO"