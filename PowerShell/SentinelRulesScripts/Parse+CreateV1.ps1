# Script: Parse-SentinelRules.ps1
param(
    [Parameter(Mandatory=$true, ParameterSetName='SingleFile')]
    [string]$InputJsonPath,
    
    [Parameter(Mandatory=$true, ParameterSetName='BatchFiles')]
    [string[]]$InputJsonPaths,
    
    [Parameter(Mandatory=$true, ParameterSetName='Directory')]
    [string]$InputDirectory,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory,
    
    [string]$TenantName = "",
    
    [switch]$IncludeTenantInPath,
    
    [string]$FileExtension = "*.json"
)

# Improved Function to extract source name from rule properties
function Get-SourceName {
    param(
        [PSCustomObject]$Rule,
        [string]$FileName
    )
    
    # Comprehensive source mapping based on your actual sources
    $sourcePatterns = @{
        'MicrosoftDefenderXDR' = @{
            TemplatePatterns = @('*Defender*XDR*', '*MDATP*', '*DefenderATP*', '*MicrosoftDefenderAdvancedThreatProtection*', '*Defender*Advanced*')
            QueryPatterns = @('\bdeviceprocessevents\b', '\bdevicenetworkevents\b', '\bdevicefileevents\b', '\bdevicelogonevent\b', '\bdeviceregistryevent\b', '\badvancedhunting\b', '\bdeviceinfo\b')
            FilenamePatterns = @('*DefenderXDR*', '*Defender-XDR*', '*MDATP*', '*DefenderATP*')
            DisplayNamePatterns = @('*defender.*xdr*', '*mdatp*', '*microsoft defender atp*', '*defender advanced*')
        }
        
        'MicrosoftDefenderForEndpoint' = @{
            TemplatePatterns = @('*MSDefender*Endpoint*', '*MicrosoftDefender*Endpoint*', '*DefenderForEndpoint*', '*MDE*')
            QueryPatterns = @('\bdevicesecurityconfigassessment\b', '\bdevicevulnerabilityassessment\b', '\bdefenderiocindicator\b')
            FilenamePatterns = @('*MSDefender*Endpoint*', '*MicrosoftDefenderForEndpoint*', '*DefenderForEndpoint*', '*MDE*')
            DisplayNamePatterns = @('*microsoft defender for endpoint*', '*defender for endpoint*', '*mde*')
        }
        
        'MicrosoftEntraID' = @{
            TemplatePatterns = @('*EntraID*', '*Entra-ID*', '*EntraIdentity*', '*AzureAD*', '*Azure-AD*', '*AAD*')
            QueryPatterns = @('\bsigninlogs\b', '\bauditlogs\b', '\baadnoninteractiveuserassignlogs\b', '\baadserviceprincipallogins\b', '\bentra\b', '\bazuread\b', '\bidentityinfo\b')
            FilenamePatterns = @('*EntraID*', '*Entra-ID*', '*AzureAD*', '*Azure-AD*', '*AAD*')
            DisplayNamePatterns = @('*entra*id*', '*azure*ad*', '*aad*', '*azure active directory*')
        }
        
        'AmazonWebServices' = @{
            TemplatePatterns = @('*AWS*', '*Amazon*', '*AmazonWebServices*')
            QueryPatterns = @('\bawscloudtrail\b', '\baws_*', '\bamazon\b', '\bs3\b.*\baws\b', '\bec2\b.*\baws\b')
            FilenamePatterns = @('*AWS*', '*Amazon*', '*AmazonWebServices*')
            DisplayNamePatterns = @('*aws*', '*amazon*', '*cloud trail*')
        }
        
        'NetworkSessionEssentials' = @{
            TemplatePatterns = @('*NetworkSession*', '*Network-Session*', '*NetworkSessionEssentials*')
            QueryPatterns = @('\bcommonnetworkconnections\b', '\bnetworkconnection\b', '\bnetworksession\b', '\bvmicomputer\b', '\bnetworkmonitoring\b')
            FilenamePatterns = @('*NetworkSession*', '*Network-Session*', '*NetworkEssentials*')
            DisplayNamePatterns = @('*network session*', '*network connection*', '*network monitoring*')
        }
        
        'ThreatIntelligence' = @{
            TemplatePatterns = @('*ThreatIntel*', '*Threat-Intel*', '*ThreatIntelligence*', '*IOC*', '*Indicator*')
            QueryPatterns = @('\bthreatintelligenceindicator\b', '\bioc\b', '\bindicator\b', '\bmaliciousip\b', '\bthreatintel\b')
            FilenamePatterns = @('*ThreatIntel*', '*Threat-Intel*', '*IOC*', '*Indicator*')
            DisplayNamePatterns = @('*threat intel*', '*ioc*', '*indicator*', '*malicious*', '*threat intelligence*')
        }
        
        'EndpointThreatProtectionEssentials' = @{
            TemplatePatterns = @('*EndpointThreat*', '*Endpoint-Threat*', '*EndpointProtection*', '*EndpointThreatProtectionEssentials*')
            QueryPatterns = @('\bsecurityevent\b', '\bwindowsfirewall\b', '\bsysmon\b', '\bendpoint\b')
            FilenamePatterns = @('*EndpointThreat*', '*Endpoint-Threat*', '*EndpointProtection*')
            DisplayNamePatterns = @('*endpoint threat*', '*endpoint protection*', '*endpoint security*')
        }
        
        'SecurityThreatEssentialSolution' = @{
            TemplatePatterns = @('*SecurityThreat*', '*Security-Threat*', '*ThreatEssential*', '*SecurityEssential*')
            QueryPatterns = @('\bsecurityalert\b', '\bsecurityevent\b', '\bthreat\b', '\bmalware\b')
            FilenamePatterns = @('*SecurityThreat*', '*Security-Threat*', '*ThreatEssential*', '*SecurityEssential*')
            DisplayNamePatterns = @('*security threat*', '*threat essential*', '*security essential*')
        }
        
        'GreyNoiseThreatIntelligence' = @{
            TemplatePatterns = @('*GreyNoise*', '*Grey-Noise*', '*GreyNoiseThreat*')
            QueryPatterns = @('\bgreynoise\b', '\bgrey.*noise\b')
            FilenamePatterns = @('*GreyNoise*', '*Grey-Noise*')
            DisplayNamePatterns = @('*greynoise*', '*grey noise*')
        }
        
        'AttackerToolsThreatProtectionEssentials' = @{
            TemplatePatterns = @('*AttackerTools*', '*Attacker-Tools*', '*AttackerToolsThreat*')
            QueryPatterns = @('\battacker\b', '\bmalicious.*tool\b', '\bhacking.*tool\b', '\bpowershell.*encoded\b')
            FilenamePatterns = @('*AttackerTools*', '*Attacker-Tools*', '*AttackerTool*')
            DisplayNamePatterns = @('*attacker tool*', '*malicious tool*', '*hacking tool*')
        }
        
        'WindowsForwardedEvents' = @{
            TemplatePatterns = @('*WindowsForwarded*', '*Windows-Forwarded*', '*WinEventForward*', '*WEF*')
            QueryPatterns = @('\bwindowsevent\b', '\bforwardedevents\b', '\bwineventlog\b', '\bevent.*forward\b')
            FilenamePatterns = @('*WindowsForwarded*', '*Windows-Forwarded*', '*WinEvent*', '*WEF*')
            DisplayNamePatterns = @('*windows forwarded*', '*forwarded event*', '*windows event*')
        }
        
        'GalleryContent' = @{
            TemplatePatterns = @('*Gallery*', '*CommunityContent*', '*Community-Content*')
            QueryPatterns = @() # Gallery content usually doesn't have specific query patterns
            FilenamePatterns = @('*Gallery*', '*Community*')
            DisplayNamePatterns = @('*gallery*', '*community*')
        }
        
        'CustomContent' = @{
            TemplatePatterns = @('*Custom*', '*Bespoke*', '*Internal*')
            QueryPatterns = @() # Custom content varies too much
            FilenamePatterns = @('*Custom*', '*Bespoke*', '*Internal*')
            DisplayNamePatterns = @('*custom*', '*bespoke*', '*internal*')
        }
        
        # Additional mappings
        'AzureActivity' = @{
            TemplatePatterns = @('*AzureActivity*', '*Azure-Activity*')
            QueryPatterns = @('\bazureactivity\b')
            FilenamePatterns = @('*AzureActivity*', '*Azure-Activity*')
            DisplayNamePatterns = @('*azure activity*')
        }
        
        'AzureSQLDatabaseSolution' = @{
            TemplatePatterns = @('*AzureSQL*', '*Azure-SQL*', '*SQLDatabase*')
            QueryPatterns = @('\bsqlazure\b', '\bazuresqldb\b', '\bsqldatabase\b')
            FilenamePatterns = @('*AzureSQL*', '*Azure-SQL*', '*SQLDatabase*')
            DisplayNamePatterns = @('*azure sql*', '*sql database*')
        }
        
        'BusinessEmailCompromise' = @{
            TemplatePatterns = @('*BusinessEmail*', '*Business-Email*', '*EmailCompromise*', '*BEC*')
            QueryPatterns = @('\bemailpost\b', '\bemailattachment\b', '\boffice.*activity\b', '\bexchange\b')
            FilenamePatterns = @('*BusinessEmail*', '*Business-Email*', '*EmailCompromise*', '*BEC*')
            DisplayNamePatterns = @('*business email*', '*email compromise*', '*bec*')
        }
        
        'CloudIdentityThreatProtectionEssentials' = @{
            TemplatePatterns = @('*CloudIdentity*', '*Cloud-Identity*', '*CloudIdentityThreat*')
            QueryPatterns = @('\bcloudappevents\b', '\bidentitylogon\b', '\bcloudidentity\b')
            FilenamePatterns = @('*CloudIdentity*', '*Cloud-Identity*')
            DisplayNamePatterns = @('*cloud identity*', '*identity threat*')
        }
        
        'DNSEssentials' = @{
            TemplatePatterns = @('*DNSEssentials*', '*DNS-Essentials*', '*DNS*')
            QueryPatterns = @('\bdnsevent\b', '\bdnsquery\b', '\bdnslog\b')
            FilenamePatterns = @('*DNS*Essentials*', '*DNSEssentials*', '*DNS*')
            DisplayNamePatterns = @('*dns*', '*domain name*')
        }
        
        'MalwareProtectionEssentials' = @{
            TemplatePatterns = @('*MalwareProtection*', '*Malware-Protection*', '*AntiMalware*')
            QueryPatterns = @('\bmalware\b', '\bvirus\b', '\bantimalware\b', '\bmaliciousfile\b')
            FilenamePatterns = @('*MalwareProtection*', '*Malware-Protection*', '*AntiMalware*')
            DisplayNamePatterns = @('*malware*', '*virus*', '*anti-malware*')
        }
    }
    
    # Function to test patterns against a string
    function Test-Patterns {
        param(
            [string]$TestString,
            [string[]]$Patterns
        )
        
        if ([string]::IsNullOrEmpty($TestString) -or $Patterns.Count -eq 0) {
            return $false
        }
        
        foreach ($pattern in $Patterns) {
            if ($TestString -like $pattern) {
                return $true
            }
        }
        return $false
    }
    
    function Test-RegexPatterns {
        param(
            [string]$TestString,
            [string[]]$Patterns
        )
        
        if ([string]::IsNullOrEmpty($TestString) -or $Patterns.Count -eq 0) {
            return $false
        }
        
        $lowerTestString = $TestString.ToLower()
        foreach ($pattern in $Patterns) {
            if ($lowerTestString -match $pattern) {
                return $true
            }
        }
        return $false
    }
    
    # Priority order for detection (most reliable first)
    
    # 1. Template Name matching (highest priority)
    if ($Rule.alertRuleTemplateName) {
        $templateName = $Rule.alertRuleTemplateName
        foreach ($source in $sourcePatterns.Keys) {
            if (Test-Patterns -TestString $templateName -Patterns $sourcePatterns[$source].TemplatePatterns) {
                return $source
            }
        }
    }
    
    # 2. Query content analysis (very reliable for specific data sources)
    if ($Rule.query) {
        $query = $Rule.query
        foreach ($source in $sourcePatterns.Keys) {
            if (Test-RegexPatterns -TestString $query -Patterns $sourcePatterns[$source].QueryPatterns) {
                return $source
            }
        }
    }
    
    # 3. Filename-based detection
    $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    foreach ($source in $sourcePatterns.Keys) {
        if (Test-Patterns -TestString $baseFileName -Patterns $sourcePatterns[$source].FilenamePatterns) {
            return $source
        }
    }
    
    # 4. Display name matching (lowest priority due to potential ambiguity)
    if ($Rule.displayName) {
        $displayName = $Rule.displayName.ToLower()
        foreach ($source in $sourcePatterns.Keys) {
            if (Test-Patterns -TestString $displayName -Patterns $sourcePatterns[$source].DisplayNamePatterns) {
                return $source
            }
        }
    }
    
    # 5. Enhanced fallback detection based on common rule characteristics
    if ($Rule.query) {
        $query = $Rule.query.ToLower()
        
        # Additional fallback patterns for common but hard-to-detect sources
        if ($query -match '\bsecurityevent\b' -and $query -match '\bwindows\b') {
            return 'WindowsForwardedEvents'
        }
        elseif ($query -match '\boffice.*365\b|\bo365\b|\bexchange.*online\b') {
            return 'BusinessEmailCompromise'
        }
        elseif ($query -match '\bcloud.*app\b|\bsaas\b|\bcloud.*service\b') {
            return 'CloudIdentityThreatProtectionEssentials'
        }
        elseif ($query -match '\bthreat\b' -and $query -match '\bintel\b|\bindicator\b|\bioc\b') {
            return 'ThreatIntelligence'
        }
        elseif ($query -match '\bendpoint\b' -and $query -match '\bsecur\b|\bprotect\b|\bthreat\b') {
            return 'EndpointThreatProtectionEssentials'
        }
    }
    
    # Final fallback - return Unknown with more context
    Write-Warning "Could not determine source for rule: $($Rule.displayName) from file: $FileName"
    if ($Rule.alertRuleTemplateName) {
        Write-Warning "  Template: $($Rule.alertRuleTemplateName)"
    }
    
    return "Unknown-Source"
}

# Function to compare two rule objects for changes
function Compare-Rules {
    param(
        [PSCustomObject]$ExistingRule,
        [PSCustomObject]$NewRule
    )
    
    $changes = @()
    
    # Properties to compare (excluding metadata fields)
    $propertiesToCompare = @(
        'DisplayName', 'Description', 'Severity', 'Enabled', 'Query', 
        'QueryFrequency', 'QueryPeriod', 'TriggerOperator', 'TriggerThreshold',
        'SuppressionDuration', 'SuppressionEnabled', 'Tactics', 'Techniques'
    )
    
    foreach ($property in $propertiesToCompare) {
        $existingValue = $ExistingRule.$property
        $newValue = $NewRule.$property
        
        # Handle array comparisons
        if ($existingValue -is [Array] -and $newValue -is [Array]) {
            $existingStr = ($existingValue | Sort-Object) -join ','
            $newStr = ($newValue | Sort-Object) -join ','
            if ($existingStr -ne $newStr) {
                $changes += "$property changed from [$existingStr] to [$newStr]"
            }
        }
        elseif ($existingValue -ne $newValue) {
            $changes += "$property changed from '$existingValue' to '$newValue'"
        }
    }
    
    return $changes
}

# Function to add or update version history
function Update-VersionHistory {
    param(
        [PSCustomObject]$Rule,
        [string[]]$Changes = @(),
        [bool]$IsNew = $false
    )
    
    $currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if (-not $Rule.PSObject.Properties['VersionHistory']) {
        $Rule | Add-Member -MemberType NoteProperty -Name 'VersionHistory' -Value @()
    }
    
    $versionEntry = [PSCustomObject]@{
        Date = $currentDate
        Version = if ($Rule.VersionHistory.Count -eq 0) { "1.0" } else { 
            $lastVersion = [double]($Rule.VersionHistory[-1].Version)
            ($lastVersion + 0.1).ToString("F1")
        }
        Action = if ($IsNew) { "Created" } else { "Updated" }
        Changes = $Changes
        UpdatedBy = $env:USERNAME
    }
    
    $Rule.VersionHistory += $versionEntry
    $Rule | Add-Member -MemberType NoteProperty -Name 'LastUpdated' -Value $currentDate -Force
    $Rule | Add-Member -MemberType NoteProperty -Name 'CurrentVersion' -Value $versionEntry.Version -Force
}

# Function to process a single JSON file
function Process-JsonFile {
    param(
        [string]$FilePath,
        [string]$BaseOutputDirectory,
        [hashtable]$GlobalTracking,
        [hashtable]$GlobalStats
    )
    
    Write-Host "Processing file: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Cyan
    
    try {
        # Read the ARM template JSON
        $armTemplate = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
        
        # Process each rule in the resources array
        foreach ($resource in $armTemplate.resources) {
            if ($resource.type -eq "Microsoft.OperationalInsights/workspaces/providers/alertRules") {
                $rule = $resource.properties
                
                # Extract rule ID from resource name
                $ruleId = ($resource.name -split '/')[-1]
                
                # Create rule object with cleaned structure
                $cleanRule = [PSCustomObject]@{
                    RuleId = $ruleId
                    DisplayName = $rule.displayName
                    Description = $rule.description
                    Severity = $rule.severity
                    Enabled = $rule.enabled
                    Query = $rule.query
                    QueryFrequency = $rule.queryFrequency
                    QueryPeriod = $rule.queryPeriod
                    TriggerOperator = $rule.triggerOperator
                    TriggerThreshold = $rule.triggerThreshold
                    SuppressionDuration = $rule.suppressionDuration
                    SuppressionEnabled = $rule.suppressionEnabled
                    Tactics = $rule.tactics
                    Techniques = $rule.techniques
                    SubTechniques = $rule.subTechniques
                    AlertRuleTemplateName = $rule.alertRuleTemplateName
                    TemplateVersion = $rule.templateVersion
                    EntityMappings = $rule.entityMappings
                    CustomDetails = $rule.customDetails
                    IncidentConfiguration = $rule.incidentConfiguration
                    EventGroupingSettings = $rule.eventGroupingSettings
                    Kind = $resource.kind
                    ApiVersion = $resource.apiVersion
                    SourceFile = [System.IO.Path]::GetFileName($FilePath)
                }
                
                # Determine source and severity
                $sourceName = Get-SourceName -Rule $cleanRule -FileName ([System.IO.Path]::GetFileName($FilePath))
                $severity = if ($rule.severity) { $rule.severity } else { "Unknown" }
                
                # Create directory structure based on IncludeTenantInPath switch
                if ($IncludeTenantInPath -and $TenantName) {
                    $folderName = "$TenantName/$severity-$sourceName"
                } else {
                    $folderName = "$severity-$sourceName"
                }
                
                $targetDir = Join-Path $BaseOutputDirectory $folderName
                New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                
                # Create safe filename
                $safeName = $rule.displayName -replace '[\\/*?:"<>|]', '_' -replace '\s+', '_'
                $ruleFileName = "$safeName.json"
                $ruleFilePath = Join-Path $targetDir $ruleFileName
                
                # Check if rule file already exists
                $isNewRule = $false
                $changes = @()
                
                if (Test-Path $ruleFilePath) {
                    # Load existing rule
                    $existingRule = Get-Content -Path $ruleFilePath -Raw | ConvertFrom-Json
                    
                    # Compare rules for changes
                    $changes = Compare-Rules -ExistingRule $existingRule -NewRule $cleanRule
                    
                    if ($changes.Count -gt 0) {
                        # Rule has changes - preserve existing version history
                        if ($existingRule.PSObject.Properties['VersionHistory']) {
                            $cleanRule | Add-Member -MemberType NoteProperty -Name 'VersionHistory' -Value $existingRule.VersionHistory
                        }
                        Update-VersionHistory -Rule $cleanRule -Changes $changes -IsNew $false
                        $GlobalStats['Updated']++
                        Write-Host "  Updated rule: $($rule.displayName)" -ForegroundColor Yellow
                    }
                    else {
                        # No changes - preserve existing metadata
                        if ($existingRule.PSObject.Properties['VersionHistory']) {
                            $cleanRule | Add-Member -MemberType NoteProperty -Name 'VersionHistory' -Value $existingRule.VersionHistory
                        }
                        if ($existingRule.PSObject.Properties['LastUpdated']) {
                            $cleanRule | Add-Member -MemberType NoteProperty -Name 'LastUpdated' -Value $existingRule.LastUpdated
                        }
                        if ($existingRule.PSObject.Properties['CurrentVersion']) {
                            $cleanRule | Add-Member -MemberType NoteProperty -Name 'CurrentVersion' -Value $existingRule.CurrentVersion
                        }
                        $GlobalStats['Unchanged']++
                        Write-Host "  No changes: $($rule.displayName)" -ForegroundColor Green
                    }
                }
                else {
                    # New rule
                    $isNewRule = $true
                    Update-VersionHistory -Rule $cleanRule -IsNew $true
                    $GlobalStats['New']++
                    Write-Host "  Created new rule: $($rule.displayName)" -ForegroundColor White
                }
                
                # Update global tracking
                $GlobalTracking[$ruleId] = @{
                    DisplayName = $rule.displayName
                    FileName = $ruleFileName
                    Directory = $folderName
                    Severity = $severity
                    Source = $sourceName
                    LastSeen = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Status = if ($isNewRule) { "New" } elseif ($changes.Count -gt 0) { "Updated" } else { "Unchanged" }
                    SourceFile = [System.IO.Path]::GetFileName($FilePath)
                }
                
                # Add tenant info to rule file
                if ($TenantName) {
                    $cleanRule | Add-Member -MemberType NoteProperty -Name 'OriginTenant' -Value $TenantName -Force
                }

                # Save rule file
                $cleanRule | ConvertTo-Json -Depth 10 | Out-File -FilePath $ruleFilePath -Encoding UTF8
                
                $GlobalStats['Total']++
            }
        }
    }
    catch {
        Write-Error "Error processing file $FilePath`: $($_.Exception.Message)"
    }
}

# Function to initialize or load tenant tracking
function Initialize-TenantTracking {
    param(
        [string]$OutputDirectory,
        [string]$TenantName
    )
    
    if (-not $TenantName) {
        return $null
    }
    
    $tenantTrackingFile = Join-Path $OutputDirectory "tenant_tracking_$($TenantName.ToLower()).json"
    
    # Only create tenant tracking file if it doesn't exist
    if (-not (Test-Path $tenantTrackingFile)) {
        $tenantInfo = [PSCustomObject]@{
            TenantName = $TenantName
            FirstProcessed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ProcessingHistory = @()
            TotalProcessingRuns = 0
        }
        
        $tenantInfo | ConvertTo-Json -Depth 5 | Out-File -FilePath $tenantTrackingFile -Encoding UTF8
        Write-Host "Created new tenant tracking file: tenant_tracking_$($TenantName.ToLower()).json" -ForegroundColor Cyan
        
        return @{
            FilePath = $tenantTrackingFile
            Data = $tenantInfo
            IsNew = $true
        }
    }
    else {
        # Load existing tenant tracking
        $existingData = Get-Content -Path $tenantTrackingFile -Raw | ConvertFrom-Json
        Write-Host "Loaded existing tenant tracking for: $TenantName" -ForegroundColor Green
        
        return @{
            FilePath = $tenantTrackingFile
            Data = $existingData
            IsNew = $false
        }
    }
}

# Function to update tenant tracking
function Update-TenantTracking {
    param(
        [hashtable]$TenantTracking,
        [hashtable]$ProcessingStats,
        [string[]]$FilesProcessed
    )
    
    if (-not $TenantTracking) {
        return
    }
    
    # Collect details for each rule this tenant changed
    $ruleChanges = @()
    
    foreach ($ruleId in $GlobalTracking.Keys) {
        $ruleInfo = $GlobalTracking[$ruleId]
        if ($ruleInfo.SourceFile -in ($FilesProcessed | ForEach-Object { [System.IO.Path]::GetFileName($_) })) {
            if ($ruleInfo.Status -ne "Unchanged") {
                $ruleChanges += [PSCustomObject]@{
                    DisplayName = $ruleInfo.DisplayName
                    Status      = $ruleInfo.Status
                    Severity    = $ruleInfo.Severity
                    Source      = $ruleInfo.Source
                    Directory   = $ruleInfo.Directory
                    FileName    = $ruleInfo.FileName
                    RulePath    = Join-Path $ruleInfo.Directory $ruleInfo.FileName
                }
            }
        }
    }
    
    # Build the current run object
    $currentRun = [PSCustomObject]@{
        ProcessingDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        FilesProcessed     = $FilesProcessed.Count
        FileList           = $FilesProcessed | ForEach-Object { [System.IO.Path]::GetFileName($_) }
        RulesProcessed     = $ProcessingStats.Total
        NewRules           = $ProcessingStats.New
        UpdatedRules       = $ProcessingStats.Updated
        UnchangedRules     = $ProcessingStats.Unchanged
        ProcessedBy        = $env:USERNAME
        ChangedRules       = $ruleChanges
    }

    $TenantTracking.Data.ProcessingHistory += $currentRun
    $TenantTracking.Data.TotalProcessingRuns++
    $TenantTracking.Data | Add-Member -MemberType NoteProperty -Name 'LastProcessed' -Value $currentRun.ProcessingDate -Force
    
    # Save updated tenant tracking
    $TenantTracking.Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $TenantTracking.FilePath -Encoding UTF8
    
    Write-Host "Updated tenant tracking - Run #$($TenantTracking.Data.TotalProcessingRuns)" -ForegroundColor Yellow
}

# Main execution logic
$globalTracking = @{}
$globalStats = @{
    Total = 0
    New = 0
    Updated = 0
    Unchanged = 0
}

# Initialize tenant tracking if tenant name is provided
$tenantTracking = Initialize-TenantTracking -OutputDirectory $OutputDirectory -TenantName $TenantName

# Determine input files to process
$filesToProcess = @()

if ($PSCmdlet.ParameterSetName -eq 'SingleFile') {
    $filesToProcess = @($InputJsonPath)
}
elseif ($PSCmdlet.ParameterSetName -eq 'BatchFiles') {
    $filesToProcess = $InputJsonPaths
}
elseif ($PSCmdlet.ParameterSetName -eq 'Directory') {
    $filesToProcess = Get-ChildItem -Path $InputDirectory -Filter $FileExtension -Recurse | ForEach-Object { $_.FullName }
}

# Create base output directory
New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null

Write-Host "=== Starting Batch Processing ===" -ForegroundColor Magenta
Write-Host "Files to process: $($filesToProcess.Count)" -ForegroundColor White
Write-Host "Output directory: $OutputDirectory" -ForegroundColor White
if ($IncludeTenantInPath -and $TenantName) {
    Write-Host "Tenant: $TenantName" -ForegroundColor White
}
Write-Host ""

# Process each file
foreach ($file in $filesToProcess) {
    if (Test-Path $file) {
        Process-JsonFile -FilePath $file -BaseOutputDirectory $OutputDirectory -GlobalTracking $globalTracking -GlobalStats $globalStats
    }
    else {
        Write-Warning "File not found: $file"
    }
}

# Save global tracking file
$trackingFile = Join-Path $OutputDirectory "global_rule_tracking.json"
$globalTracking | ConvertTo-Json -Depth 5 | Out-File -FilePath $trackingFile -Encoding UTF8

# Update tenant tracking if applicable
if ($tenantTracking) {
    Update-TenantTracking -TenantTracking $tenantTracking -ProcessingStats $globalStats -FilesProcessed $filesToProcess
}

# Create global summary
$summary = [PSCustomObject]@{
    TenantName = $TenantName
    ProcessingDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalRules = $globalStats.Total
    NewRules = $globalStats.New
    UpdatedRules = $globalStats.Updated
    UnchangedRules = $globalStats.Unchanged
    FilesProcessed = $filesToProcess.Count
    OutputStructure = if ($IncludeTenantInPath -and $TenantName) { "Tenant\Severity-Source\Rules" } else { "Severity-Source\Rules" }
    TenantTrackingFile = if ($tenantTracking) { [System.IO.Path]::GetFileName($tenantTracking.FilePath) } else { "None" }
    IsNewTenantTracking = if ($tenantTracking) { $tenantTracking.IsNew } else { $false }
}

# Save global summary
$summaryPath = Join-Path $OutputDirectory "global_summary.json"
$summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $summaryPath -Encoding UTF8

# Display final summary
Write-Host "`n=== Processing Complete ===" -ForegroundColor Magenta
Write-Host "Total Rules Processed: $($globalStats.Total)" -ForegroundColor White
Write-Host "New Rules: $($globalStats.New)" -ForegroundColor Cyan
Write-Host "Updated Rules: $($globalStats.Updated)" -ForegroundColor Yellow
Write-Host "Unchanged Rules: $($globalStats.Unchanged)" -ForegroundColor Green
Write-Host "Files Processed: $($filesToProcess.Count)" -ForegroundColor White
Write-Host "Output Directory: $OutputDirectory" -ForegroundColor Gray

# Display tenant tracking info
if ($tenantTracking) {
    if ($tenantTracking.IsNew) {
        Write-Host "Tenant Tracking: NEW - Created tracking file for '$TenantName'" -ForegroundColor Cyan
    } else {
        Write-Host "Tenant Tracking: UPDATED - Run #$($tenantTracking.Data.TotalProcessingRuns) for '$TenantName'" -ForegroundColor Yellow
    }
    Write-Host "Tenant File: $([System.IO.Path]::GetFileName($tenantTracking.FilePath))" -ForegroundColor Gray
}

# Return summary for further processing
return $summary