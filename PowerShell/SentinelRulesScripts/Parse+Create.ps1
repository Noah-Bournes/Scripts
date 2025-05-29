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

# Enhanced Function to extract source name from rule properties with comprehensive filtering
function Get-SourceName {
    param(
        [PSCustomObject]$Rule,
        [string]$FileName
    )
    
    # First check the rule kind - this is the most reliable indicator
    if ($Rule.kind) {
        switch ($Rule.kind.ToLower()) {
            'fusion' { return 'FusionML' }
            'microsoftsecurityincidentcreation' { return 'MicrosoftSecurityIncidentCreation' }
            'mlbehavioranalytics' { return 'MLBehaviorAnalytics' }
            'threatintelligence' { return 'Threat Intelligence' }
            'nrt' { return 'NearRealTime' }
            'scheduled' { 
                # For scheduled rules, continue with more detailed analysis
                # Don't return here, let it fall through to pattern matching
            }
        }
    }
    
    # Enhanced source mapping with comprehensive coverage of all requested sources
    $sourcePatterns = @{
        'Threat Intelligence' = @{
            TemplatePatterns = @('*ThreatIntel*', '*Threat-Intel*', '*ThreatIntelligence*', '*IOC*', '*Indicator*', '*Threat*Intelligence*')
            QueryPatterns = @('\bthreatintelligenceindicator\b', '\bioc\b', '\bindicator\b', '\bmaliciousip\b', '\bthreatintel\b', '\bthreat.*intelligence\b')
            FilenamePatterns = @('*ThreatIntel*', '*Threat-Intel*', '*IOC*', '*Indicator*', '*Threat*Intelligence*')
            DisplayNamePatterns = @('*threat.*intel*', '*ioc*', '*indicator*', '*malicious*', '*threat.*intelligence*')
            SourceSubTypePatterns = @('Threat Intelligence')
        }
        
        'Microsoft Defender XDR' = @{
            TemplatePatterns = @('*Defender*XDR*', '*MDXDR*', '*M365D*', '*Microsoft365Defender*', '*DefenderXDR*', '*Microsoft*Defender*XDR*')
            QueryPatterns = @('\bdeviceprocessevents\b', '\bdevicenetworkevents\b', '\bdevicefileevents\b', '\bdevicelogonevents\b', '\bdeviceregistryevents\b', '\bdeviceimageloadevents\b', '\bdeviceevents\b', '\bdeviceinfo\b', '\bdevicetvconfigurationassessment\b')
            FilenamePatterns = @('*DefenderXDR*', '*Defender-XDR*', '*MDXDR*', '*M365Defender*', '*MicrosoftDefenderXDR*', '*Microsoft*Defender*XDR*')
            DisplayNamePatterns = @('*defender.*xdr*', '*microsoft.*365.*defender*', '*m365.*defender*', '*mdxdr*', '*microsoft.*defender.*xdr*')
            SourceSubTypePatterns = @('Microsoft 365 Defender', 'Microsoft Defender XDR')
        }
        
        'Microsoft Entra ID' = @{
            TemplatePatterns = @('*EntraID*', '*Entra-ID*', '*EntraIdentity*', '*AzureAD*', '*Azure-AD*', '*AAD*', '*Microsoft*Entra*ID*', '*Entra*')
            QueryPatterns = @('\bsigninlogs\b', '\bauditlogs\b', '\baadnoninteractiveuserassignlogs\b', '\baadserviceprincipallogins\b', '\bentraidlogs\b', '\bidentityinfo\b', '\bentra\b')
            FilenamePatterns = @('*EntraID*', '*Entra-ID*', '*AzureAD*', '*Azure-AD*', '*AAD*', '*Microsoft*Entra*ID*', '*Entra*')
            DisplayNamePatterns = @('*entra.*id*', '*azure.*ad*', '*aad*', '*azure.*active.*directory*', '*entra*')
            SourceSubTypePatterns = @('Microsoft Entra ID Protection', 'Azure Active Directory Identity Protection', 'Microsoft Entra ID')
        }
        
        'Network Session Essentials' = @{
            TemplatePatterns = @('*Network*Session*Essentials*', '*NetworkSession*', '*Network*Session*', '*Session*Essentials*')
            QueryPatterns = @('\bnetworksession\b', '\bnetwork.*session\b', '\bsession.*network\b')
            FilenamePatterns = @('*Network*Session*Essentials*', '*NetworkSession*', '*Network*Session*')
            DisplayNamePatterns = @('*network.*session.*essentials*', '*network.*session*', '*session.*essentials*')
            SourceSubTypePatterns = @('Network Session Essentials')
        }
        
        'Microsoft 365' = @{
            TemplatePatterns = @('*Microsoft365*', '*Microsoft*365*', '*M365*', '*Office365*', '*O365*')
            QueryPatterns = @('\bofficeactivity\b', '\bo365\b', '\boffice.*365\b', '\bexchangeonline\b', '\bsharepoint\b', '\bteams\b', '\bmicrosoft.*365\b')
            FilenamePatterns = @('*Microsoft365*', '*Microsoft*365*', '*M365*', '*Office365*', '*O365*')
            DisplayNamePatterns = @('*microsoft.*365*', '*office.*365*', '*m365*', '*o365*')
            SourceSubTypePatterns = @('Microsoft 365', 'Office 365')
        }
        
        'Attacker Tools Threat Protection Essentials' = @{
            TemplatePatterns = @('*Attacker*Tools*Threat*Protection*Essentials*', '*Attacker*Tools*', '*Threat*Protection*Essentials*')
            QueryPatterns = @('\battacker.*tools\b', '\bthreat.*protection\b', '\battacker\b.*\btools\b')
            FilenamePatterns = @('*Attacker*Tools*Threat*Protection*Essentials*', '*Attacker*Tools*', '*Threat*Protection*Essentials*')
            DisplayNamePatterns = @('*attacker.*tools.*threat.*protection.*essentials*', '*attacker.*tools*', '*threat.*protection.*essentials*')
            SourceSubTypePatterns = @('Attacker Tools Threat Protection Essentials')
        }
        
        'Azure Activity' = @{
            TemplatePatterns = @('*AzureActivity*', '*Azure-Activity*', '*Azure*Activity*')
            QueryPatterns = @('\bazureactivity\b', '\bazure.*resource\b', '\bresource.*manager\b', '\bazure.*activity\b')
            FilenamePatterns = @('*AzureActivity*', '*Azure-Activity*', '*Azure*Activity*')
            DisplayNamePatterns = @('*azure.*activity*', '*resource.*manager*')
            SourceSubTypePatterns = @('Azure Activity')
        }
        
        'Endpoint Threat Protection Essentials' = @{
            TemplatePatterns = @('*Endpoint*Threat*Protection*Essentials*', '*Endpoint*Threat*Protection*', '*Endpoint*Protection*')
            QueryPatterns = @('\bendpoint.*threat\b', '\bendpoint.*protection\b', '\bthreat.*protection.*endpoint\b')
            FilenamePatterns = @('*Endpoint*Threat*Protection*Essentials*', '*Endpoint*Threat*Protection*', '*Endpoint*Protection*')
            DisplayNamePatterns = @('*endpoint.*threat.*protection.*essentials*', '*endpoint.*threat.*protection*', '*endpoint.*protection*')
            SourceSubTypePatterns = @('Endpoint Threat Protection Essentials')
        }
        
        'Cloud Identity Threat Protection Essentials' = @{
            TemplatePatterns = @('*Cloud*Identity*Threat*Protection*Essentials*', '*Cloud*Identity*Protection*', '*Identity*Threat*Protection*')
            QueryPatterns = @('\bcloud.*identity\b', '\bidentity.*threat\b', '\bcloud.*protection\b')
            FilenamePatterns = @('*Cloud*Identity*Threat*Protection*Essentials*', '*Cloud*Identity*Protection*', '*Identity*Threat*Protection*')
            DisplayNamePatterns = @('*cloud.*identity.*threat.*protection.*essentials*', '*cloud.*identity.*protection*', '*identity.*threat.*protection*')
            SourceSubTypePatterns = @('Cloud Identity Threat Protection Essentials')
        }
        
        'DNS Essentials' = @{
            TemplatePatterns = @('*DNS*Essentials*', '*DNS*', '*DomainName*Essentials*')
            QueryPatterns = @('\bdnsevent\b', '\bdnsquery\b', '\bdnslog\b', '\bdomain.*name\b', '\bdns\b')
            FilenamePatterns = @('*DNS*Essentials*', '*DNS*', '*DomainName*Essentials*')
            DisplayNamePatterns = @('*dns.*essentials*', '*dns*', '*domain.*name*')
            SourceSubTypePatterns = @('DNS Essentials')
        }
        
        '1Password' = @{
            TemplatePatterns = @('*1Password*', '*OnePassword*', '*1Pass*')
            QueryPatterns = @('\b1password\b', '\bone.*password\b', '\b1pass\b')
            FilenamePatterns = @('*1Password*', '*OnePassword*', '*1Pass*')
            DisplayNamePatterns = @('*1password*', '*one.*password*', '*1pass*')
            SourceSubTypePatterns = @('1Password')
        }
        
        'Network Threat Protection Essentials' = @{
            TemplatePatterns = @('*Network*Threat*Protection*Essentials*', '*Network*Threat*Protection*', '*Network*Protection*')
            QueryPatterns = @('\bnetwork.*threat\b', '\bnetwork.*protection\b', '\bthreat.*protection.*network\b')
            FilenamePatterns = @('*Network*Threat*Protection*Essentials*', '*Network*Threat*Protection*', '*Network*Protection*')
            DisplayNamePatterns = @('*network.*threat.*protection.*essentials*', '*network.*threat.*protection*', '*network.*protection*')
            SourceSubTypePatterns = @('Network Threat Protection Essentials')
        }
        
        'MicrosoftDefenderForEndpoint' = @{
            TemplatePatterns = @('*DefenderForEndpoint*', '*Defender4Endpoint*', '*MDE*', '*MDATP*', '*DefenderATP*', '*Microsoft*Defender*Endpoint*')
            QueryPatterns = @('\bdevicenetworkinfo\b', '\bdevicetvcconfigurationassessment\b', '\bdevicesecurityconfigassessment\b', '\bdevicevulnerabilityassessment\b', '\bdefenderiocindicator\b')
            FilenamePatterns = @('*DefenderForEndpoint*', '*Defender4Endpoint*', '*MDE*', '*MDATP*', '*DefenderATP*', '*Microsoft*Defender*Endpoint*')
            DisplayNamePatterns = @('*defender.*endpoint*', '*defender.*atp*', '*mdatp*', '*mde*', '*microsoft.*defender.*endpoint*')
            SourceSubTypePatterns = @('Microsoft Defender for Endpoint', 'MicrosoftDefenderForEndpoint')
        }
        
        'Azure Active Directory' = @{
            TemplatePatterns = @('*AzureActiveDirectory*', '*Azure*Active*Directory*', '*AAD*', '*AzureAD*')
            QueryPatterns = @('\bazureactivedirectory\b', '\bazure.*active.*directory\b', '\baad\b', '\bazuread\b')
            FilenamePatterns = @('*AzureActiveDirectory*', '*Azure*Active*Directory*', '*AAD*', '*AzureAD*')
            DisplayNamePatterns = @('*azure.*active.*directory*', '*aad*', '*azure.*ad*')
            SourceSubTypePatterns = @('Azure Active Directory', 'Azure Active Directory Identity Protection')
        }
        
        'Gallery Content' = @{
            TemplatePatterns = @('*Gallery*Content*', '*Gallery*', '*Community*Content*', '*Community*')
            QueryPatterns = @('\bgallery\b', '\bcommunity\b', '\btemplate\b.*\bgallery\b')
            FilenamePatterns = @('*Gallery*Content*', '*Gallery*', '*Community*Content*', '*Community*')
            DisplayNamePatterns = @('*gallery.*content*', '*gallery*', '*community.*content*', '*community*')
            SourceSubTypePatterns = @('Gallery Content', 'Community Content')
        }
        
        # Additional common sources for completeness
        'MicrosoftDefenderForIdentity' = @{
            TemplatePatterns = @('*DefenderForIdentity*', '*Defender4Identity*', '*MDI*', '*DefenderIdentity*')
            QueryPatterns = @('\bidentitylogonevents\b', '\bidentityqueryevents\b', '\bidentitydirectoryevents\b')
            FilenamePatterns = @('*DefenderForIdentity*', '*Defender4Identity*', '*MDI*', '*DefenderIdentity*')
            DisplayNamePatterns = @('*defender.*identity*', '*mdi*')
            SourceSubTypePatterns = @('Microsoft Defender for Identity')
        }
        
        'MicrosoftDefenderForOffice365' = @{
            TemplatePatterns = @('*DefenderForOffice*', '*Defender4Office*', '*MDO*', '*DefenderO365*')
            QueryPatterns = @('\bemailevents\b', '\bemailattachmentinfo\b', '\bemailpostdeliveryevents\b', '\bemailurlinfo\b')
            FilenamePatterns = @('*DefenderForOffice*', '*Defender4Office*', '*MDO*', '*DefenderO365*')
            DisplayNamePatterns = @('*defender.*office*', '*mdo*')
            SourceSubTypePatterns = @('Microsoft Defender for Office 365')
        }
        
        'MicrosoftDefenderForCloud' = @{
            TemplatePatterns = @('*DefenderForCloud*', '*Defender4Cloud*', '*MDC*', '*AzureDefender*', '*ASC*')
            QueryPatterns = @('\bsecurityalert\b.*\basctype\b', '\bsecurityrecommendation\b')
            FilenamePatterns = @('*DefenderForCloud*', '*Defender4Cloud*', '*MDC*', '*AzureDefender*', '*ASC*')
            DisplayNamePatterns = @('*defender.*cloud*', '*azure.*defender*', '*mdc*', '*asc*')
            SourceSubTypePatterns = @('Microsoft Defender for Cloud', 'Azure Defender')
        }
    }
    
    # Function to test patterns against a string (case-insensitive)
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
    
    # Check sourceSettings for Fusion rules (highest priority for Fusion)
    if ($Rule.sourceSettings -and $Rule.kind -eq "Fusion") {
        $enabledSources = @()
        
        foreach ($sourceSetting in $Rule.sourceSettings) {
            if ($sourceSetting.enabled -and $sourceSetting.sourceSubTypes) {
                foreach ($subType in $sourceSetting.sourceSubTypes) {
                    if ($subType.enabled) {
                        $enabledSources += $subType.sourceSubTypeName
                        if ($subType.sourceSubTypeDisplayName) {
                            $enabledSources += $subType.sourceSubTypeDisplayName
                        }
                    }
                }
            }
        }
        
        # Find the best match based on enabled sources
        $sourceMatches = @{}
        foreach ($source in $sourcePatterns.Keys) {
            $matchCount = 0
            foreach ($enabledSource in $enabledSources) {
                if (Test-Patterns -TestString $enabledSource -Patterns $sourcePatterns[$source].SourceSubTypePatterns) {
                    $matchCount++
                }
            }
            if ($matchCount -gt 0) {
                $sourceMatches[$source] = $matchCount
            }
        }
        
        # Return the source with the most matches, or default to FusionML
        if ($sourceMatches.Count -gt 0) {
            $bestMatch = ($sourceMatches.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
            return $bestMatch
        } else {
            return 'FusionML'
        }
    }
    
    # Priority order for detection (most reliable first)
    
    # 1. Template Name matching (highest priority for non-Fusion rules)
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
    
    # 4. Display name matching
    if ($Rule.displayName) {
        $displayName = $Rule.displayName.ToLower()
        foreach ($source in $sourcePatterns.Keys) {
            if (Test-Patterns -TestString $displayName -Patterns $sourcePatterns[$source].DisplayNamePatterns) {
                return $source
            }
        }
    }
    
    # Final fallback based on rule kind
    if ($Rule.kind -eq "Fusion") {
        return 'FusionML'
    } elseif ($Rule.kind -eq "ThreatIntelligence") {
        return 'Threat Intelligence'
    } elseif ($Rule.kind -eq "MicrosoftSecurityIncidentCreation") {
        return 'MicrosoftSecurityIncidentCreation'
    } elseif ($Rule.kind -eq "MLBehaviorAnalytics") {
        return 'MLBehaviorAnalytics'
    }
    
    # Final fallback with warning
    Write-Warning "Could not determine source for rule: $($Rule.displayName) from file: $FileName"
    if ($Rule.alertRuleTemplateName) {
        Write-Warning "  Template: $($Rule.alertRuleTemplateName)"
    }
    if ($Rule.kind) {
        Write-Warning "  Kind: $($Rule.kind)"
    }
    
    return "Unknown-Source"
}

# Function to extract severity from rule properties or filename
function Get-Severity {
    param(
        [PSCustomObject]$Rule,
        [string]$FileName
    )
    
    # Priority order for severity detection
    
    # 1. Check rule properties first (most reliable)
    if ($Rule.severity) {
        return $Rule.severity
    }
    
    # 2. Check filename for severity prefix
    $baseFileName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $lowerFileName = $baseFileName.ToLower()
    
    if ($lowerFileName -match '^(high|medium|low|informational)-') {
        switch ($matches[1]) {
            'high' { return 'High' }
            'medium' { return 'Medium' }
            'low' { return 'Low' }
            'informational' { return 'Informational' }
        }
    }
    
    # 3. Check for severity keywords in display name
    if ($Rule.displayName) {
        $displayName = $Rule.displayName.ToLower()
        if ($displayName -match '\b(high|critical)\b') {
            return 'High'
        } elseif ($displayName -match '\bmedium\b') {
            return 'Medium'
        } elseif ($displayName -match '\blow\b') {
            return 'Low'
        } elseif ($displayName -match '\b(info|informational)\b') {
            return 'Informational'
        }
    }
    
    # Default fallback
    return 'Unknown-Severity'
}

# Function to filter rules by severity and source
function Filter-RulesBySourceAndSeverity {
    param(
        [PSCustomObject[]]$Rules,
        [string[]]$AllowedSources = @(),
        [string[]]$AllowedSeverities = @(),
        [string[]]$ExcludedSources = @(),
        [string[]]$ExcludedSeverities = @()
    )
    
    $filteredRules = @()
    
    foreach ($rule in $Rules) {
        $include = $true
        
        # Get source and severity for this rule
        $source = Get-SourceName -Rule $rule.Rule -FileName $rule.FileName
        $severity = Get-Severity -Rule $rule.Rule -FileName $rule.FileName
        
        # Apply source filters
        if ($AllowedSources.Count -gt 0) {
            if ($source -notin $AllowedSources) {
                $include = $false
            }
        }
        
        if ($ExcludedSources.Count -gt 0) {
            if ($source -in $ExcludedSources) {
                $include = $false
            }
        }
        
        # Apply severity filters
        if ($AllowedSeverities.Count -gt 0) {
            if ($severity -notin $AllowedSeverities) {
                $include = $false
            }
        }
        
        if ($ExcludedSeverities.Count -gt 0) {
            if ($severity -in $ExcludedSeverities) {
                $include = $false
            }
        }
        
        if ($include) {
            # Add source and severity properties to the rule object
            $rule | Add-Member -MemberType NoteProperty -Name 'DetectedSource' -Value $source -Force
            $rule | Add-Member -MemberType NoteProperty -Name 'DetectedSeverity' -Value $severity -Force
            $filteredRules += $rule
        }
    }
    
    return $filteredRules
}

# Function to get summary statistics of rules by source and severity
function Get-RuleSummary {
    param(
        [PSCustomObject[]]$Rules
    )
    
    $summary = @{
        TotalRules = $Rules.Count
        BySeverity = @{}
        BySource = @{}
        BySourceAndSeverity = @{}
    }
    
    foreach ($rule in $Rules) {
        $source = Get-SourceName -Rule $rule.Rule -FileName $rule.FileName
        $severity = Get-Severity -Rule $rule.Rule -FileName $rule.FileName
        
        # Count by severity
        if (-not $summary.BySeverity.ContainsKey($severity)) {
            $summary.BySeverity[$severity] = 0
        }
        $summary.BySeverity[$severity]++
        
        # Count by source
        if (-not $summary.BySource.ContainsKey($source)) {
            $summary.BySource[$source] = 0
        }
        $summary.BySource[$source]++
        
        # Count by source and severity combination
        $combination = "$source - $severity"
        if (-not $summary.BySourceAndSeverity.ContainsKey($combination)) {
            $summary.BySourceAndSeverity[$combination] = 0
        }
        $summary.BySourceAndSeverity[$combination]++
    }
    
    return $summary
}

# Example usage functions
function Show-FilteringExamples {
    Write-Host "=== Rule Filtering Examples ===" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "1. Filter by specific sources:" -ForegroundColor Yellow
    Write-Host '   $filteredRules = Filter-RulesBySourceAndSeverity -Rules $allRules -AllowedSources @("Threat Intelligence", "Microsoft Defender XDR")'
    Write-Host ""
    
    Write-Host "2. Filter by severity:" -ForegroundColor Yellow
    Write-Host '   $highRules = Filter-RulesBySourceAndSeverity -Rules $allRules -AllowedSeverities @("High", "Critical")'
    Write-Host ""
    
    Write-Host "3. Exclude specific sources:" -ForegroundColor Yellow
    Write-Host '   $filteredRules = Filter-RulesBySourceAndSeverity -Rules $allRules -ExcludedSources @("Gallery Content")'
    Write-Host ""
    
    Write-Host "4. Complex filtering:" -ForegroundColor Yellow
    Write-Host '   $specificRules = Filter-RulesBySourceAndSeverity -Rules $allRules -AllowedSources @("Microsoft Entra ID", "Azure Activity") -AllowedSeverities @("High", "Medium") -ExcludedSources @("Gallery Content")'
    Write-Host ""
    
    Write-Host "5. Get summary statistics:" -ForegroundColor Yellow
    Write-Host '   $summary = Get-RuleSummary -Rules $allRules'
    Write-Host '   $summary.BySource | Format-Table'
    Write-Host ""
    
    Write-Host "Available Sources:" -ForegroundColor Cyan
    $availableSources = @(
        "Threat Intelligence", "Microsoft Defender XDR", "Microsoft Entra ID", 
        "Network Session Essentials", "Microsoft 365", "Attacker Tools Threat Protection Essentials",
        "Azure Activity", "Endpoint Threat Protection Essentials", "Cloud Identity Threat Protection Essentials",
        "DNS Essentials", "1Password", "Network Threat Protection Essentials", 
        "MicrosoftDefenderForEndpoint", "Azure Active Directory", "Gallery Content"
    )
    
    foreach ($source in $availableSources | Sort-Object) {
        Write-Host "  - $source" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "Available Severities:" -ForegroundColor Cyan
    Write-Host "  - High" -ForegroundColor White
    Write-Host "  - Medium" -ForegroundColor White
    Write-Host "  - Low" -ForegroundColor White
    Write-Host "  - Informational" -ForegroundColor White
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
        [string[]]$FilesProcessed,
        [hashtable]$globalTracking  # FIX: Add this parameter
    )
    
    if (-not $TenantTracking) {
        return
    }
    
    # Collect details for each rule this tenant changed
    $ruleChanges = @()
    
    # FIX: Use the passed parameter instead of global variable
    foreach ($ruleId in $globalTracking.Keys) {
        $ruleInfo = $globalTracking[$ruleId]
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
        Process-JsonFile -FilePath $file -BaseOutputDirectory $OutputDirectory -globalTracking $globalTracking -GlobalStats $globalStats
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
    Update-TenantTracking -TenantTracking $tenantTracking -ProcessingStats $globalStats -FilesProcessed $filesToProcess -GlobalTracking $globalTracking
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