# Script: Parse-SentinelRules.ps1
# Enhanced version with support for multiple runs and flexible directory structure

param(
    [Parameter(Mandatory=$true)]
    [string]$InputJsonPath,
    
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory,
    
    [string]$ClientName = "Unknown-Client",
    
    [switch]$Force,
    
    [switch]$CreateTimestampedFolder
)

# Validate input file exists
if (-not (Test-Path $InputJsonPath)) {
    Write-Error "Input file not found: $InputJsonPath"
    exit 1
}

Write-Host "Processing Sentinel rules from: $InputJsonPath"
Write-Host "Client: $ClientName"
Write-Host "Output directory: $OutputDirectory"

try {
    # Read the ARM template JSON
    $armTemplate = Get-Content -Path $InputJsonPath -Raw | ConvertFrom-Json
    Write-Host "Successfully loaded ARM template"
} catch {
    Write-Error "Failed to parse JSON file: $($_.Exception.Message)"
    exit 1
}

# Create dynamic output directory structure
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Build the rules directory path
if ($CreateTimestampedFolder) {
    $rulesDir = Join-Path $OutputDirectory "$ClientName\$timestamp"
} else {
    $rulesDir = Join-Path $OutputDirectory $ClientName
    
    # If directory exists and not using Force, create timestamped subfolder
    if ((Test-Path $rulesDir) -and -not $Force) {
        $rulesDir = Join-Path $rulesDir $timestamp
        Write-Host "Directory exists, creating timestamped subfolder: $rulesDir"
    }
}

try {
    New-Item -ItemType Directory -Path $rulesDir -Force | Out-Null
    Write-Host "Created output directory: $rulesDir"
} catch {
    Write-Error "Failed to create output directory: $($_.Exception.Message)"
    exit 1
}

# Extract workspace parameter (if available)
$workspaceParam = $armTemplate.parameters.workspace.type

# Initialize arrays for categorization
$rulesByTactic = @{}
$rulesBySeverity = @{}
$allRules = @()
$processedCount = 0
$errorCount = 0

Write-Host "Processing rules from ARM template..."

# Process each rule in the resources array
foreach ($resource in $armTemplate.resources) {
    if ($resource.type -eq "Microsoft.OperationalInsights/workspaces/providers/alertRules") {
        try {
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
                # Enhanced metadata
                ProcessedAt = $timestamp
                ProcessedBy = $env:USERNAME
                SourceFile = Split-Path $InputJsonPath -Leaf
                ClientName = $ClientName
            }
            
            # Add to collections for organization
            $allRules += $cleanRule
            
            # Categorize by tactics (handle null/empty tactics)
            if ($rule.tactics -and $rule.tactics.Count -gt 0) {
                foreach ($tactic in $rule.tactics) {
                    if ($tactic) {  # Ensure tactic is not null or empty
                        if (-not $rulesByTactic.ContainsKey($tactic)) {
                            $rulesByTactic[$tactic] = @()
                        }
                        $rulesByTactic[$tactic] += $cleanRule
                    }
                }
            } else {
                # Handle rules without tactics
                if (-not $rulesByTactic.ContainsKey("No Tactic")) {
                    $rulesByTactic["No Tactic"] = @()
                }
                $rulesByTactic["No Tactic"] += $cleanRule
            }
            
            # Categorize by severity (handle null severity)
            $severity = if ($rule.severity) { $rule.severity } else { "Unknown" }
            if (-not $rulesBySeverity.ContainsKey($severity)) {
                $rulesBySeverity[$severity] = @()
            }
            $rulesBySeverity[$severity] += $cleanRule
            
            # Create individual rule file with enhanced naming
            $safeName = if ($rule.displayName) { 
                $rule.displayName -replace '[\\/*?:"<>|]', '_' -replace '\s+', '_' 
            } else { 
                "UnnamedRule_$ruleId" 
            }
            
            # Limit filename length to avoid filesystem issues
            if ($safeName.Length -gt 100) {
                $safeName = $safeName.Substring(0, 100)
            }
            
            $ruleFileName = "$safeName.json"
            $ruleFilePath = Join-Path $rulesDir $ruleFileName
            
            # Handle duplicate filenames
            $counter = 1
            while ((Test-Path $ruleFilePath) -and -not $Force) {
                $ruleFileName = "$safeName`_$counter.json"
                $ruleFilePath = Join-Path $rulesDir $ruleFileName
                $counter++
            }
            
            $cleanRule | ConvertTo-Json -Depth 10 | Out-File -FilePath $ruleFilePath -Encoding UTF8
            $processedCount++
            
            if ($processedCount % 10 -eq 0) {
                Write-Host "Processed $processedCount rules..."
            }
            
        } catch {
            Write-Warning "Failed to process rule: $($_.Exception.Message)"
            $errorCount++
        }
    }
}

Write-Host "Rule processing completed:"
Write-Host "  - Successfully processed: $processedCount rules"
if ($errorCount -gt 0) {
    Write-Host "  - Errors encountered: $errorCount rules" -ForegroundColor Yellow
}

# Create enhanced summary files
$summary = [PSCustomObject]@{
    ClientName = $ClientName
    SourceFile = Split-Path $InputJsonPath -Leaf
    SourceFilePath = $InputJsonPath
    OutputDirectory = $rulesDir
    TotalRules = $allRules.Count
    ProcessedRules = $processedCount
    ErrorCount = $errorCount
    RulesBySeverity = @{}
    RulesByTactic = @{}
    ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ExportTimestamp = $timestamp
    EnabledRules = ($allRules | Where-Object { $_.Enabled -eq $true }).Count
    DisabledRules = ($allRules | Where-Object { $_.Enabled -eq $false }).Count
    ProcessedBy = $env:USERNAME
    ProcessedFrom = $env:COMPUTERNAME
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
}

# Populate summary statistics
foreach ($severity in $rulesBySeverity.Keys) {
    $summary.RulesBySeverity[$severity] = $rulesBySeverity[$severity].Count
}

foreach ($tactic in $rulesByTactic.Keys) {
    $summary.RulesByTactic[$tactic] = $rulesByTactic[$tactic].Count
}

# Save enhanced summary
$summaryPath = Join-Path $rulesDir "export_summary.json"
$summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $summaryPath -Encoding UTF8



Write-Host "`nExport completed successfully!"
Write-Host "Summary saved to: $summaryPath"
Write-Host "Individual rule files saved to: $rulesDir"

# Display summary
Write-Host "`n=== EXPORT SUMMARY ===" -ForegroundColor Green
Write-Host "Client: $($summary.ClientName)"
Write-Host "Total Rules: $($summary.TotalRules)"
Write-Host "Enabled Rules: $($summary.EnabledRules)"
Write-Host "Disabled Rules: $($summary.DisabledRules)"
Write-Host "Export Directory: $($summary.OutputDirectory)"

if ($summary.RulesBySeverity.Count -gt 0) {
    Write-Host "`nRules by Severity:"
    foreach ($sev in $summary.RulesBySeverity.Keys) {
        Write-Host "  $sev`: $($summary.RulesBySeverity[$sev])"
    }
}

# Return summary for display
return $summary