#.\Sentinel-RulesV2.ps1 -InputPath "C:\Users\NoahBournes\Documents\TT-Sentinel" -OutputDirectory "C:\Users\NoahBournes\Git\Analytics-Rules" -TenantName "TarbhTech"

# Script: Parse-SentinelRulesV2.ps1
# Enhanced version with support for multiple JSON files and automatic folder organization

param(
    [Parameter(Mandatory=$true)]
    [string]$InputPath,  # Can be a file, folder, or wildcard pattern
    
    [Parameter(Mandatory=$true)]
    [string]$OutputDirectory,
    
    [Parameter(Mandatory=$true)]
    [string]$TenantName,  # Name of the tenant for tracking
    
    [string]$ClientName = "Unknown-Client",
    
    [switch]$Force,
    
    [switch]$VerboseOutput
)

# Function to update tenant tracking file
function Update-TenantTracking {
    param(
        [string]$OutputDirectory,
        [string]$TenantName,
        [array]$ProcessingResults,
        [string]$Timestamp
    )
    
    $trackingDir = Join-Path $OutputDirectory "_tenant_tracking"
    if (-not (Test-Path $trackingDir)) {
        New-Item -ItemType Directory -Path $trackingDir -Force | Out-Null
    }
    
    $trackingFile = Join-Path $trackingDir "tenant_tracking.json"
    $tenantFile = Join-Path $trackingDir "$TenantName`_tracking.json"
    
    # Load existing tracking data or create new
    $allTenantsTracking = @{}
    if (Test-Path $trackingFile) {
        try {
            $allTenantsTracking = Get-Content -Path $trackingFile -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            Write-Warning "Could not load existing tracking file, creating new one"
            $allTenantsTracking = @{}
        }
    }
    
    # Create current session data - only include items that were actually added
    $sessionData = [PSCustomObject]@{
        TenantName = $TenantName
        SessionTimestamp = $Timestamp
        ProcessedBy = $env:USERNAME
        ProcessedFrom = $env:COMPUTERNAME
        FilesWithNewRules = @()  # Only files that had rules added
        TotalRulesAdded = 0
        NewFoldersCreated = @()  # Only newly created folders
        SessionSummary = @{
            NewRulesAdded = @()  # Only new rules, not skipped ones
        }
    }
    
    # Process results to build detailed tracking - only for files with new rules
    foreach ($result in $ProcessingResults) {
        if ($result.Success -and $result.ProcessedRules -gt 0) {  # Only if rules were actually added
            $fileData = [PSCustomObject]@{
                FileName = $result.FileName
                TargetFolder = $result.TargetDirectory
                RulesAdded = $result.ProcessedRules
                RuleDetails = $result.RuleDetails
                FolderWasNew = $result.FolderWasNew
            }
            
            $sessionData.FilesWithNewRules += $fileData
            $sessionData.TotalRulesAdded += $result.ProcessedRules
            
            # Track only newly created folders
            if ($result.FolderWasNew -and $sessionData.NewFoldersCreated -notcontains $result.TargetDirectory) {
                $sessionData.NewFoldersCreated += $result.TargetDirectory
            }
            
            # Add only new rule details to session summary
            if ($result.RuleDetails) {
                $sessionData.SessionSummary.NewRulesAdded += $result.RuleDetails
            }
        }
    }
    
    # Only update tracking if there were actual changes
    if ($sessionData.TotalRulesAdded -gt 0) {
        # Update all tenants tracking
        if (-not $allTenantsTracking.ContainsKey($TenantName)) {
            $allTenantsTracking[$TenantName] = @{
                FirstSeen = $Timestamp
                LastUpdated = $Timestamp
                TotalSessions = 0
                TotalRulesAdded = 0
                Sessions = @()
            }
        }
        
        $allTenantsTracking[$TenantName].LastUpdated = $Timestamp
        $allTenantsTracking[$TenantName].TotalSessions++
        $allTenantsTracking[$TenantName].TotalRulesAdded += $sessionData.TotalRulesAdded
        $allTenantsTracking[$TenantName].Sessions += $sessionData
        
        # Save updated tracking files
        $allTenantsTracking | ConvertTo-Json -Depth 8 | Out-File -FilePath $trackingFile -Encoding UTF8
        $sessionData | ConvertTo-Json -Depth 8 | Out-File -FilePath $tenantFile -Encoding UTF8
        
        Write-Host "Tenant tracking updated (new additions only):"
        Write-Host "  All tenants: $trackingFile"
        Write-Host "  $TenantName session: $tenantFile"
    } else {
        Write-Host "No new rules added - tenant tracking not updated" -ForegroundColor Yellow
    }
    
    return $sessionData
}
# Function to check if a rule already exists in the target directory
function Test-RuleExists {
    param(
        [string]$TargetDirectory,
        [object]$Rule
    )
    
    if (-not (Test-Path $TargetDirectory)) {
        return $false
    }
    
    # Get all JSON files in the target directory
    $existingFiles = Get-ChildItem -Path $TargetDirectory -Filter "*.json" -File
    
    foreach ($file in $existingFiles) {
        try {
            $existingRule = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            
            # Check if rules match based on RuleId, DisplayName, or Query
            if (($Rule.RuleId -and $existingRule.RuleId -eq $Rule.RuleId) -or
                ($Rule.DisplayName -and $existingRule.DisplayName -eq $Rule.DisplayName) -or
                ($Rule.Query -and $existingRule.Query -eq $Rule.Query)) {
                if ($VerboseOutput) {
                    Write-Host "  Rule already exists: $($Rule.DisplayName)" -ForegroundColor Yellow
                }
                return $true
            }
        } catch {
            # Skip files that can't be parsed as JSON
            continue
        }
    }
    
    return $false
}

# Function to process a single JSON file
function Process-SentinelRulesFile {
    param(
        [string]$JsonFilePath,
        [string]$BaseOutputDirectory
    )
    
    Write-Host "`nProcessing file: $JsonFilePath" -ForegroundColor Cyan
    
    # Extract filename without extension for folder name
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($JsonFilePath)
    $targetDirectory = Join-Path $BaseOutputDirectory $fileName
    
    # Create target directory if it doesn't exist
    $folderWasNew = $false
    if (-not (Test-Path $targetDirectory)) {
        try {
            New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
            Write-Host "Created directory: $targetDirectory" -ForegroundColor Green
            $folderWasNew = $true
        } catch {
            Write-Error "Failed to create directory $targetDirectory`: $($_.Exception.Message)"
            return @{
                FileName = $fileName
                ProcessedRules = 0
                SkippedRules = 0
                ErrorCount = 1
                Success = $false
                FolderWasNew = $false
            }
        }
    }
    
    # Load and parse the JSON file
    try {
        $armTemplate = Get-Content -Path $JsonFilePath -Raw | ConvertFrom-Json
        Write-Host "Successfully loaded ARM template from $fileName"
    } catch {
        Write-Error "Failed to parse JSON file $JsonFilePath`: $($_.Exception.Message)"
        return @{
            FileName = $fileName
            ProcessedRules = 0
            SkippedRules = 0
            ErrorCount = 1
            Success = $false
        }
    }
    
    # Initialize counters
    $processedCount = 0
    $skippedCount = 0
    $errorCount = 0
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $addedRules = @()  # Track rules added for tenant tracking
    
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
                    SourceFile = Split-Path $JsonFilePath -Leaf
                    ClientName = $ClientName
                }
                
                # Check if rule already exists
                if (-not $Force -and (Test-RuleExists -TargetDirectory $targetDirectory -Rule $cleanRule)) {
                    $skippedCount++
                    continue
                }
                
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
                $ruleFilePath = Join-Path $targetDirectory $ruleFileName
                
                # Handle duplicate filenames
                $counter = 1
                while ((Test-Path $ruleFilePath) -and -not $Force) {
                    $ruleFileName = "$safeName`_$counter.json"
                    $ruleFilePath = Join-Path $targetDirectory $ruleFileName
                    $counter++
                }
                
                # Save the rule
                $cleanRule | ConvertTo-Json -Depth 10 | Out-File -FilePath $ruleFilePath -Encoding UTF8
                $processedCount++
                
                # Track added rule for tenant tracking
                $addedRules += [PSCustomObject]@{
                    RuleId = $cleanRule.RuleId
                    DisplayName = $cleanRule.DisplayName
                    FileName = $ruleFileName
                    FilePath = $ruleFilePath
                    Severity = $cleanRule.Severity
                    Enabled = $cleanRule.Enabled
                    Tactics = $cleanRule.Tactics
                    AddedAt = $timestamp
                }
                
                if ($VerboseOutput -and ($processedCount % 5 -eq 0)) {
                    Write-Host "  Processed $processedCount rules from $fileName..."
                }
                
            } catch {
                Write-Warning "Failed to process rule in $fileName`: $($_.Exception.Message)"
                $errorCount++
            }
        }
    }
    
    Write-Host "Completed $fileName`: $processedCount processed, $skippedCount skipped, $errorCount errors" -ForegroundColor Green
    
    return @{
        FileName = $fileName
        ProcessedRules = $processedCount
        SkippedRules = $skippedCount
        ErrorCount = $errorCount
        Success = $true
        TargetDirectory = $targetDirectory
        RuleDetails = $addedRules  # Include rule details for tracking
    }
}

# Main execution starts here
Write-Host "=== Sentinel Rules Multi-File Processor ===" -ForegroundColor Magenta
Write-Host "Input Path: $InputPath"
Write-Host "Output Directory: $OutputDirectory"
Write-Host "Tenant: $TenantName"
Write-Host "Client: $ClientName"
Write-Host "Force Overwrite: $Force"
Write-Host "Verbose Output: $VerboseOutput"

# Validate output directory
if (-not (Test-Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Host "Created base output directory: $OutputDirectory"
    } catch {
        Write-Error "Failed to create base output directory: $($_.Exception.Message)"
        exit 1
    }
}

# Get list of JSON files to process
$jsonFiles = @()

if (Test-Path $InputPath -PathType Container) {
    # Input is a directory - get all JSON files
    $jsonFiles = Get-ChildItem -Path $InputPath -Filter "*.json" -File | Select-Object -ExpandProperty FullName
    Write-Host "Found $($jsonFiles.Count) JSON files in directory"
} elseif (Test-Path $InputPath -PathType Leaf) {
    # Input is a single file
    if ($InputPath -like "*.json") {
        $jsonFiles = @($InputPath)
        Write-Host "Processing single JSON file"
    } else {
        Write-Error "Input file must be a JSON file: $InputPath"
        exit 1
    }
} else {
    # Try to resolve as wildcard pattern
    try {
        $jsonFiles = Get-ChildItem -Path $InputPath -Filter "*.json" -File | Select-Object -ExpandProperty FullName
        if ($jsonFiles.Count -eq 0) {
            Write-Error "No JSON files found matching pattern: $InputPath"
            exit 1
        }
        Write-Host "Found $($jsonFiles.Count) JSON files matching pattern"
    } catch {
        Write-Error "Invalid input path or pattern: $InputPath"
        exit 1
    }
}

if ($jsonFiles.Count -eq 0) {
    Write-Error "No JSON files found to process"
    exit 1
}

# Process each JSON file
$overallResults = @()
$totalProcessed = 0
$totalSkipped = 0
$totalErrors = 0

foreach ($jsonFile in $jsonFiles) {
    $result = Process-SentinelRulesFile -JsonFilePath $jsonFile -BaseOutputDirectory $OutputDirectory
    $overallResults += $result
    $totalProcessed += $result.ProcessedRules
    $totalSkipped += $result.SkippedRules
    $totalErrors += $result.ErrorCount
}

# Update tenant tracking
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$tenantTracking = Update-TenantTracking -OutputDirectory $OutputDirectory -TenantName $TenantName -ProcessingResults $overallResults -Timestamp $timestamp

# Create overall summary
$overallSummary = [PSCustomObject]@{
    TenantName = $TenantName
    ClientName = $ClientName
    InputPath = $InputPath
    OutputDirectory = $OutputDirectory
    FilesProcessed = $jsonFiles.Count
    TotalRulesProcessed = $totalProcessed
    TotalRulesSkipped = $totalSkipped
    TotalErrors = $totalErrors
    ProcessingResults = $overallResults
    TenantTracking = $tenantTracking
    ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ProcessedBy = $env:USERNAME
    ProcessedFrom = $env:COMPUTERNAME
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
}

# Save overall summary
$summaryPath = Join-Path $OutputDirectory "multi_file_export_summary.json"
$overallSummary | ConvertTo-Json -Depth 6 | Out-File -FilePath $summaryPath -Encoding UTF8

# Display final summary
Write-Host "`n=== OVERALL PROCESSING SUMMARY ===" -ForegroundColor Green
Write-Host "Tenant: $TenantName"
Write-Host "Files Processed: $($jsonFiles.Count)"
Write-Host "Total Rules Processed: $totalProcessed"
Write-Host "Total Rules Skipped (duplicates): $totalSkipped"
Write-Host "Total Errors: $totalErrors"
Write-Host "Output Directory: $OutputDirectory"
Write-Host "Summary saved to: $summaryPath"

Write-Host "`n=== DETAILED RESULTS ===" -ForegroundColor Cyan
foreach ($result in $overallResults) {
    if ($result.Success) {
        Write-Host "$($result.FileName): $($result.ProcessedRules) processed, $($result.SkippedRules) skipped"
    } else {
        Write-Host "$($result.FileName): FAILED" -ForegroundColor Red
    }
}

Write-Host "`nProcessing completed!" -ForegroundColor Green

# Return summary object
return $overallSummary