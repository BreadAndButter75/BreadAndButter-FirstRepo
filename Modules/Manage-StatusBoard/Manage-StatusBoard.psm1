Function New-StatusBoard {
    param(
        [Parameter(Mandatory=$True)][string[]]$XAxis, 
        [Parameter(Mandatory=$True)][string[]]$YAxis,
        [Parameter()][string[]]$DefaultValue = 'Not Started',
        [Parameter()][hashtable]$ColorMapValuesToAdd
    )
    $Global:StatusBoard = @{}
    $Global:StatusBoardYAxis = $YAxis
    $Global:StatusBoardXAxis = $XAxis
    $Global:StatusBoardColorMap = @{
        'Not Started' = 'Red'
        'In Progress' = 'Yellow'
        'Completed' = 'Green'
        Default = 'Gray'
        'True' = 'Green'
        'False' = 'Red'
        'Success' = 'Green'
        'Fail' = 'Red'
    }
    # Add colors if specified
    if($ColorMapValuesToAdd){
        foreach($Key in $ColorMapValuesToAdd.Keys){
            $StatusBoardColorMap[$key] = $ColorMapValuesToAdd[$Key]
        }
    }
    foreach($YAxisItem in $YAxis){
        $StatusBoard[$YAxisItem] = @{}
        Foreach($XAxisItem in $XAxis){
            $StatusBoard[$YAxisItem][$XAxisItem] = $DefaultValue
        }
    }
}
Function Show-StatusBoard {
    param(
        [Parameter()][hashtable]$ColorMapValuesToAdd
    )
        # Add colors if specified
    if($ColorMapValuesToAdd){
        foreach($Key in $ColorMapValuesToAdd){
            $StatusBoardColorMap[$key] = $ColorMapValuestoAdd[$Key]
        }
    }

    $columnWidth = ($Global:StatusBoardXAxis + $Global:StatusBoardYAxis | Measure-Object -Maximum Length).Maximum + 2

    clear-host
    
    # Write Header
    Write-Host ("".PadRight($ColumnWidth)) -nonewline
    foreach ($XAxisItem in $Global:StatusBoardXAxis){
        Write-Host ($XAxisItem.PadRight($ColumnWidth)) -NoNewLine -ForeGroundColor Magenta
    }
    Write-Host ""

    # Write each Row 
    foreach($YAxisItem in $Global:StatusBoardYAxis){
        Write-Host $YAxisItem.PadRight($ColumnWidth) -NoNewLine -ForeGroundColor Cyan
        Foreach($XAxisItem in $Global:StatusBoardXAxis){
            $Status = $Global:StatusBoard[$YAxisItem][$XAxisItem]
            $Color = If($StatusBoardColorMap.ContainsKey($Status)){$StatusBoardColorMap[$Status]}Else{$StatusBoardColorMap['Default']}
            Write-Host ($Status.PadRight($ColumnWidth)) -foregroundcolor $Color -NoNewLine
        }
        Write-Host ""
    }
}
Function Get-StatusBoard {
    $results = @()
    foreach($YAxisItem in $Global:StatusBoardYAxis){
        $row = [ordered]@{ Item = $YAxisItem}
        foreach ($XAxisItem in $Global:StatusBoardXAxis){
            $row[$XAxisItem] = $Global:StatusBoard[$YAxisItem][$XAxisItem]
        }
        $results += [PSCustomObject]$Row
    }
    return $results
}
Function Set-StatusBoardCell {
    param(
        [Parameter(Mandatory, Position=0)][string]$YAxisItem,
        [Parameter(Mandatory, Position=1)][string]$XAxisItem,
        [Parameter(Mandatory,Position=2)][string]$Value
    )
    if(!($Global:StatusBoard.ContainsKey($YAxisItem))){
        throw "item '$YAxisItem' not found in StatusBoard."
    }
    if(!($Global:StatusBoard[$YAxisItem].ContainsKey($XAxisItem))){
        throw "column '$XAxisItem' not found for '$YAxisItem' in StatusBoard."
    }
    $Global:StatusBoard[$YAxisItem][$XAxisItem] = $Value
}