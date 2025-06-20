Function New-StatusBoard {
    param(
        [Parameter(Mandatory=$True)][string[]]$TopAxis, 
        [Parameter(Mandatory=$True)][string[]]$SideAxis,
        [Parameter()][string[]]$DefaultValue = 'Not Started',
        [Parameter()][hashtable]$ColorMapValuesToAdd
    )
    $Global:StatusBoard = @{}
    $Global:StatusBoardSideAxis = $SideAxis
    $Global:StatusBoardTopAxis = $TopAxis
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
    foreach($SideAxisItem in $SideAxis){
        $StatusBoard[$SideAxisItem] = @{}
        Foreach($TopAxisItem in $TopAxis){
            $StatusBoard[$SideAxisItem][$TopAxisItem] = $DefaultValue
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

    $columnWidth = ($Global:StatusBoardTopAxis + $Global:StatusBoardSideAxis | Measure-Object -Maximum Length).Maximum + 2

    clear-host
    
    # Write Header
    Write-Host ("".PadRight($ColumnWidth)) -nonewline
    foreach ($TopAxisItem in $Global:StatusBoardTopAxis){
        Write-Host ($topAxisItem.PadRight($ColumnWidth)) -NoNewLine -ForeGroundColor Magenta
    }
    Write-Host ""

    # Write each Row 
    foreach($SideAxisItem in $Global:StatusBoardSideAxis){
        Write-Host $SideAxisItem.PadRight($ColumnWidth) -NoNewLine -ForeGroundColor Cyan
        Foreach($TopAxisItem in $Global:StatusBoardTopAxis){
            $Status = $Global:StatusBoard[$SideAxisItem][$TopAxisItem]
            $Color = If($StatusBoardColorMap.ContainsKey($Status)){$StatusBoardColorMap[$Status]}Else{$StatusBoardColorMap['Default']}
            Write-Host ($Status.PadRight($ColumnWidth)) -foregroundcolor $Color -NoNewLine
        }
        Write-Host ""
    }
}
Function Get-StatusBoard {
    $results = @()
    foreach($sideAxisItem in $Global:StatusBoardSideAxis){
        $row = [ordered]@{ Item = $SideAxisItem}
        foreach ($topAxisItem in $Global:StatusBoardTopAxis){
            $row[$topAxisItem] = $Global:StatusBoard[$sideAxisItem][$topAxisItem]
        }
        $results += [PSCustomObject]$Row
    }
    return $results
}
Function Set-StatusBoardCell {
    param(
        [Parameter(Mandatory, Position=0)][string]$SideAxisItem,
        [Parameter(Mandatory, Position=1)][string]$TopAxisItem,
        [Parameter(Mandatory,Position=2)][string]$Value
    )
    if(!($Global:StatusBoard.ContainsKey($SideAxisItem))){
        throw "item '$SideAxisItem' not found in StatusBoard."
    }
    if(!($Global:StatusBoard[$sideAxisItem].ContainsKey($TopAxisItem))){
        throw "column '$topAxisItem' not found for '$sideAxisItem' in StatusBoard."
    }
    $Global:StatusBoard[$SideAxisItem][$topAxisItem] = $Value
}