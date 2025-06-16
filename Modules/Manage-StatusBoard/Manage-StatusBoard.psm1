Function New-StatusBoard {
    param(
        [Parameter(Mandatory=$True)][string[]]$TopAxis, 
        [Parameter(Mandatory=$True)][string[]]$SideAxis,
        [Parameter()][string[]]$DefaultValue = 'Not Started',
        [Parameter()][hashtable]$ColorMapValuesToAdd
    )
    $Global:StatusBoard = @{}
    $Global:StatusBoardColorMap = @{
        'Not Started' = 'Red'
        'In Progress' = 'Yellow'
        'Completed' = 'Green'
    }
    # Add colors if specified
    if($ColorMapValuesToAdd){
        foreach($Key in $ColorMapValuesToAdd){
            $StatusBoardColorMap[$key] = $ColorMapValuestoAdd[$Key]
        }
    }
    foreach($SideAxisItem in $SideAxis){
        $StatusBoard[$SideAxisItem] = @{}
        Foreach($TopAxisItem in $TopAxis){
            $StatusBoard[$SideAxisItem][$TopAxisItem] = '$DefaultValue'
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

    $TopAxis = ($Global:StatusBoard.Values | Select-object -First 1).Keys
    $columnWidth = ($TopAxis + $Global:StatusBoard.Keys | Measure-Object -Maximum Length).Maximum + 2

    clear-host
    
    # Write Header
    Write-Host ("".PadRight($ColumnWidth)) -nonewline
    foreach ($TopAxisItem in $TopAxis){
        Write-Host ($topAxisItem.PadRight($ColumnWidth)) -NoNewLine -ForeGroundColor Magenta
    }
    Write-Host ""

    # Write each Row 
    foreach($SideAxisItem in $Global:StatusBoard.Keys){
        Write-Host $SideAxisItem.PadRight($ColumnWidth) -NoNewLine -ForeGroundColor Cyan
        Foreach($TopAxisItem in $TopAxis){
            $Status = $Global:StatusBoard[$SideAxisItem][$TopAxisItem]
            $Color = If($StatusBoardColorMap.ContainsKey($Status)){$StatusBoardColorMap[$Status]}Else{$StatusBoardColorMap['Default']}
            Write-Host ($Status.PadRight($ColumnWidth)) -foregroundcolor $Color -NoNewLine
        }
        Write-Host ""
    }
}
Function Get-StatusBoard {
    $results = @()
    $TopAxis = ($Global:StatusBoard.Values | Select-Object -First 1).Keys
    foreach($sideAxisItem in $Global:StatusBoard.Keys){
        $row = [ordered]@{ Item = $SideAxisItem}
        foreach ($topAxisItem in $topAxis){
            $row[$topAxisItem] = $Global:StatusBoard[$sideAxisItem][$topAxisItem].Value
        }
        $results += [PSCustomObject]$Row
    }
    return $results
}