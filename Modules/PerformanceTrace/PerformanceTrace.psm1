Function Get-HardwareConfiguration {
    [CmdletBinding()]
    param ()

    # CPU Information
    $cpu = Get-WmiObject Win32_Processor | Select-Object Name, NumberOfCores, MaxClockSpeed

    # Memory Information
    $memory = Get-WmiObject Win32_PhysicalMemory | Measure-Object Capacity -Sum
    $totalMemoryGB = [math]::Round($memory.Sum / 1GB, 2)

    # GPU Information
    $gpu = Get-WmiObject Win32_VideoController | Select-Object Name, DriverVersion, AdapterRAM
    $totalGpuRAMGB = [math]::Round(($gpu | Measure-Object AdapterRAM -Sum).Sum / 1GB, 2)

    # Disk Information
    $disk = Get-WmiObject Win32_DiskDrive | Select-Object Model, Size, MediaType
    $totalDiskSizeGB = [math]::Round(($disk | Measure-Object Size -Sum).Sum / 1GB, 2)

    # Operating System Information
    $os = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture

    # Output
    [PSCustomObject]@{
        CPU               = $cpu.Name
        Cores             = $cpu.NumberOfCores
        ClockSpeedMHz     = $cpu.MaxClockSpeed
        TotalMemoryGB     = $totalMemoryGB
        GPU               = $gpu.Name -join ', '
        GPUDriverVersion  = $gpu.DriverVersion -join ', '
        TotalGpuRAMGB     = $totalGpuRAMGB
        DiskModel         = $disk.Model -join ', '
        TotalDiskSizeGB   = $totalDiskSizeGB
        DiskMediaType     = $disk.MediaType -join ', '
        OS                = $os.Caption
        OSVersion         = $os.Version
        OSArchitecture    = $os.OSArchitecture
    }
}

function Get-HardwareUsageStats {
    [CmdletBinding()]
    param (

    )

    # CPU Load Percentage
    $cpuLoad = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $cpuLoad = [math]::Round($cpuLoad, 2)

    # Memory Usage
    $memStats = Get-CimInstance Win32_OperatingSystem
    $totalMem = [math]::Round($memStats.TotalVisibleMemorySize / 1MB, 2)
    $freeMem = [math]::Round($memStats.FreePhysicalMemory / 1MB, 2)
    $usedMem = $totalMem - $freeMem
    $memUsagePercentage = [math]::Round(($usedMem / $totalMem) * 100, 2)

    # Disk Usage (Percentage for C: drive)
    $diskUsage = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    $totalDiskSpace = [math]::Round($diskUsage.Size / 1GB, 2)
    $freeDiskSpace = [math]::Round($diskUsage.FreeSpace / 1GB, 2)
    $usedDiskSpace = $totalDiskSpace - $freeDiskSpace
    $diskUsagePercentage = [math]::Round(($usedDiskSpace / $totalDiskSpace) * 100, 2)

    # Disk Read/Write Speeds (Bytes per second)
    $readCounter = Get-Counter '\PhysicalDisk(0 C:)\Disk Read Bytes/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $writeCounter = Get-Counter '\PhysicalDisk(0 C:)\Disk Write Bytes/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue
    $readSpeedMBps = [math]::Round($readCounter / 1MB, 2)
    $writeSpeedMBps = [math]::Round($writeCounter / 1MB, 2)

        # GPU Engine Load (% usage)
    $gpuLoadCounter = Get-Counter '\GPU Engine(*)\Utilization Percentage' | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.InstanceName -match 'engtype_3D' } | Measure-Object -Property CookedValue -Average
    $gpuLoad = [math]::Round($gpuLoadCounter.Average * 100, 2)

    # GPU Memory Usage (Dedicated and Shared) in Bytes
    $dedicatedMemoryCounter = Get-Counter '\GPU Adapter Memory(*)\Dedicated Usage' | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Sum
    $dedicatedMemoryGB = [math]::Round($dedicatedMemoryCounter.Sum / 1GB, 2)

    $sharedMemoryCounter = Get-Counter '\GPU Adapter Memory(*)\Shared Usage' | Select-Object -ExpandProperty CounterSamples | Measure-Object -Property CookedValue -Sum
    $sharedMemoryGB = [math]::Round($sharedMemoryCounter.Sum / 1GB, 2)

    # Get total GPU memory by summing across all video controllers
    $totalPhysicalMemoryBytes = (Get-CimInstance Win32_VideoController | Measure-Object -Property AdapterRAM -Sum).Sum
    $totalPhysicalMemoryGB = [math]::Round($totalPhysicalMemoryBytes / 1GB, 2)

    # Calculate GPU memory usage percentage
    $gpuMemoryUsagePercent = if ($totalPhysicalMemoryGB -ne 0) {
        [math]::Round((($dedicatedMemoryGB + $sharedMemoryGB) / $totalPhysicalMemoryGB) * 100, 2)
    } else {
        0
    }


    # Output
    [PSCustomObject]@{
        Timestamp           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Processor_CPU_Load_Percent    = $cpuLoad
        RAM_Used_Memory_GB      = $usedMem
        RAM_Total_Memory_GB     = $totalMem
        RAM_Memory_Usage_Percent = $memUsagePercentage
        DISK_Used_Disk_GB        = $usedDiskSpace
        DISK_Total_Disk_GB       = $totalDiskSpace
        DISK_Disk_Usage_Percent  = $diskUsagePercentage
        DISK_Read_Speed_MBps     = $readSpeedMBps
        DISK_Write_Speed_MBps    = $writeSpeedMBps
        GPU_GPU_Load_Percent        = $gpuLoad
        GPU_Dedicated_Memory_GB     = $dedicatedMemoryGB
        GPU_Shared_Memory_GB        = $sharedMemoryGB
        GPU_Total_GPU_Memory_GB     = $totalPhysicalMemoryGB
        GPU_GPU_Memory_Usage_Percent = $gpuMemoryUsagePercent
    }
}

Function Start-PerformanceTrace {
    Param(
        [Parameter()][Int]$IntervalSeconds = 2, 
        [Parameter()][Int]$RetentionDays = 1,
        [Parameter()][Int]$DurationHours = 24,
        [Parameter()][string]$OutputFile = "C:\temp\PerformanceLog.csv"
    )

    $EndTime = (Get-Date).AddHours($DurationHours)

    While ((Get-Date) -le $EndTime) {
        try {
            # Collect new stats
            $newData = Get-HardwareUsageStats

            # Check if file exists; if not, create it with headers
            if (-not (Test-Path $outputFile)) {
                $newData | Export-Csv -Path $outputFile -NoTypeInformation
            } else {
                # Append new data to the CSV file
                $newData | Export-Csv -Path $outputFile -NoTypeInformation -Append
            }

            # Wait for the specified interval before collecting new data
            Start-Sleep -Seconds $IntervalSeconds

        } catch {
            Write-Warning "An error occurred: $_"
        }
    }

    # Filter out old data based on retention period
    try {
        $currentTime = Get-Date
        $DaysAgo = $currentTime.AddDays(-$RetentionDays)

        $logData = Import-Csv -Path $outputFile | Where-Object { (Get-Date $_."Timestamp") -ge $DaysAgo }
        $logData | Export-Csv -Path $outputFile -NoTypeInformation
    } catch {
        Write-Warning "An error occurred during log filtering: $_"
    }
}

Export-ModuleMember Start-PerformanceTrace, Get-HardwareUsageStats