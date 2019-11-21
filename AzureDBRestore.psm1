<#
    .SYNOPSIS
        Gets the Shared Access Signature for the access policy in the specified container.

    .PARAMETER StorageAccountName
        String containing the Blob Storage Account Name.

    .PARAMETER AccountKey
        String containing the Blob Storage Account Key.

    .PARAMETER ContainerName
        String containing the Blob Storage Container Name.

    .PARAMETER PolicyName
        String containing the Blob Storage Share Access Policy Name.
#>
function Get-SharedAccessSignature {
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountName,
   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $AccountKey,
   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PolicyName,
   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContainerName 
    )

    # Create a new storage account context using an ARM storage account  
    $storageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $AccountKey
   
    $result = Set-AzureStorageContainerStoredAccessPolicy -Container $ContainerName -Policy $PolicyName -Context $storageContext -ExpiryTime ((Get-Date).AddDays(360)) -Permission rwdl
   
    # Gets the Shared Access Signature for the policy  
    $sas = New-AzureStorageContainerSASToken -name $ContainerName -Policy $PolicyName -Context $storageContext
    return $($sas.Substring(1))
}

<#
    .SYNOPSIS
        Sets SQL Server credential to allow restore/backups to/from URLs.

    .PARAMETER ServerInstance
        String containing SQL Server Instance name to backup/restore from/to.

    .PARAMETER Credential
        String containing the credential name to backup/restore from/to.

    .PARAMETER Secret
        String containing Azure Storage Container SAS Token.
#>
function Set-SQLServerBackupCredential 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerInstance,
   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Credential,
   
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Secret
    )

    $query = @"
              USE Master;
              if exists (
                         select *
                         from   sys.credentials s
                         where  s.name = '$Credential'
                        )
              begin
                 alter credential [$Credential]
                 with identity = 'SHARED ACCESS SIGNATURE'
                 ,secret = '$Secret';
              end
              else
              begin
              CREATE CREDENTIAL [$Credential]-- this name must match the container path, start with https and must not contain a forward slash.
              WITH IDENTITY='SHARED ACCESS SIGNATURE' -- this is a mandatory string and do not change it. 
              , SECRET = '$Secret'
              end
"@;

    Invoke-Sqlcmd -ServerInstance $serverInstance -query $query -QueryTimeout 0

}

<#
    .SYNOPSIS
        Returns an array of valid (mon-corrupted) backup files.
        Unless a limit in time specified it will return all blobs in the specified container

    .PARAMETER ServerName
        String containing SQL Server Instance name to backup/restore from/to.

    .PARAMETER StorageAccountName
        String containing the Blob Storage Account Name.

    .PARAMETER StorageAccountKey
        String containing the Blob Storage Account Key.

    .PARAMETER ContainerName
        String containing the Blob Storage Container Name.

    .PARAMETER PolicyName
        String containing the Blob Storage Share Access Policy Name.

    .PARAMETER Database
        String containing the database to restore. 
    .PARAMETER FromLastModified
        Optional parameter to reduce the amount of blobs to read.       
#>
function Get-BackupBlobs
{
    [cmdletbinding()]
    param 
    (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerName,

        [Parameter(Mandatory = $false)]
        [System.String]
        $InstanceName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PolicyName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContainerName,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Database,

        [Parameter(Mandatory = $false)]
        [System.String]
        $FromLastModified 
    )

    if ([string]::IsNullOrEmpty($FromLastModified)) {
        $FromLastModified = (Get-Date).AddDays(-7)
    }
 

    $tmpout = @()
    $sqlsvr = New-Object -TypeName  Microsoft.SQLServer.Management.Smo.Server($ServerName)
    $restore = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Restore
    $devicetype = [Microsoft.SqlServer.Management.Smo.DeviceType]::URL
 
    $context = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

    $ContainerUri = 'https://' + $StorageAccountName + '.blob.core.windows.net/' + $ContainerName
    
    $secret = Get-SharedAccessSignature `
        -StorageAccountName $StorageAccountName `
        -AccountKey $StorageAccountKey `
        -PolicyName $PolicyName `
        -ContainerName $ContainerName
    
    Set-SQLServerBackupCredential -ServerInstance $ServerName -Credential $ContainerUri -Secret $secret

    $Filter = $database + '_*.*'
    
    # Get all backup blobs older than FromLastModified
    
    $blobs = Get-AzureStorageBlob -Context $context -Container $containerName -Blob $Filter|`
        where-object { ($_.LastModified -gt $FromLastModified) } | `
        sort @{expression = "LastModified"; Descending = $true}
 
    foreach ($blob in $blobs) {
        $fullurl = $ContainerUri + '/' + $blob.Name
        $restoredevice = New-Object -TypeName Microsoft.SQLServer.Management.Smo.BackupDeviceItem($fullurl, $devicetype)
        $restore.Devices.add($restoredevice) | Out-Null
        $errcnt = 0
        try {
            $restore.ReadMediaHeader($sqlsvr) | Out-Null
        }
        catch [System.Exception] {
            $errcnt = 1
        }
        finally {
            if ($errcnt -ne 1) {
                $tmpout += $fullurl
            }
            $errcnt = 0
        }
        $restore.Devices.remove($restoredevice) | out-null
        Remove-Variable restoredevice
    }
    return $tmpout
}

<#
    .SYNOPSIS
        Get the content of the backup header in order to be able to do point in time recovery

    .PARAMETER ServerName
        String containing SQL Server Instance name to backup/restore from/to.

    .PARAMETER BlobPath
        String containing the full blob URI path
#>
function Get-BackupBlobContents {
    Param
    (

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $BlobPath
    )
 
    $sqlsvr = New-Object -TypeName  Microsoft.SQLServer.Management.Smo.Server($ServerName)
    $restore = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Restore
    $devicetype = [Microsoft.SqlServer.Management.Smo.DeviceType]::URL
 
    $restoredevice = New-Object -TypeName Microsoft.SQLServer.Management.Smo.BackupDeviceItem($BlobPath, $devicetype)
    $restore.Devices.add($restoredevice) | Out-Null
    $Temp = $Restore.ReadBackupHeader($sqlsvr)
    $Temp | Add-Member -MemberType NoteProperty -Name FilePath -value $BlobPath
    $restore.Devices.Remove($restoredevice) | Out-Null
    return $temp
}

<#
    .SYNOPSIS
        Returns an array of valid (mon-corrupted) backup files.
        Unless a limit in time specified it will return all blobs in the specified container

    .PARAMETER ServerName
        String containing SQL Server Instance name to backup/restore from/to.

    .PARAMETER DataFolder
        String containing the path to the data folder path of database.
    
    .PARAMETER LogFolder
        String containing the path to the log folder path of database.    

    .PARAMETER StorageAccountName
        String containing the Blob Storage Account Name.

    .PARAMETER StorageAccountKey
        String containing the Blob Storage Account Key.

    .PARAMETER ContainerName
        String containing the Blob Storage Container Name.

    .PARAMETER PolicyName
        String containing the Blob Storage Share Access Policy Name.

    .PARAMETER DatabasesToInclude
        String Array containing all database to restore. 
    .PARAMETER GoBackTime
        Optional parameter to reduce the amount of blobs to read.       
    .PARAMETER PointInTime
        Optional parameter for point in time recovery.        
#>

function Restore-DatabasesFromBlobStorage {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerName,

        [Parameter(Mandatory = $false)]
        [System.String]
        $InstanceName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DataFolder,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $LogFolder,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $StorageAccountKey,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $PolicyName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ContainerName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ScriptOnly = $false,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $NoRecovery = $false,

        [Parameter(Mandatory = $true)]
        [System.String[]]
        $DatabasesToInclude = @(),

        [Parameter(Mandatory = $false)]
        [System.String]
        $PointInTime,

        [Parameter(Mandatory = $false)]
        [System.String]
        $GoBackTime

 
    )
    if ([string]::IsNullOrEmpty($PointInTime)) {
        $DateTime = get-date
    }
    else {
        $DateTime = get-date($PointInTime)
    }
    
    $filterDateTimeSQL = get-date($DateTime).ToUniversalTime() -format "MMM dd, yyyy hh:mm tt"

    New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey

    $ContainerUri = 'https://' + $StorageAccountName + '.blob.core.windows.net/' + $ContainerName

    $secret = Get-SharedAccessSignature `
        -StorageAccountName $StorageAccountName `
        -AccountKey $StorageAccountKey `
        -PolicyName $PolicyName `
        -ContainerName $ContainerName
    
    Set-SQLServerBackupCredential -ServerInstance $ServerName -Credential $ContainerUri -Secret $secret

        
    foreach ($database in $DatabasesToInclude) {
        $backupBlobs = @()
        $backups = @()

 
        $backupBlobs += Get-BackupBlobs `
            -ServerName $ServerName `
            -StorageAccountName $StorageAccountName `
            -StorageAccountKey $StorageAccountKey `
            -ContainerName $containerName -Database $database `
            -Policy $policyName `
            -FromLastModified $GoBackTime          
        
        if ($backupBlobs.Count -eq 0) 
        {
            Write-Error "There is no backup media for $database database"
        }
        else 
        {
            foreach ($Blob in $backupBlobs | Sort-Object -property LastLSN) 
            {
                $backups += Get-BackupBlobContents `
                    -BlobPath $Blob `
                    -ServerName $ServerName
            }

        
            $RestoreDatabase = @()
            $RestoreDatabaseObject = @()
            $RestoreLogs = @()

            $RestoreFirstStriped = $Backups | Where-Object {($_.BackupTypeDescription -eq "Database") -and ($_.BackupStartDate -lt $filterDateTimeSQL)} | Sort-Object LastLSN -Descending | Select-Object -First 1
            $RestoreDatabaseObject += $Backups | Where-Object {($_.BackupTypeDescription -eq "Database") -and ($_.BackupSetGUID -eq $RestoreFirstStriped.BackupSetGUID)} 
            $tmpLSN = $RestoreDatabaseObject | Measure-Object -Property LastLSN -Maximum
            $RestoreLogs += $Backups | Where-Object {($_.LastLSN -ge $tmpLSN.Maximum) -and ($_.BackupTypeDescription -eq "Transaction Log") -and ($_.BackupStartDate -lt $filterDateTimeSQL)}
            $RestoreLogs = $RestoreLogs | sort-object -property LastLSN
        

            Foreach ($o in $RestoreDatabaseObject) {
                $RestoreDatabase += $o.FilePath
            }

            # Relocate files
            $dbfiles = @()
            $relocate = @()
            $url = $RestoreFirstStriped.FilePath
            $query = "RESTORE FileListOnly FROM  URL='$url'"
            $dbfiles = invoke-sqlcmd -ServerInstance $ServerName -Query $query
        
            foreach ($dbfile in $dbfiles) {
                $DbFileName = $dbfile.PhysicalName | Split-Path -Leaf
                if ($dbfile.Type -eq 'L') {
                    $newfile = Join-Path -Path $LogFolder -ChildPath $DbFileName
                }
                else {
                    $newfile = Join-Path -Path $DataFolder -ChildPath  $DbFileName
                }
                $relocate += New-Object Microsoft.SqlServer.Management.Smo.RelocateFile ($dbfile.LogicalName, $newfile)
            }
        
            if ($ScriptOnly -eq $true)
            {
                Restore-SqlDatabase `
                -ServerInstance $ServerName `
                -Database $database `
                -RelocateFile $relocate `
                -RestoreAction 'Database' `
                -BackupFile $RestoreDatabase `
                -NoRecovery `
                -script
            }
            else
            {
            Restore-SqlDatabase `
                -ServerInstance $ServerName `
                -Database $database `
                -RelocateFile $relocate `
                -RestoreAction 'Database' `
                -BackupFile $RestoreDatabase `
                -NoRecovery
            }
        
            foreach ($backup in $RestoreLogs) {
                $urlPath = $backup.FilePath
            if ($ScriptOnly -eq $true)
            {
                Restore-SqlDatabase `
                    -ServerInstance $ServerName `
                    -Database $database `
                    -RestoreAction 'Log' `
                    -BackupFile $urlPath `
                    -NoRecovery `
                    -script
            }
            else
            {
                    Restore-SqlDatabase `
                    -ServerInstance $ServerName `
                    -Database $database `
                    -RestoreAction 'Log' `
                    -BackupFile $urlPath `
                    -NoRecovery
                    
            }

            }
            
            if ($NoRecovery -eq $false) 
            {
                $RestoreWithRecoveryQuery= "RESTORE DATABASE $database WITH RECOVERY"
                if ($scriptOnly -eq $true)
                {
                   Write-Output $RestoreWithRecoveryQuery
                }
                else 
                {
                   invoke-sqlcmd -ServerInstance $ServerName -Query $RestoreWithRecoveryQuery
                }
            }           

        }
    }
}






