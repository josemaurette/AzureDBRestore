# AzureDBRestore
Set of functions to allow restoring databases directly from Azure Blob Storage. This functionality does not require access to MSDB since all information required to restore the database is extracted from the blobs. It also allows stiped backups and point in time recovery 

## How to run it
```powershell

$ServerName = 'localhost'
$dataFolder = 'C:\MSSQL\DATA\'
$logFolder = 'C:\MSSQL\Log\'
$StorageAccountName = '<StorageAccountName>'
$containerName = '<containerName>'
$StorageAccountKey = '<StorageAccountKey>'
$policyName = '<access policy name>'

$databasesToRestore = @('DB1','DB2')

Restore-DatabasesFromBlobStorage `
    -ServerName $ServerName `
    -DataFolder $dataFolder `
    -LogFolder $logFolder `
    -StorageAccountName $StorageAccountName `
    -StorageAccountKey $StorageAccountKey `
    -ContainerName $containerName -DatabasesToInclude $databasesToRestore `
    -Policy $policyName `
    -ScriptOnly $true `
    -NoRecovery $false

```