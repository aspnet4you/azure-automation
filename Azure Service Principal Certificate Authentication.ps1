<#
    .DESCRIPTION
        An example azure automation runbook which reads Azure KeyVault using the Managed Identity
		Get Secret password and Certificate (PFX) from Azure KeyVault
		Loads PFX file in Memory
		Saves PFX in local file, only available during the running job
		Export PFX to Current User store
		Signs into Azure with Service Principal with Certificate Authentcation
		Read Azure Storage blobs


    .NOTES
        AUTHOR: Prodip K. Saha
        LASTEDIT: Feb 7, 2022
#>

"Please enable appropriate RBAC permissions to the system identity of this automation account. Otherwise, the runbook may fail..."

$secretname= 'secret-in-keyvault-used-4-cert-password'
$KeyVaultName = 'azure-keyvault-name'
$CertificateName  = 'cert-name-in-keyvault'
$ApplicationId = 'azure-ad-application-id'
$Tenant = 'your-tenant.onmicrosoft.com'
$Subscription = 'your-subscription-name'
$StorageAccountName = 'azure-storage-account-name'
$StorageContainerName = 'container1'

"Logging in to Azure..."
#If you are running locally in PowerShell ISE, don't use the -Identity flag
#Instead use your interactive elevated account. Be sure to configure RBAC permission accordingly.
$managedIdentityCtx = Connect-AzAccount -Tenant $Tenant -Subscription $Subscription #run locally
#$managedIdentityCtx = Connect-AzAccount -Identity #run in Azure Automation

$TenantId = $managedIdentityCtx.Context.Tenant.TenantId
$subscriptionId = $managedIdentityCtx.Context.Subscription.Id

#Check if PFX file is persisted between the jobs
$folderPath = "$env:TEMP\mycerts"
Write-Output ("Path: $folderPath")

$isCertExist = Test-Path $folderPath
Write-Output("isCertExist: $isCertExist")

if ($isCertExist -eq $false)
{
	New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
	Write-Output("Cert Path did't exist. New folder created: $folderPath")
}

# Read key from key vault
# Prerequisite: Key Vault Access Policy must grant access to keys, secrets and certificates to the Identity used
# to run this automation account job. This automation account is using Managed Identity and key vault access policy
# is configured accordingly.

#Get the current version of a specific secret
$certPassword = Get-AzKeyVaultSecret -VaultName $vaultName -Name $secretname

#Get Certificate and Key. PFX Certificate Key must be Exportable.
#Certificate format should be PKCS #12 and Exportable Private Key is set to Yes.
$cert = Get-AzKeyVaultCertificate -VaultName $KeyVaultName -Name $CertificateName
$azKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $cert.Name

$pfxCertFile = "$folderPath\$CertificateName.pfx"

if ((Test-Path $pfxCertFile) -eq $false)
{
	Write-Output("No certificate file present in the path: $pfxCertFile")
}
else
{
	Write-Output("Certificate file present in the path: $pfxCertFile")
}


#Put KeyVault Certificate information in memory to export
[PSCredential]$password = New-Object System.Management.Automation.PSCredential('cert-credential',$azKeyVaultSecret.SecretValue)
$cert64TextString = [System.Convert]::FromBase64String($password.GetNetworkCredential().password)
$x509CertCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$x509CertCollection.Import($cert64TextString, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)  

#Export Azure Key Vault certificate to .pfx file 
$x509CertCollectionBytes = $x509CertCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $certPassword)
[System.IO.File]::WriteAllBytes($pfxCertFile, $x509CertCollectionBytes)
Write-Output "Exported certificate to file - $pfxCertFile"

#Get certtificate Thumbprint
$CertPass = ConvertTo-SecureString $certPassword -AsPlainText -Force
$PFXCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($pfxCertFile, $CertPass)
$Thumbprint = $PFXCert.Thumbprint

#Import cert into current user store. This is needed to resolve the certificate
#when connecting to Azure with Thumbprint.
Import-PfxCertificate -FilePath $pfxCertFile -CertStoreLocation Cert:\CurrentUser\My -Password $CertPass


#Connect to Azure Service Principal with Certificate Authentication
$spCtx = Connect-AzAccount -ServicePrincipal -CertificateThumbprint $Thumbprint -ApplicationId $ApplicationId -TenantId $TenantId

#Read Azure Storage Blob Container
$context = New-AzStorageContext -StorageAccountName  $StorageAccountName
Get-AzStorageBlob -Container $StorageContainerName -Context $context | Select-Object -Property Name

#Disconnect from Azure Contexts
Disconnect-AzAccount -AzureContext $managedIdentityCtx.Context
Disconnect-AzAccount -AzureContext $spCtx.Context


#Delete PFX cert from local folder
if ((Test-Path $pfxCertFile) -eq $true)
{
	Remove-Item -Path $pfxCertFile -Force | Out-Null
}

#Delete PFX cert from local Certificate Store
Get-ChildItem Cert:\CurrentUser\My |Where-Object { $_.Thumbprint -match $Thumbprint } |Remove-Item