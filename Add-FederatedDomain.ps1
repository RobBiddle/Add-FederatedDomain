<#
.NOTES
    Author: Robert D. Biddle
    Date: 01/27/2017
.Synopsis
   Add an additional Federated Domain to ADFS
.DESCRIPTION
    This should be run on the ADFS server in an Administrative PowerShell environment
    Connect to Office365 using Partner credentials so that TenantId parameter can be utilized in MSOnline cmdlets   
.EXAMPLE
   Add-FederatedDomain -TenantId 2e6ec23f-4e6a-403e-adfe-af5e8de381cb -DomainToFederate example.org -FederationServerFQDN fs.fakedomain.org
#>
function Global:Add-FederatedDomain {
    [CmdletBinding()]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # TenantId of Partner
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false)]
        [String]
        $TenantId,

        # Domain name to Federate
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false)]
        [String]
        $DomainToFederate,

        # Public FQDN of ADFS Federation Server
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$false)]
        [String]
        $FederationServerFQDN,

        # Credential for Office365
        [Parameter(HelpMessage="PSCredential object for Office 365")]
        [PSCredential]
        $CredentialForOffice365,

        # Federation Server Token-Signing Certificate Byte String
        [Parameter(Mandatory=$false,ValueFromPipelineByPropertyName=$false)]
        [String]
        $FederationCertificate = $null
    )
    Begin
    {
        # Throw Terminating Error if $FederationCertificate was not specified and ADFS PowerShell Module is not present
        If(!($FederationCertificate) -and !(Get-Module -ListAvailable ADFS)){
            Throw "Must be run on ADFS server, unless Token-Signing Certificate is provided"
        }
        # If ADFS PowerShell Module is available use Get-AdfsCertificate cmdlet to obtain 
        If(!($FederationCertificate) -and (Get-Module -ListAvailable ADFS)){
            Write-Verbose "Attempting to obtainin ADFS Certificate from local store..."
            $cert = Get-AdfsCertificate -CertificateType Token-Signing
            $certBytes = $cert[0].Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes("$ENV:TEMP\tokensigning.cer", $certBytes)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$ENV:TEMP\tokensigning.cer")
            $certData = [system.convert]::tobase64string($cert.rawdata)
            Remove-Item "$ENV:TEMP\tokensigning.cer"
        }
        If($FederationCertificate){
            $certData = $FederationCertificate
        }
        # Test for existing MsolService connection
        if ((Get-MsolCompanyInformation -ErrorAction SilentlyContinue) -ne $true) {
            # Connect to Office365
            if($CredentialForOffice365){
                Connect-MsolService -Credential $CredentialForOffice365
            }Else{
                $CredentialForOffice365 = (Get-Credential -Message "Office365 Partner Admin Credentials")
                Connect-MsolService -Credential $CredentialForOffice365
            }
        }
    }
    Process
    {
        if(!(Get-MsolDomain -TenantId $TenantId -DomainName $DomainToFederate)){
            New-Msoldomain -Name $DomainToFederate -TenantId $TenantId
            $TXTrecordToSet = (Get-MsolDomainVerificationDns -DomainName $DomainToFederate -TenantId $TenantId -Mode DnsTxtRecord).Text
            $VerificationRecord = (Resolve-DnsName -Name $DomainToFederate -Type TXT).Strings
            if($VerificationRecord -notmatch $TXTrecordToSet) {
                Write-Error -Message "TXT Record containing $TXTrecordToSet must be added to $DomainToFederate Public DNS Zone"
                Return
            }
        }

        # Confirm Domain if necessary
        If(Get-MsolDomainVerificationDns -DomainName $DomainToFederate -TenantId $TenantId){
            $TXTrecordToSet = (Get-MsolDomainVerificationDns -DomainName $DomainToFederate -TenantId $TenantId -Mode DnsTxtRecord).Text
            Write-Output -Message "$DomainToFederate TXT Record of $TXTrecordToSet has not been verified, attempting verification now..."
            Confirm-MsolDomain -TenantId $TenantId -DomainName $DomainToFederate -ErrorAction SilentlyContinue
            if ((Get-MsolDomain -DomainName $DomainToFederate -TenantId $TenantId).Status -notlike 'Verified' -and (Get-MsolDomain -DomainName $DomainToFederate -TenantId $TenantId).Authentication -like 'Federated') {
                Set-MsolDomainAuthentication -DomainName $DomainToFederate -TenantId $TenantId -Authentication Managed
                Confirm-MsolDomain -TenantId $TenantId -DomainName $DomainToFederate
            }
        }

        Set-MsolDomain -Name (Get-MsolDomain -TenantId $TenantId | Where-Object Name -like "*microsoft.com").Name -TenantId $TenantId -IsDefault
        # ADFS Federation Settings
        Set-MsolDomainAuthentication `
            -ActiveLogOnUri "https://$FederationServerFQDN/adfs/services/trust/2005/usernamemixed"  `
            -Authentication Federated `
            -DomainName $DomainToFederate `
            -IssuerUri "http://$DomainToFederate/adfs/services/trust/" `
            -LogOffUri "https://$FederationServerFQDN/adfs/ls/" `
            -MetadataExchangeUri "https://$FederationServerFQDN/adfs/services/trust/mex" `
            -PassiveLogOnUri "https://$FederationServerFQDN/adfs/ls/" `
            -SigningCertificate $certData `
            -TenantId $TenantId

    }
    End
    {
        Get-MsolDomain -TenantId $TenantId -DomainName $DomainToFederate
    }
}
