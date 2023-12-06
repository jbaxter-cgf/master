############################################
## Functions
############################################
function Write-Log
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $File,

        [parameter(Mandatory=$true)]
        [System.String]
        $Text,

        [parameter(Mandatory=$true)]
        [ValidateSet("Information", "Error", "Warning")]
        [System.String]
        $Status
    )
    $Output = ("[" + (((Get-Date).ToShortDateString()) + "][" + (Get-Date).ToLongTimeString()) + "][" + $Status + "] " + $Text);
    $Output | Out-File -Encoding UTF8 -Force -FilePath $File -Append;
    Return Write-Output $Output;
}

##Author: Nicola Suter, Kudos to Tobias Renström for Get-ADGroupMembership, Test-ADGroupMemberShip and Test-RunningAsSystem
function Get-ADGroupMembership {
    [CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[System.String]
		$UserPrincipalName
	)
	process {
		try {
			if ([System.String]::IsNullOrEmpty($env:USERDNSDOMAIN) -and [System.String]::IsNullOrEmpty($searchRoot)) {
				Write-Error "Security group filtering won't work because `$env:USERDNSDOMAIN is not available!"
				Write-Warning "You can override your AD Domain in the `$overrideUserDnsDomain variable"
				Write-Output "Security group filtering won't work because `$env:USERDNSDOMAIN is not available!"
				exit 1
			}
			else {

				# if no domain specified fallback to PowerShell environment variable
				if ([System.String]::IsNullOrEmpty($searchRoot)) {
					$searchRoot = $env:USERDNSDOMAIN
				}

				$searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
				$searcher.Filter = "(&(userprincipalname=$UserPrincipalName))"
				$searcher.SearchRoot = "LDAP://$searchRoot"
				$distinguishedName = $searcher.FindOne().Properties.distinguishedname
				$searcher.Filter = "(member:1.2.840.113556.1.4.1941:=$distinguishedName)"

				[void]$searcher.PropertiesToLoad.Add("name")

				$list = [System.Collections.Generic.List[String]]@()
				$results = $searcher.FindAll()

				foreach ($result in $results) {
					$resultItem = $result.Properties
					[void]$List.add($resultItem.name)
				}
				$list
			}
		}
		catch {
			#Nothing we can do
			Write-Warning $_.Exception.Message
		}
	}
}

#Import JSON file contents into array for processing.
function Get-JSON {
	[CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
		[System.String]
		$File
    )
	$ImportJson = Get-Content $File | Out-String -ErrorAction SilentlyContinue
	$processJSON = $ImportJson | ConvertFrom-Json -ErrorAction Stop
	$processJSON = foreach ($u in $processJSON) {
		[PSCustomObject]@{
			id          = $($u.id)
			email       = $($u.email)
			firstName   = $($u.firstName)
			lastName    = $($u.lastName)
			userType    = $($u.userType)
		}
	}
}

Function Test-Elevation {
	Write-Host "Checking for elevation"

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
		[Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Warning "Sorry, you need to run this script from an elevated PowerShell prompt!`nPlease start the PowerShell prompt as an Administrator and re-run the script."
		Write-Warning "Aborting script..."
		Break
	}
	Write-Host "PowerShell runs elevated, OK, continuing...`n" -ForegroundColor Green
}

#check if running as system
function Test-RunningAsSystem {
	process {
		return [bool]($(whoami -user) -match "S-1-5-18")
	}
}

## Testing if groupmembership is given for user
function Test-GroupMembership {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
		[System.String]
		$driveMappingConfig,

		[Parameter(Mandatory=$true)]
		[System.String]
		$groupMemberships
    )
    try {
        $obj = foreach ($d in $driveMappingConfig) {
            if (-not ([string]::IsNullOrEmpty($($d.GroupFilter)))) {
                foreach ($filter in $($d.GroupFilter)) {
                    if ($groupMemberships -contains $filter) {
                        $d
                    }
                    else {
                        #no match for group
                    }
                }
            }
            else {
                $d 
            }
        }
        $obj
    }
    catch {
        Write-Error "Unknown error testing group memberships: $($_.Exception.Message)"
    }
}
function Test-PendingReboot {

}
Function Test-Elevation {
	Write-Host "Checking for elevation"

	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
		[Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Warning "Sorry, you need to run this script from an elevated PowerShell prompt!`nPlease start the PowerShell prompt as an Administrator and re-run the script."
		Write-Warning "Aborting script..."
		Break
	}
	Write-Host "PowerShell runs elevated, OK, continuing...`n" -ForegroundColor Green
}

Function Test-InternetConnection
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
		[System.String]
		$Target
    )

    #Test the connection to target.
    $Result = Test-NetConnection -ComputerName ($Target -replace "https://","") -Port 443 -WarningAction SilentlyContinue;

    #Return result.
    Return $Result;
}

Function Test-ScheduleTask
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
		[System.String]
		$Name
    )
    #Create a new schedule object.
    $Schedule = New-Object -com Schedule.Service;
    #Connect to the store.
    $Schedule.Connect();
    #Get schedule tak folders.
    $Task = $Schedule.GetFolder("\").GetTasks(0) | Where-Object {$_.Name -eq $Name -and $_.Enabled -eq $true};
    #If the task exists and is enabled.
    If($Task)
    {
        Return $true;
    }
    Else
    {
        Return $false;
    }
}

Function Test-Module {
	Param(
		[String]$Name,
		[String]$Scope
	)

	try {
		Write-Output "Module:`t $Name `tSTATUS=SEARCHING"
		if ($null -eq (Get-InstalledModule -Name $Name -ErrorAction Stop -Verbose:$false)) {
			Write-Output "Module:`t $Name `tSTATUS=VERSIONCHECK"
			$LatestModuleVersion = (Find-Module -Name $Name -ErrorAction Stop -Verbose:$false).Version
			if ($LatestModuleVersion -gt $Name.Version) {
				Write-Output "Module:`t $Name `tSTATUS=UPDATING `tVERSION=$($LatestModuleVersion.ToString())"
				#$UpdateModuleInvocation = Update-Module -Name $Name -Scope $Scope -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
				Update-Module -Name $Name -Scope $Scope -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
			}
			if ($LatestModuleVersion -eq $Name.Version) {
				Write-Output "Module:`t $Name `tSTATUS=PASSED"
			}
		} else {
			Write-Output "Module:`t $Name `tSTATUS=INSTALLED"
		}
	}
	catch [System.Exception] {
		Write-Output "Module:`t $Name `tSTATUS=MISSING"
		try {
			# Install NuGet package provider
			#$PackageProvider = Install-PackageProvider -Name NuGet -Scope $Scope -Force -Verbose:$false
			$PackageProvider = Install-PackageProvider -Name NuGet -Scope $Scope -Force -Verbose:$false

			# Check if PSGallery is a trusted source, and if not, add it
			$PSGallery = Get-PSRepository -Name PSGallery -ErrorAction Stop -Verbose:$false
			if ($PSGallery.InstallationPolicy -ne "Trusted") {
				Write-Output "Adding PSGallery as trusted source"
				Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
			}
			
			# Install module
			Install-Module -Name $Name -Scope $Scope -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
			Write-Output "Module:`t $Name `tSTATUS=INSTALLING"			
			Write-Output "Module:`t $Name `tSTATUS=INSTALLED"
		}
		catch [System.Exception] {
			Write-Output "Module:`t $Name `tSTATUS=FAILED"
			Break
		}
	}
}

# Deprecated, replace with Invoke-LoginMgGraph
Function Invoke-LoginMSOnline {
	<#
	## Establish connection to Microsoft Online Services 
    Try {
        Get-MsolDomain -ErrorAction Stop > $null
    }
    Catch {
        Write-Output "Connecting to Office 365..."
        Connect-MsolService
    }
    Finally {
        Write-Output "Connected to MsolService"
    }
	#>
	Write-Output "This cmdlet is deprecated, please use Invoke-LoginMgGraph instead."
}

# Deprecation on March 30, 2024, replace with Invoke-LoginMgGraph
Function Invoke-Login {
	## Establish connection to Microsoft Online Services 
    Try {
        Get-AzureADDomain -ErrorAction Stop > $null
    }
    Catch {
        Write-Output "Connecting to Azure AD..."
		Connect-AzureAD
	}
    Finally {
        Write-Output "Connected to Azure AD"
    }
	#>
	Write-Output "This cmdlet is schedule for deprecation on March 30, 2024. Please use Invoke-LoginMgGraph instead."
}


# Replace
Function Invoke-LoginMgGraph {
	## Establish connection to Microsoft Online Services 
    Try {
        Get-Organization -ErrorAction Stop > $null
    }
    Catch {
        Write-Output "Connecting to Microsoft Graph..."
        Connect-MSGraph -ForceInteractive
        Update-MSGraphEnvironment -SchemaVersion beta
        Connect-MSGraph
    }
    Finally {
        Write-Output "Connected to Microsoft Graph"
		Select-MgProfile Beta
    }	
}

Function Invoke-LoginMSGraph {
	## Establish connection to Microsoft Online Services 
    Try {
        Get-Organization -ErrorAction Stop > $null
    }
    Catch {
        Write-Output "Connecting to Microsoft Graph..."
        Connect-MSGraph -ForceInteractive
        Update-MSGraphEnvironment -SchemaVersion beta
        Connect-MSGraph
    }
    Finally {
        Write-Output "Connected to Microsoft Graph"
		Select-MgProfile Beta
    }	
}