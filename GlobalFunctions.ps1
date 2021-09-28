############################################
## Define Functions
############################################
Function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true)][string]$File,
        [parameter(Mandatory=$true)][string]$Text,
        [parameter(Mandatory=$true)][string][ValidateSet("Information", "Error", "Warning")]$Status
    )

    #Construct output.
    $Output = ("[" + (((Get-Date).ToShortDateString()) + "][" + (Get-Date).ToLongTimeString()) + "][" + $Status + "] " + $Text);
    
    #Output.
    $Output | Out-File -Encoding UTF8 -Force -FilePath $File -Append;
    Return Write-Output $Output;
}

##Author: Nicola Suter, Kudos to Tobias Renström for Get-ADGroupMembership, Test-ADGroupMemberShip and Test-RunningAsSystem
function Get-ADGroupMembership {
	param(
		[parameter(Mandatory = $true)]
		[string]$UserPrincipalName
	)

	process {

		try {

			if ([string]::IsNullOrEmpty($env:USERDNSDOMAIN) -and [string]::IsNullOrEmpty($searchRoot)) {
				Write-Error "Security group filtering won't work because `$env:USERDNSDOMAIN is not available!"
				Write-Warning "You can override your AD Domain in the `$overrideUserDnsDomain variable"
				Write-Output "Security group filtering won't work because `$env:USERDNSDOMAIN is not available!"
				exit 1
			}
			else {

				# if no domain specified fallback to PowerShell environment variable
				if ([string]::IsNullOrEmpty($searchRoot)) {
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

#check if running as system
function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match "S-1-5-18")
	}
}

#Testing if groupmembership is given for user
function Test-GroupMembership {
    [CmdletBinding()]
    param (
        $driveMappingConfig,
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
    Param
    (
        [parameter(Mandatory=$true)][string]$Target
    )

    #Test the connection to target.
    $Result = Test-NetConnection -ComputerName ($Target -replace "https://","") -Port 443 -WarningAction SilentlyContinue;

    #Return result.
    Return $Result;
}

Function Test-ScheduleTask
{
    [CmdletBinding()]
    
    Param
    (
        [parameter(Mandatory=$true)][string]$Name
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
        #Return true.
        Return $true;
    }
    #If the task doesn't exist.
    Else
    {
        #Return false.
        Return $false;
    }
}

Function Test-Module {
	Param([string]$Name)
	try {
		#Write-Host "INFO: Attempting to locate $Module module"
		Write-Output "Module:`t $Name `tSTATUS=SEARCHING"
		Write-Output "Module:`t $Name `tSTATUS=FOUND"
		$ModuleName = Get-InstalledModule -Name $Name -ErrorAction Stop -Verbose:$false
		if ($ModuleName -ne $null) {
			#Write-Host "INFO: Authentication module detected, checking for latest version"
			Write-Output "Module:`t $Name `tSTATUS=VERSIONCHECK"
			$LatestModuleVersion = (Find-Module -Name $Name -ErrorAction Stop -Verbose:$false).Version
			if ($LatestModuleVersion -gt $ModuleName.Version) {
				#Write-Host "INFO: Latest version of $Module module is not installed, attempting to install: $($LatestModuleVersion.ToString())"
				Write-Output "Module:`t $Name `tSTATUS=UPDATING `tVERSION=$($LatestModuleVersion.ToString())"
				$UpdateModuleInvocation = Update-Module -Name $Name -Scope CurrentUser -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
			}
			if ($LatestModuleVersion -eq $ModuleName.Version) {
				#Write-Host "INFO: Latest version of $Module module is installed.
				Write-Output "Module:`t $Name `tSTATUS=PASSED"
			}
		}
	}
	catch [System.Exception] {
		#Write-Host "WARN: Unable to detect $Name module, attempting to install from PSGallery"
		Write-Output "Module:`t $Name `tSTATUS=MISSING"
		try {
            Test-Elevation
			# Install NuGet package provider
			$PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false

            # Set PSRepository as Trusted
			Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
			
			# Install AzureAD module
			Install-Module -Name $Name -Scope AllUsers -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
			#Write-Host "INFO: Successfully installed $Name"
			Write-Output "Module:`t $Name `tSTATUS=INSTALLING"
		}
		catch [System.Exception] {
			#Write-Host "ERROR: An error occurred while attempting to install $Name module. Error message: $($_.Exception.Message)" ; Break
			Write-Output "Module:`t $Name `tSTATUS=FAILED" ; Break
		}
	}
}

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
}

Function Invoke-LoginMSOnline {
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
}