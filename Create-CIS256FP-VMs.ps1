#Create-Topology.ps1 written by Kevin Azevedo on 8/29/17
#A Script to create a virtual network and associated virtual machines to support a CIS course
#

#Initialization
$vdiskPath = "D:\Images" #The path to the virtual disk images
$OSImages = @{ "W10" = "W10-Base.vhdx"; "SVR2019G" = "2K19-GUI-Base.vhdx"}  #Map the OS names to the image files
$line = "=" * 66

#Create-VM a function to create a new virtual machine or a clone and any associated switches
function Create-VM {
Param (
    [parameter(Mandatory=$true)]
    [string] $VMName,   
    [parameter(Mandatory=$true)] 
    [ValidateSet("W10","SVR2019G","Other")]
    [String] $OS,
    [parameter(Mandatory=$false)]
    [int64] $RAM = 2GB,
    [parameter(Mandatory=$false)]
    [switch] $Clone = $true,
    [parameter(Mandatory=$true)]
    [string] $Switch   
)

Write-Host "Creating a $OS $vmtype virtual machine named $name using the image $diskImage with "+ $RAM/1GB + "GB of memory connected to the $switch switch!" -ForegroundColor DarkGreen
$vmpath = "D:\VM"
$vhdpath = "D:\VHD"
#Create the virtual switch if it does not exist
if (!(Get-VMSwitch -Name $switch -ErrorAction SilentlyContinue )) 
{ 
    Write-host -ForegroundColor Yellow "Creating private virtual switch $switch..."
    Write-host -ForegroundColor Yellow $line
    New-VMSwitch -Name $switch -SwitchType Private
}

#Create the virtual machine
Write-Host -ForegroundColor Yellow "Creating virtual machine..."
New-VM -Name $vmname -MemoryStartupBytes $RAM -Generation 2 -NoVHD -SwitchName $switch
Set-VMNetworkAdapter -VMName $VMName -DeviceNaming On #Name the network adapter after the switch and propagate to the VM

#This allows the student and a script to see which switch the network adapter is connected to
Rename-VMNetworkAdapter -VMName $VMName -NewName $switch

#Automatic checkpoints just slow things down and cause students to ask questions
Set-VM -Name $VMName -AutomaticCheckpointsEnabled $false

if ($Clone)
{
    $diskImage = $OSImages.$OS
    New-VHD -Path "$vhdpath\$vmname.vhdx" -ParentPath "$vdiskPath\$diskImage" -Differencing
    Add-VMHardDiskDrive -VMName $vmname -Path "$vhdpath\$vmname.vhdx"
 }
 else
 {
    New-VHD -Path "$vhdpath\$vmname.vhdx" -Dynamic
    Add-VMHardDiskDrive -VMName $vmname -Path "$vhdpath\$vmname.vhdx"
 }

#Set the boot order for the virtual machine
Set-VMFirmware -VMName $vmname -FirstBootDevice (Get-VMHardDiskDrive -VMName $vmname)

}

function Add-Disk ([int] $Number, [string] $VMName)
{
    if (!(Get-VM -Name $vmname)) { Write-Host -ForegroundColor Cyan "VM not found"; exit }
    for ($i=1; $i -le $number; $i++)
    {
        $disk = New-VHD -Dynamic -Path ("$vhdpath\$vmname" + "-" + "disk$i.vhdx") -SizeBytes 127GB
        Add-VMHardDiskDrive -VMName $vmname -Path $disk.Path
    } 
}

Function Add-NetworkAdapter ([string] $VMName, [string] $Switch)
{
    #Create the virtual switch if it does not exist
    if (!(Get-VMSwitch -Name $Switch -ErrorAction SilentlyContinue )) 
    { 
        Write-host -ForegroundColor Yellow "Creating private virtual switch $Switch..."
        Write-host -ForegroundColor Yellow $line
        New-VMSwitch -Name $Switch -SwitchType Private
    }
    Add-VMNetworkAdapter -VMName $VMName -SwitchName $switch -Name $switch -DeviceNaming On
    
}

#
#Main Loop - this is where you create the virtual machines and 
$vmnames = @("CIS256-FP-DC1")

foreach ($vmname in $vmnames)
{
    Create-VM -VMName $vmname -RAM 2GB -OS SVR2019G -Clone -switch WANPT
}

$vmnames = @("CIS256-FP-Client")
foreach ($vmname in $vmnames)
{
    Create-VM -VMName $vmname -RAM 2GB -OS W10 -Clone -switch WANPT
}

Get-VM -Name CIS256-FP* | Set-VM -DynamicMemory 
