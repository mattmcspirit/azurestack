# Login to Environment
Connect-AzureAD

# Set password profile
$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
$PasswordProfile.Password = "Pa55w.rd"

# How many users to create?
$CreateUsers = 10

for ($X = 1; $X -le $CreateUsers; $X++) {
    New-AzureADUser -AccountEnabled $True -DisplayName "OlympiaDP$X" -PasswordProfile $PasswordProfile -MailNickName "OlympiaDP$X" -UserPrincipalName "OlympiaDP$X@asicdc.com"
    New-AzureADUser -AccountEnabled $True -DisplayName "OlympiaUser$X" -PasswordProfile $PasswordProfile -MailNickName "OlympiaUser$X" -UserPrincipalName "OlympiaUser$X@asicdc.com"
}


# Clean Up
for ($X = 1; $X -le $CreateUsers; $X++) {
    Remove-AzureADUser -ObjectId "OlympiaDP$X@asicdc.com"
    Remove-AzureADUser -ObjectId "OlympiaUser$X@asicdc.com"
}