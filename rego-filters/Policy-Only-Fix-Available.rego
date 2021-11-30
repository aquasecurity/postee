package postee

#Trigger the integration only if image has a vulnerability with fix available (true). 
#If set to false, integration will be triggered even if all vulnerabilities has no fix available
default PermitOnlyFixAvailable = false
PermitOnlyFixAvailable = true{ 
     is_string(input.resources[_].vulnerabilities[_].fix_version)
}

allow{
	PermitOnlyFixAvailable
}
