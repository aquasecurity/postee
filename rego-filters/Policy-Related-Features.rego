package postee
import future.keywords.in
#Constants vulnerability values. Don't remove it!
allVulnerability := {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

ArrayPermitedImageNames := {"ubuntu", "busybox"} #Comma separated list of images that will trigger the integration.
ArrayIgnoredImageNames := {"alpine", "postgres"}  #List of comma separated images that will be ignored by the integration
ArrayPermitedRegistry := {"Aqua"} #The list of registry name that triggers the integration.
ArrayIgnoreRegistry := {"Aqua"} #Comma separated list of registries that will be ignored by the integration
Vulnerability := "low" #The minimum vulnerability severity that triggers the integration.


default PermitImageNames = false
PermitImageNames = true{ 
     contains(input.image, ArrayPermitedImageNames[_])
}

default IgnoreImageNames = true
IgnoreImageNames = false{ 
     contains(input.image, ArrayIgnoredImageNames[_])
}

default PermitRegistry = false
PermitRegistry = true{ 
     contains(input.registry, ArrayPermitedRegistry[_])
}

default IgnoreRegistry = true
IgnoreRegistry = false{ 
     contains(input.registry, ArrayIgnoreRegistry[_])
}

default PermitMinVulnerability = false
PermitMinVulnerability = true{ 
     some i, val in allVulnerability
		val >= allVulnerability[Vulnerability]
		input.vulnerability_summary[i] > 0
}

default PermitOnlyFixAvailable = false
PermitOnlyFixAvailable = true{ 
     is_string(input.resources[_].vulnerabilities[_].fix_version)
}

#Select the required functions. The functions will be conjunct as a logical "AND". 
allow{
#     PermitImageNames
#     IgnoreImageNames
#     PermitRegistry
#     IgnoreRegistry
#     PermitMinVulnerability
#     PermitOnlyFixAvailable
}




