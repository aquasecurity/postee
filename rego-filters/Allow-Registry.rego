package postee


ArrayPermitedRegistry := {"Aqua"} #The list of registry name that triggers the integration.

default PermitRegistry = false
PermitRegistry = true{ 
     contains(input.registry, ArrayPermitedRegistry[_])
}

allow{
   PermitRegistry
}
