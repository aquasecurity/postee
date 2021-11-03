package postee


ArrayIgnoreRegistry := {"all", "Aqua"} #Comma separated list of registries that will be ignored by the integration

default IgnoreRegistry = true
IgnoreRegistry = false{ 
     contains(input.registry, ArrayIgnoreRegistry[_])
}

allow{
   IgnoreRegistry
}