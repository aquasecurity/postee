package postee


ArrayIgnoredImageNames := {"ignor"} #List of comma separated images that will be ignored by the integration

default IgnoreImageNames = true
IgnoreImageNames = false{ 
     contains(input.image, ArrayIgnoredImageNames[_])
}

allow{
   IgnoreImageNames
}