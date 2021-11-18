package postee


ArrayPermitedImageNames := {"ubuntu", "busybox"}#Comma separated list of images that will trigger the integration.

default PermitImageNames = false
PermitImageNames = true{ 
     contains(input.image, ArrayPermitedImageNames[_])
}

allow{
   PermitImageNames
}