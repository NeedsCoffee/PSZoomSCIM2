'modules','lists','logs','certs' | %{New-Item -Name $_ -ItemType Directory -ErrorAction SilentlyContinue}
Save-Module -Name Logging,Microsoft.Graph.Authentication,Microsoft.Graph.Users,Microsoft.Graph.Groups -Path .\modules\
