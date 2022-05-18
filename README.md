# ACL-TCAM-Analyser
Script to determine the TCAM resources required for a given access-list on the Cisco 8000 series platforms.
Script currently only supports ingress IPv4 ACLs. 
No support for hybrid ACLs with object groups.
To use the script create a file in the same folder as the script called "sample-acl" and copy your ACL into that file. Then run the script.

Note to get the actual TCAM resource usage for ingress ACLs on the router itself, the command "show controllers npu resources ingressacltcam location <X/X>" can be used.
