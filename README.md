# ACL-TCAM-Analyser

Scripts to determine the TCAM resources required for a given access-list on the Cisco 8000 series platforms.
For IPv4 access-lists use the acltcamcheck.py script.
For IPv6 access-lists use the v6acltcamcheck.py script.

These scripts do not support for hybrid ACLs with object groups.

To use one of the scripts create a file in the same folder as the script called "sample-acl" and copy your ACL into that file. Then run the script.

Note to get the actual TCAM resource usage for ingress ACLs on the router itself, the command "show controllers npu resources ingressacltcam location <X/X>" can be used.
