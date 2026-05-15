# join-ad-sssd

A bash script for Debian/Ubuntu distros to join active directory and configure access


This script:
- Installs required packages
- Joins the machine to Active Directory
- Configures SSSD
- Allows one AD group to authenticate through SSSD - MAKE SURE TO USE the WINDOWS2000 name/format of the group
- Optimizes SSSD for users with very large AD group memberships
- Enables automatic home directory creation on first login
- Grants sudo rights to that AD group using numeric GID
- Ensures SSH uses PAM



The script should be run as root or sudo

The script is interactive and will ask for the domain, the username and password for the binding AD user, the AD Group to allow in, and the backup local user is AD fails.

