#!/usr/bin/env bash

set -euo pipefail

###############################################################################
# Ubuntu Active Directory Join Script using SSSD and PAM
#
# This script:
#   - Installs required packages
#   - Joins the machine to Active Directory
#   - Configures SSSD
#   - Allows one AD group to authenticate through SSSD
#   - Optimizes SSSD for users with very large AD group memberships
#   - Enables automatic home directory creation on first login
#   - Grants sudo rights to that AD group using numeric GID
#   - Ensures SSH uses PAM
#
# Run as root:
#   sudo bash join-ad-sssd.sh
###############################################################################

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root."
    echo "Try: sudo bash $0"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "This script is intended for Ubuntu/Debian systems using apt."
    exit 1
fi

echo
echo "============================================================"
echo " Ubuntu Active Directory Join with SSSD"
echo "============================================================"
echo

read -rp "Enter the Active Directory domain name, for example corp.example.com: " AD_DOMAIN
read -rp "Enter the AD username allowed to join computers to the domain: " JOIN_USER
read -rp "Enter the AD group allowed to SSH and receive sudo access (MUST BE IN WINDOWS2000 FORMAT): " AD_GROUP
read -rp "Enter the backup local Linux user if AD stops working, optional: " LOCAL_USER

echo
read -rsp "Enter the password for ${JOIN_USER}: " JOIN_PASS
echo
echo

if [[ -z "${AD_DOMAIN}" || -z "${JOIN_USER}" || -z "${JOIN_PASS}" || -z "${AD_GROUP}" ]]; then
    echo "Domain, username, password, and AD group are required."
    exit 1
fi

###############################################################################
# Input validation
###############################################################################

# Prevent config injection or malformed sssd.conf/sudoers comments.
# Do not quote AD group values inside sssd.conf; instead validate input here.
for value_name in AD_DOMAIN JOIN_USER AD_GROUP LOCAL_USER; do
    value="${!value_name}"

    if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
        echo "Error: ${value_name} must not contain newline characters."
        exit 1
    fi

    if printf '%s' "${value}" | grep -q '[[:cntrl:]]'; then
        echo "Error: ${value_name} must not contain control characters."
        exit 1
    fi
done

DOMAIN_LOWER="$(echo "${AD_DOMAIN}" | tr '[:upper:]' '[:lower:]')"
DOMAIN_UPPER="$(echo "${AD_DOMAIN}" | tr '[:lower:]' '[:upper:]')"

SSSD_CONF="/etc/sssd/sssd.conf"
SSHD_CONFIG="/etc/ssh/sshd_config"

timestamp="$(date +%Y%m%d-%H%M%S)"

cleanup() {
    unset JOIN_PASS
}
trap cleanup EXIT

echo "Domain: ${DOMAIN_LOWER}"
echo "Kerberos realm: ${DOMAIN_UPPER}"
echo "Allowed AD group: ${AD_GROUP}"

if [[ -n "${LOCAL_USER}" ]]; then
    echo "Backup local Linux user: ${LOCAL_USER}"
fi

echo

###############################################################################
# Helper functions
###############################################################################

sanitize_filename() {
    # sudo may ignore files in /etc/sudoers.d depending on filename patterns.
    # Avoid dots, spaces, special characters, and trailing separators.
    echo "$1" \
        | tr '.' '_' \
        | tr -cs 'A-Za-z0-9_-' '_' \
        | sed 's/^_*//; s/_*$//'
}

###############################################################################
# Validate Bash shell
###############################################################################

echo "Validating Bash shell..."

if [[ ! -x /bin/bash ]]; then
    echo "Error: /bin/bash does not exist or is not executable."
    exit 1
fi

if ! grep -qx "/bin/bash" /etc/shells; then
    echo "Adding /bin/bash to /etc/shells..."
    echo "/bin/bash" >> /etc/shells
fi

echo "Bash shell validated."
echo

###############################################################################
# Validate optional local backup user
###############################################################################

if [[ -n "${LOCAL_USER}" ]]; then
    echo "Checking backup local Linux user..."

    if id "${LOCAL_USER}" >/dev/null 2>&1; then
        echo "Local user '${LOCAL_USER}' exists."
    else
        echo "Warning: Local user '${LOCAL_USER}' does not exist."
        echo "This script will continue, but you may want to create that account."
    fi

    echo
fi

###############################################################################
# Install required packages
###############################################################################

echo "Installing required packages..."

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y \
    realmd \
    sssd \
    sssd-tools \
    libnss-sss \
    libpam-sss \
    adcli \
    samba-common-bin \
    krb5-user \
    packagekit \
    oddjob \
    oddjob-mkhomedir \
    sudo

echo "Required packages installed."
echo

###############################################################################
# Discover the domain
###############################################################################

echo "Discovering Active Directory domain..."

if ! realm discover "${DOMAIN_LOWER}"; then
    echo
    echo "Unable to discover the domain: ${DOMAIN_LOWER}"
    echo "Check DNS, time synchronization, and network connectivity."
    exit 1
fi

echo
echo "Domain discovery succeeded."
echo

###############################################################################
# Join the domain
###############################################################################

if realm list | grep -qi "^${DOMAIN_LOWER}"; then
    echo "This machine already appears to be joined to ${DOMAIN_LOWER}."
    echo "Skipping domain join."
else
    echo "Joining domain ${DOMAIN_LOWER}..."

    if ! printf '%s\n' "${JOIN_PASS}" | realm join \
        --membership-software=adcli \
        --client-software=sssd \
        --user="${JOIN_USER}" \
        "${DOMAIN_LOWER}"; then

        echo
        echo "Domain join failed."
        echo "Check credentials, DNS, time sync, and AD permissions."
        exit 1
    fi

    echo "Domain join succeeded."
fi

echo

###############################################################################
# Configure SSSD
###############################################################################

echo "Configuring SSSD..."

if [[ -f "${SSSD_CONF}" ]]; then
    cp -a "${SSSD_CONF}" "${SSSD_CONF}.bak.${timestamp}"
    echo "Backed up existing SSSD config to ${SSSD_CONF}.bak.${timestamp}"
fi

cat > "${SSSD_CONF}" <<EOF
[sssd]
domains = ${DOMAIN_LOWER}
config_file_version = 2
services = nss, pam
implicit_pac_responder = False

[nss]
homedir_substring = /home

[pam]

[domain/${DOMAIN_LOWER}]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = ${DOMAIN_UPPER}
realmd_tags = manages-system joined-with-adcli

id_provider = ad
auth_provider = ad
chpass_provider = ad
access_provider = simple

ad_domain = ${DOMAIN_LOWER}
fallback_homedir = /home/%u

# Use short usernames instead of user@domain
use_fully_qualified_names = False

# AD SID to UID/GID mapping
ldap_id_mapping = True

# Do not enumerate AD users/groups
enumerate = False

# Critical performance setting for large AD groups and users with many groups.
# This prevents SSSD from downloading full member lists for large groups.
ignore_group_members = True

# Disable dynamic DNS updates from SSSD.
# This avoids noisy and sometimes slow nsupdate behavior.
dyndns_update = False

# AD group allowed to authenticate through SSSD.
# Do not quote or escape dollar signs here. SSSD expects the literal group name.
simple_allow_groups = ${AD_GROUP}
EOF

chmod 600 "${SSSD_CONF}"
chown root:root "${SSSD_CONF}"

echo "SSSD configuration written to ${SSSD_CONF}."
echo

echo "Validating SSSD configuration..."

if command -v sssctl >/dev/null 2>&1; then
    sssctl config-check || {
        echo "SSSD configuration validation failed."
        exit 1
    }
else
    echo "sssctl not found; skipping SSSD config-check."
fi

systemctl enable sssd
systemctl restart sssd

echo "SSSD restarted."
echo

###############################################################################
# Enable home directory creation on first login
###############################################################################

echo "Enabling automatic home directory creation on first login..."

if command -v pam-auth-update >/dev/null 2>&1; then
    pam-auth-update --enable mkhomedir --force
else
    echo "pam-auth-update not found."
    echo "Adding pam_mkhomedir manually to common-session."

    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
        echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/common-session
    fi
fi

echo "Home directory creation enabled."
echo

###############################################################################
# Configure sudo access for AD group
###############################################################################

echo "Configuring sudo access for AD group..."

SAFE_DOMAIN="$(sanitize_filename "${DOMAIN_LOWER}")"
SAFE_GROUP="$(sanitize_filename "${AD_GROUP}")"
SUDOERS_FILE="/etc/sudoers.d/ad_${SAFE_DOMAIN}_${SAFE_GROUP}"

echo "Resolving AD group GID for sudoers..."

AD_GROUP_ENTRY="$(getent group "${AD_GROUP}" || true)"
AD_GROUP_GID=""

if [[ -n "${AD_GROUP_ENTRY}" ]]; then
    AD_GROUP_GID="$(echo "${AD_GROUP_ENTRY}" | awk -F: '{print $3}')"
fi

if [[ -z "${AD_GROUP_GID}" || ! "${AD_GROUP_GID}" =~ ^[0-9]+$ ]]; then
    echo "Error: Could not resolve numeric GID for AD group '${AD_GROUP}'."
    echo
    echo "Sudoers will not be configured because group-name matching can fail"
    echo "with special AD group names, especially groups beginning with dollar signs."
    echo
    echo "Try manually:"
    printf "  getent group '%s'\n" "${AD_GROUP}"
    exit 1
fi

echo "Resolved AD group '${AD_GROUP}' to GID ${AD_GROUP_GID}."
echo "Using numeric GID in sudoers for reliable matching."

if [[ -f "${SUDOERS_FILE}" ]]; then
    cp -a "${SUDOERS_FILE}" "${SUDOERS_FILE}.bak.${timestamp}"
    echo "Backed up existing sudoers file to ${SUDOERS_FILE}.bak.${timestamp}"
fi

cat > "${SUDOERS_FILE}" <<EOF
# Grant sudo access to AD group ${AD_GROUP} from ${DOMAIN_LOWER}
# Using numeric GID to avoid sudoers parsing issues with AD group names.
%#${AD_GROUP_GID} ALL=(ALL:ALL) ALL
EOF

chmod 0440 "${SUDOERS_FILE}"
chown root:root "${SUDOERS_FILE}"

if ! visudo -cf "${SUDOERS_FILE}"; then
    echo "sudoers validation failed. Removing ${SUDOERS_FILE}."
    rm -f "${SUDOERS_FILE}"
    exit 1
fi

if ! visudo -c; then
    echo
    echo "Warning: Global sudoers validation reported issues."
    echo "Check files under /etc/sudoers.d for bad permissions or syntax."
    echo "Common fix:"
    echo "  chmod 0440 /etc/sudoers.d/FILENAME"
    echo
fi

echo "Sudo access granted to AD group: ${AD_GROUP}"
echo "Sudoers file: ${SUDOERS_FILE}"
echo

###############################################################################
# Ensure SSH uses PAM
###############################################################################

echo "Ensuring SSH uses PAM..."

if [[ -f "${SSHD_CONFIG}" ]]; then
    cp -a "${SSHD_CONFIG}" "${SSHD_CONFIG}.bak.${timestamp}"
fi

if grep -qE '^[#[:space:]]*UsePAM' "${SSHD_CONFIG}"; then
    sed -i 's/^[#[:space:]]*UsePAM.*/UsePAM yes/' "${SSHD_CONFIG}"
else
    echo "UsePAM yes" >> "${SSHD_CONFIG}"
fi

echo "Validating SSH configuration..."

if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh
else
    echo "SSH configuration validation failed."
    echo "Restoring backup."
    cp -a "${SSHD_CONFIG}.bak.${timestamp}" "${SSHD_CONFIG}"
    exit 1
fi

echo "SSH configuration updated."
echo

###############################################################################
# Clear SSSD cache and perform basic checks
###############################################################################

echo "Clearing SSSD cache..."
sss_cache -E || true

echo
echo "Performing basic lookup checks..."
echo

echo "Checking AD group lookup without printing full membership list:"

if getent group "${AD_GROUP}" >/dev/null 2>&1; then
    echo "AD group resolved successfully: ${AD_GROUP}"
    echo "AD group GID: ${AD_GROUP_GID}"
else
    echo "Warning: Could not resolve group '${AD_GROUP}' yet."
    echo "This can happen immediately after joining the domain."
    echo "Try again later with:"
    printf "  getent group '%s'\n" "${AD_GROUP}"
fi

echo
echo "Checking SSSD status:"

if systemctl --no-pager --quiet is-active sssd; then
    echo "SSSD is active."
else
    echo "Warning: SSSD is not active."
    systemctl status sssd --no-pager || true
fi

echo
echo "Current realm configuration:"
realm list || true

echo
echo "============================================================"
echo " Active Directory join and SSSD configuration complete."
echo "============================================================"
echo
echo "Allowed AD group:"
echo "  ${AD_GROUP}"
echo
echo "Allowed AD group numeric GID:"
echo "  ${AD_GROUP_GID}"
echo
echo "Sudoers file:"
echo "  ${SUDOERS_FILE}"
echo

if [[ -n "${LOCAL_USER}" ]]; then
    echo "Backup local Linux user:"
    echo "  ${LOCAL_USER}"
    echo
fi

echo "AD users in that group should now be able to SSH in."
echo "Their home directories will be created automatically on first login."
echo "Members of that AD group will also have sudo access."
echo
echo "Useful test commands:"
echo "  getent passwd some_ad_user"
printf "  getent group '%s'\n" "${AD_GROUP}"
echo "  id -u some_ad_user"
echo "  id -g some_ad_user"
echo "  sudo -l -U some_ad_user"
echo "  sudo sssctl user-checks some_ad_user -s sshd"
echo "  ssh some_ad_user@this-server"
echo
echo "Important:"
echo "  Local Linux accounts are not blocked by this script."
echo "  AD authentication through SSSD is limited to the configured AD group."
echo "  Avoid running plain 'id some_ad_user' for users with huge AD memberships,"
echo "  because it may attempt to resolve a very large group list."
echo
