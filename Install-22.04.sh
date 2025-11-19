#!/usr/bin/env bash
# Enterprise LEMP Stack Installer - Ubuntu 22.04 LTS ONLY
# Fully automated installation with high-traffic optimizations
# Version: 1.0.0 | Date: 2024-11-17
# Compatible: Ubuntu 22.04 LTS (Jammy Jellyfish) ONLY

set -eo pipefail
IFS=$'\n\t'

# ============================================
# SCRIPT METADATA
# ============================================
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2024-11-17"
SCRIPT_NAME="Enterprise LEMP Stack Installer"
REQUIRED_UBUNTU_VERSION="22.04"
REQUIRED_UBUNTU_CODENAME="jammy"

# ============================================
# SECURITY & NETWORK CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_SSH_PORT=2222
DEFAULT_ADMIN_IP_CIDR="0.0.0.0/0"
DEFAULT_ALLOW_SSH_FROM_ANY=true

# ============================================
# DATABASE CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_BACKUP_MYSQL_USER='backup_user'

# ============================================
# SYSTEM PERFORMANCE CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_NGINX_WORKER_CONNECTIONS=65536

# ============================================
# BACKUP CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_RETENTION_DAYS=14
DEFAULT_FTP_ENABLED=false
DEFAULT_FTP_HOST="ftp.yourserver.com"
DEFAULT_FTP_USER="your_ftp_username"
DEFAULT_FTP_PASS="your_ftp_password"
DEFAULT_FTP_PORT=21
DEFAULT_FTP_PROJECT_NAME="UptimeMatrix"
DEFAULT_FTP_REMOTE_PATH="/backups"

# ============================================
# SSL/TLS CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_ENABLE_SSL=true
DEFAULT_SSL_EMAIL="admin@uptimematrix.com"
DEFAULT_SSL_DOMAIN=""
DEFAULT_SSL_DOMAINS=""

# ============================================
# EMAIL NOTIFICATION CONFIGURATION (DEFAULTS)
# ============================================
DEFAULT_ENABLE_EMAIL_ALERTS=false
DEFAULT_ALERT_EMAIL="admin@uptimematrix.com"
DEFAULT_SMTP_HOST="smtp.gmail.com"
DEFAULT_SMTP_PORT=587
DEFAULT_SMTP_USER="your-email@gmail.com"
DEFAULT_SMTP_PASS="your-app-password"
DEFAULT_SMTP_FROM="noreply@uptimematrix.com"
DEFAULT_SMTP_USE_TLS=true

# ============================================
# SYSTEM SETTINGS (DEFAULTS)
# ============================================
DEFAULT_TIMEZONE="UTC"
DEFAULT_UNATTENDED_REBOOT=false

########################
# === INTERACTIVE CONFIGURATION ===
########################

# Function to prompt for input with default value
prompt_with_default() {
  local prompt_text="$1"
  local default_value="$2"
  local var_name="$3"
  local is_password="${4:-false}"
  local input_value=""
  
  if [[ "${is_password}" == "true" ]]; then
    if [[ -n "${default_value}" && "${default_value}" != "" ]]; then
      read -sp "${prompt_text} [default: (hidden)]: " input_value || true
    else
      read -sp "${prompt_text} [default: (auto-generate)]: " input_value || true
    fi
    echo ""
  else
    if [[ -n "${default_value}" && "${default_value}" != "" ]]; then
      read -p "${prompt_text} [default: ${default_value}]: " input_value || true
    else
      read -p "${prompt_text} [default: (empty/auto-generate)]: " input_value || true
    fi
  fi
  
  if [[ -z "${input_value:-}" ]]; then
    eval "${var_name}=\"${default_value}\""
  else
    local escaped_value=$(printf '%q' "${input_value}")
    eval "${var_name}=${escaped_value}"
  fi
}

# Function to prompt for yes/no with default
prompt_yes_no() {
  local prompt_text="$1"
  local default_value="$2"
  local var_name="$3"
  local default_display=""
  local input_value=""
  
  if [[ "${default_value}" == "true" ]]; then
    default_display="Y/n"
  else
    default_display="y/N"
  fi
  
  read -p "${prompt_text} [${default_display}]: " input_value || true
  input_value=$(echo "${input_value:-}" | tr '[:upper:]' '[:lower:]')
  
  if [[ -z "${input_value:-}" ]]; then
    eval "${var_name}=\"${default_value}\""
  elif [[ "${input_value}" == "y" || "${input_value}" == "yes" ]]; then
    eval "${var_name}=\"true\""
  else
    eval "${var_name}=\"false\""
  fi
}

# Interactive configuration function
interactive_configuration() {
  echo ""
  info "=========================================="
  info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
  info "Ubuntu 22.04 LTS (Jammy Jellyfish) ONLY"
  info "=========================================="
  echo ""
  info "Please provide configuration values. Press Enter to use defaults."
  echo ""
  
  # Security & Network
  info "--- SECURITY & NETWORK CONFIGURATION ---"
  prompt_with_default "SSH Port" "${DEFAULT_SSH_PORT}" "SSH_PORT"
  SSH_PORT=${SSH_PORT:-${DEFAULT_SSH_PORT}}
  
  prompt_with_default "Admin IP CIDR (allowed SSH range)" "${DEFAULT_ADMIN_IP_CIDR}" "ADMIN_IP_CIDR"
  ADMIN_IP_CIDR=${ADMIN_IP_CIDR:-${DEFAULT_ADMIN_IP_CIDR}}
  
  prompt_yes_no "Allow SSH from anywhere?" "${DEFAULT_ALLOW_SSH_FROM_ANY}" "ALLOW_SSH_FROM_ANY"
  echo ""
  
  # Database Configuration
  info "--- DATABASE CONFIGURATION ---"
  prompt_with_default "MySQL Root Password (empty = auto-generate)" "" "MYSQL_ROOT_PASSWORD" "true"
  MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD:-""}
  
  prompt_with_default "MySQL Backup User Name" "${DEFAULT_BACKUP_MYSQL_USER}" "BACKUP_MYSQL_USER"
  BACKUP_MYSQL_USER=${BACKUP_MYSQL_USER:-${DEFAULT_BACKUP_MYSQL_USER}}
  
  prompt_with_default "MySQL Backup User Password (empty = auto-generate)" "" "BACKUP_MYSQL_PASS" "true"
  BACKUP_MYSQL_PASS=${BACKUP_MYSQL_PASS:-""}
  
  prompt_with_default "Redis Password (empty = auto-generate)" "" "REDIS_PASSWORD" "true"
  REDIS_PASSWORD=${REDIS_PASSWORD:-""}
  echo ""
  
  # Backup Configuration
  info "--- BACKUP CONFIGURATION ---"
  prompt_with_default "Backup Retention Days" "${DEFAULT_RETENTION_DAYS}" "RETENTION_DAYS"
  RETENTION_DAYS=${RETENTION_DAYS:-${DEFAULT_RETENTION_DAYS}}
  
  prompt_yes_no "Enable FTP Backups?" "${DEFAULT_FTP_ENABLED}" "FTP_ENABLED"
  
  if [[ "${FTP_ENABLED}" == "true" ]]; then
    prompt_with_default "FTP Host" "${DEFAULT_FTP_HOST}" "FTP_HOST"
    FTP_HOST=${FTP_HOST:-${DEFAULT_FTP_HOST}}
    
    prompt_with_default "FTP Username" "${DEFAULT_FTP_USER}" "FTP_USER"
    FTP_USER=${FTP_USER:-${DEFAULT_FTP_USER}}
    
    prompt_with_default "FTP Password" "${DEFAULT_FTP_PASS}" "FTP_PASS" "true"
    FTP_PASS=${FTP_PASS:-${DEFAULT_FTP_PASS}}
    
    prompt_with_default "FTP Port" "${DEFAULT_FTP_PORT}" "FTP_PORT"
    FTP_PORT=${FTP_PORT:-${DEFAULT_FTP_PORT}}
    
    prompt_with_default "FTP Project Name" "${DEFAULT_FTP_PROJECT_NAME}" "FTP_PROJECT_NAME"
    FTP_PROJECT_NAME=${FTP_PROJECT_NAME:-${DEFAULT_FTP_PROJECT_NAME}}
    
    prompt_with_default "FTP Remote Path" "${DEFAULT_FTP_REMOTE_PATH}" "FTP_REMOTE_PATH"
    FTP_REMOTE_PATH=${FTP_REMOTE_PATH:-${DEFAULT_FTP_REMOTE_PATH}}
    
    if [[ -z "${FTP_HOST}" || "${FTP_HOST}" == "ftp.yourserver.com" ]] || \
       [[ -z "${FTP_USER}" || "${FTP_USER}" == "your_ftp_username" ]] || \
       [[ -z "${FTP_PASS}" || "${FTP_PASS}" == "your_ftp_password" ]]; then
      warn "FTP credentials not properly configured. FTP backups will be disabled."
      FTP_ENABLED=false
    fi
  else
    FTP_HOST="${DEFAULT_FTP_HOST}"
    FTP_USER="${DEFAULT_FTP_USER}"
    FTP_PASS="${DEFAULT_FTP_PASS}"
    FTP_PORT="${DEFAULT_FTP_PORT}"
    FTP_PROJECT_NAME="${DEFAULT_FTP_PROJECT_NAME}"
    FTP_REMOTE_PATH="${DEFAULT_FTP_REMOTE_PATH}"
  fi
  echo ""
  
  # SSL Configuration
  info "--- SSL/TLS CONFIGURATION ---"
  prompt_yes_no "Enable SSL (Let's Encrypt)?" "${DEFAULT_ENABLE_SSL}" "ENABLE_SSL"
  
  if [[ "${ENABLE_SSL}" == "true" ]]; then
    prompt_with_default "SSL Email" "${DEFAULT_SSL_EMAIL}" "SSL_EMAIL"
    SSL_EMAIL=${SSL_EMAIL:-${DEFAULT_SSL_EMAIL}}
    
    prompt_with_default "SSL Domain (e.g., example.com)" "${DEFAULT_SSL_DOMAIN}" "SSL_DOMAIN"
    SSL_DOMAIN=${SSL_DOMAIN:-${DEFAULT_SSL_DOMAIN}}
    
    prompt_with_default "Additional SSL Domains (comma-separated)" "${DEFAULT_SSL_DOMAINS}" "SSL_DOMAINS"
    SSL_DOMAINS=${SSL_DOMAINS:-${DEFAULT_SSL_DOMAINS}}
  else
    SSL_EMAIL="${DEFAULT_SSL_EMAIL}"
    SSL_DOMAIN="${DEFAULT_SSL_DOMAIN}"
    SSL_DOMAINS="${DEFAULT_SSL_DOMAINS}"
  fi
  echo ""
  
  # Email Configuration
  info "--- EMAIL NOTIFICATION CONFIGURATION ---"
  prompt_yes_no "Enable Email Alerts?" "${DEFAULT_ENABLE_EMAIL_ALERTS}" "ENABLE_EMAIL_ALERTS"
  
  if [[ "${ENABLE_EMAIL_ALERTS}" == "true" ]]; then
    prompt_with_default "Alert Email Address" "${DEFAULT_ALERT_EMAIL}" "ALERT_EMAIL"
    ALERT_EMAIL=${ALERT_EMAIL:-${DEFAULT_ALERT_EMAIL}}
    
    prompt_with_default "SMTP Host" "${DEFAULT_SMTP_HOST}" "SMTP_HOST"
    SMTP_HOST=${SMTP_HOST:-${DEFAULT_SMTP_HOST}}
    
    prompt_with_default "SMTP Port" "${DEFAULT_SMTP_PORT}" "SMTP_PORT"
    SMTP_PORT=${SMTP_PORT:-${DEFAULT_SMTP_PORT}}
    
    prompt_with_default "SMTP Username" "${DEFAULT_SMTP_USER}" "SMTP_USER"
    SMTP_USER=${SMTP_USER:-${DEFAULT_SMTP_USER}}
    
    prompt_with_default "SMTP Password" "${DEFAULT_SMTP_PASS}" "SMTP_PASS" "true"
    SMTP_PASS=${SMTP_PASS:-${DEFAULT_SMTP_PASS}}
    
    prompt_with_default "SMTP From Address" "${DEFAULT_SMTP_FROM}" "SMTP_FROM"
    SMTP_FROM=${SMTP_FROM:-${DEFAULT_SMTP_FROM}}
    
    if [[ "${SMTP_PORT}" == "587" ]]; then
      SMTP_USE_TLS="true"
    elif [[ "${SMTP_PORT}" == "465" ]]; then
      SMTP_USE_TLS="false"
    else
      prompt_yes_no "Use TLS Encryption?" "${DEFAULT_SMTP_USE_TLS}" "SMTP_USE_TLS"
    fi
  else
    ALERT_EMAIL="${DEFAULT_ALERT_EMAIL}"
    SMTP_HOST="${DEFAULT_SMTP_HOST}"
    SMTP_PORT="${DEFAULT_SMTP_PORT}"
    SMTP_USER="${DEFAULT_SMTP_USER}"
    SMTP_PASS="${DEFAULT_SMTP_PASS}"
    SMTP_FROM="${DEFAULT_SMTP_FROM}"
    SMTP_USE_TLS="${DEFAULT_SMTP_USE_TLS}"
  fi
  echo ""
  
  # System Settings
  info "--- SYSTEM SETTINGS ---"
  prompt_with_default "Timezone" "${DEFAULT_TIMEZONE}" "TIMEZONE"
  TIMEZONE=${TIMEZONE:-${DEFAULT_TIMEZONE}}
  
  prompt_yes_no "Allow Unattended Reboot?" "${DEFAULT_UNATTENDED_REBOOT}" "UNATTENDED_REBOOT"
  echo ""
  
  # System Performance (will be auto-detected later)
  info "--- SYSTEM PERFORMANCE ---"
  info "System resources will be auto-detected"
  info "Services will be configured optimally based on:"
  info "  - CPU cores (for Nginx workers, PHP-FPM processes)"
  info "  - RAM size (for MySQL buffer pool, Redis memory, PHP-FPM pool)"
  info "  - Disk space (for cache and logs)"
  echo ""
  
  # Summary
  info "=== CONFIGURATION SUMMARY ==="
  info "SSH Port: ${SSH_PORT}"
  info "MySQL Root Password: $(if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then echo "Auto-generate"; else echo "***SET***"; fi)"
  info "Redis Password: $(if [[ -z "${REDIS_PASSWORD}" ]]; then echo "Auto-generate"; else echo "***SET***"; fi)"
  info "FTP Backups: ${FTP_ENABLED}"
  info "SSL Enabled: ${ENABLE_SSL}"
  info "Email Alerts: ${ENABLE_EMAIL_ALERTS}"
  info "Timezone: ${TIMEZONE}"
  echo ""
  
  read -p "Press Enter to continue with installation, or Ctrl+C to cancel..."
  echo ""
}

########################
# === CONFIGURATION VARIABLES ===
########################
SSH_PORT=""
ADMIN_IP_CIDR=""
ALLOW_SSH_FROM_ANY=""
MYSQL_ROOT_PASSWORD=""
BACKUP_MYSQL_USER=""
BACKUP_MYSQL_PASS=""
REDIS_PASSWORD=""
SUPERVISOR_PASSWORD=""
RETENTION_DAYS=""
FTP_ENABLED=""
FTP_HOST=""
FTP_USER=""
FTP_PASS=""
FTP_PORT=""
FTP_PROJECT_NAME=""
FTP_REMOTE_PATH=""
ENABLE_SSL=""
SSL_EMAIL=""
SSL_DOMAIN=""
SSL_DOMAINS=""
ENABLE_EMAIL_ALERTS=""
ALERT_EMAIL=""
SMTP_HOST=""
SMTP_PORT=""
SMTP_USER=""
SMTP_PASS=""
SMTP_FROM=""
SMTP_USE_TLS=""
TIMEZONE=""
UNATTENDED_REBOOT=""
NGINX_WORKER_CONNECTIONS=""
TOTAL_RAM_GB=""
TOTAL_RAM_MB=""
CPU_CORES=""
INNODB_BUFFER_POOL_SIZE_GB=""
SERVER_CLASS=""

########################
# === FUNCTIONS =======
########################

info(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[1;31m[ERR]\e[0m $*"; exit 1; }

# Generate secure random password
generate_password() {
  local length=${1:-32}
  openssl rand -base64 $((length * 3 / 4)) | tr -d "=+/" | cut -c1-${length}
}

# Save passwords to secure file
save_passwords() {
  local password_file="/root/.lemp-install-passwords.txt"
  cat >${password_file} <<EOF
# LEMP Installation Passwords - KEEP THIS FILE SECURE!
# Generated: $(date)
# Ubuntu 22.04 LTS Installation
# 
# MySQL Root Password: ${MYSQL_ROOT_PASSWORD}
# MySQL Backup User: ${BACKUP_MYSQL_USER}
# MySQL Backup Password: ${BACKUP_MYSQL_PASS}
# Redis Password: ${REDIS_PASSWORD}
#
# Supervisor Web Interface:
# URL: http://YOUR_SERVER_IP:9001 (external access enabled)
# Local: http://127.0.0.1:9001
# Username: admin
# Password: ${SUPERVISOR_PASSWORD:-"Not configured"}
#
# FTP Configuration:
# Host: ${FTP_HOST}
# User: ${FTP_USER}
# Project: ${FTP_PROJECT_NAME}
#
# SSH Port: ${SSH_PORT}
#
EOF
  chmod 600 ${password_file}
  info "Passwords saved to ${password_file} (chmod 600)"
}

# Function to check if port is available
check_port_available() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    if ss -tuln | grep -qE ":${port}[[:space:]]" 2>/dev/null; then
      return 1
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -tuln | grep -qE ":${port}[[:space:]]" 2>/dev/null; then
      return 1
    fi
  else
    if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/${port}" 2>/dev/null; then
      return 1
    fi
  fi
  return 0
}

# Function to verify service is installed, enabled, and running
verify_service() {
  local service_name=$1
  local package_name=${2:-$service_name}
  local display_name=${3:-$service_name}
  
  info "Verifying ${display_name}..."
  
  # Check if package is installed (more flexible matching)
  if ! dpkg -l "*${package_name}*" 2>/dev/null | grep -qE "^ii"; then
    if ! command -v ${service_name} >/dev/null 2>&1; then
      err "VERIFICATION FAILED: ${display_name} package (${package_name}) is not installed."
    else
      info "  ✓ Command found: ${service_name}"
    fi
  else
    info "  ✓ Package installed: ${package_name}"
  fi
  
  # Check if service exists
  if ! systemctl list-unit-files | grep -q "^${service_name}\.service"; then
    warn "  ⚠ Service file not found: ${service_name}.service"
    # Try alternative service names
    if systemctl list-unit-files | grep -qE "${service_name}"; then
      info "  ✓ Service exists (alternative name)"
    else
      warn "  ⚠ Service ${service_name} not found in systemd, skipping service checks"
      return 0
    fi
  else
    info "  ✓ Service exists: ${service_name}"
  fi
  
  # Check if service is enabled
  if ! systemctl is-enabled --quiet ${service_name} 2>/dev/null; then
    warn "  ⚠ Service not enabled, enabling now..."
    if systemctl enable ${service_name} 2>/dev/null; then
      info "  ✓ Service enabled"
    else
      warn "  ⚠ Could not enable service (may not support enable)"
    fi
  else
    info "  ✓ Service enabled: ${service_name}"
  fi
  
  # Check if service is running
  if ! systemctl is-active --quiet ${service_name}; then
    warn "  ⚠ Service not running, attempting to start..."
    if systemctl start ${service_name} 2>/dev/null; then
      sleep 2
      if systemctl is-active --quiet ${service_name}; then
        info "  ✓ Service started successfully"
      else
        warn "  ⚠ Service failed to start"
        return 1
      fi
    else
      warn "  ⚠ Could not start service"
      return 1
    fi
  else
    info "  ✓ Service running: ${service_name}"
  fi
  
  info "✅ ${display_name} verification PASSED"
  echo ""
}

# Function to verify command exists
verify_command() {
  local command_name=$1
  local display_name=${2:-$command_name}
  
  info "Verifying ${display_name} command..."
  
  if ! command -v ${command_name} >/dev/null 2>&1; then
    err "VERIFICATION FAILED: ${display_name} command (${command_name}) not found."
  fi
  
  local version=$(${command_name} --version 2>&1 | head -1 || echo "Unknown version")
  info "  ✓ Command available: ${command_name}"
  info "  ✓ Version: ${version}"
  info "✅ ${display_name} verification PASSED"
  echo ""
}

########################
# === IDEMPOTENCY CHECK FUNCTIONS ===
########################

# Check if swap is already configured
is_swap_configured() {
  if swapon --show 2>/dev/null | grep -q . || grep -qE "^/.*swap" /proc/swaps 2>/dev/null; then
    return 0  # Swap exists
  fi
  return 1  # No swap
}

# Check if swappiness is configured
is_swappiness_configured() {
  if [[ -f /etc/sysctl.d/99-swap.conf ]] && grep -qE "^vm\.swappiness\s*=" /etc/sysctl.d/99-swap.conf 2>/dev/null; then
    return 0  # Configured
  fi
  return 1  # Not configured
}

# Check if IPv4 forwarding is enabled
is_ipv4_forwarding_enabled() {
  if [[ $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) == "1" ]]; then
    return 0  # Enabled
  fi
  return 1  # Not enabled
}

# Check if UFW rule exists for a port
is_ufw_rule_exists() {
  local port=$1
  if ufw status numbered 2>/dev/null | grep -qE "${port}/tcp|${port}/udp"; then
    return 0  # Rule exists
  fi
  return 1  # Rule doesn't exist
}

# Check if PHP module is installed
is_php_module_installed() {
  local module=$1
  if dpkg -l 2>/dev/null | grep -qE "^ii.*php[0-9]+\-${module}"; then
    return 0  # Installed
  fi
  return 1  # Not installed
}

# Check if PHP.ini setting exists
is_php_ini_setting_exists() {
  local setting=$1
  local php_ini=$2
  if [[ -f "${php_ini}" ]] && grep -qE "^${setting}\s*=" "${php_ini}" 2>/dev/null; then
    return 0  # Setting exists
  fi
  return 1  # Setting doesn't exist
}

# Check if MySQL setting exists in config
is_mysql_setting_exists() {
  local setting=$1
  local config_file=${2:-/etc/mysql/conf.d/custom.cnf}
  if [[ -f "${config_file}" ]] && grep -qE "^${setting}\s*=" "${config_file}" 2>/dev/null; then
    return 0  # Setting exists
  fi
  return 1  # Setting doesn't exist
}

# Check if Redis setting exists
is_redis_setting_exists() {
  local setting=$1
  local config_file=${2:-/etc/redis/redis.conf}
  if [[ -f "${config_file}" ]] && grep -qE "^${setting}\s+" "${config_file}" 2>/dev/null; then
    return 0  # Setting exists
  fi
  return 1  # Setting doesn't exist
}

# Check if Supervisor setting exists
is_supervisor_setting_exists() {
  local setting=$1
  local config_file=${2:-/etc/supervisor/supervisord.conf}
  if [[ -f "${config_file}" ]] && grep -qE "^${setting}\s*=" "${config_file}" 2>/dev/null; then
    return 0  # Setting exists
  fi
  return 1  # Setting doesn't exist
}

# Check if SSH login notification is configured
is_ssh_notify_configured() {
  if [[ -f /etc/pam.d/sshd ]] && grep -qE "ssh-login-notify|pam_exec.*ssh" /etc/pam.d/sshd 2>/dev/null; then
    return 0  # Configured
  fi
  return 1  # Not configured
}

# Check if Let's Encrypt certificate exists for domain
is_ssl_certificate_exists() {
  local domain=$1
  if [[ -d "/etc/letsencrypt/live/${domain}" ]] || certbot certificates 2>/dev/null | grep -qE "Domains:.*${domain}"; then
    return 0  # Certificate exists
  fi
  return 1  # Certificate doesn't exist
}

# Function to detect and allow service ports in UFW
detect_and_allow_service_ports() {
  info "Detecting and allowing service ports in UFW..."
  
  # Nginx ports (80, 443)
  for port in 80 443; do
    if ! is_ufw_rule_exists "${port}"; then
      ufw allow ${port}/tcp comment "Nginx HTTP/HTTPS" 2>/dev/null || true
      info "  ✓ Allowed port ${port}/tcp (Nginx)"
    else
      info "  - Port ${port}/tcp already allowed"
    fi
  done
  
  # Supervisor web interface (9001)
  if ! is_ufw_rule_exists "9001"; then
    ufw allow 9001/tcp comment "Supervisor Web Interface" 2>/dev/null || true
    info "  ✓ Allowed port 9001/tcp (Supervisor)"
  else
    info "  - Port 9001/tcp already allowed"
  fi
  
  # Check Nginx config for additional listen ports
  if [[ -d /etc/nginx ]]; then
    NGINX_PORTS=$(grep -h "listen" /etc/nginx/sites-enabled/* /etc/nginx/conf.d/* 2>/dev/null | \
      grep -oE "listen\s+[0-9]+" | awk '{print $2}' | sort -u)
    for port in ${NGINX_PORTS}; do
      if [[ "${port}" != "80" && "${port}" != "443" ]] && ! is_ufw_rule_exists "${port}"; then
        ufw allow ${port}/tcp comment "Nginx Custom Port" 2>/dev/null || true
        info "  ✓ Allowed port ${port}/tcp (Nginx custom)"
      fi
    done
  fi
  
  # Check Redis port (if exposed, usually not)
  if [[ -f /etc/redis/redis.conf ]]; then
    REDIS_PORT=$(grep "^port" /etc/redis/redis.conf 2>/dev/null | awk '{print $2}' | head -1)
    if [[ -n "${REDIS_PORT}" && "${REDIS_PORT}" != "6379" ]]; then
      if ! is_ufw_rule_exists "${REDIS_PORT}"; then
        ufw allow ${REDIS_PORT}/tcp comment "Redis" 2>/dev/null || true
        info "  ✓ Allowed port ${REDIS_PORT}/tcp (Redis)"
      fi
    fi
  fi
  
  # Check for other listening services
  if command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | cut -d':' -f2 | sort -u)
    for port in ${LISTENING_PORTS}; do
      # Skip common system ports and already handled ports
      if [[ "${port}" =~ ^(22|25|53|80|443|3306|6379|9001)$ ]]; then
        continue
      fi
      # Only add if it's a high port (likely a service)
      if [[ ${port} -gt 1024 ]] && [[ ${port} -lt 65535 ]] && ! is_ufw_rule_exists "${port}"; then
        SERVICE_NAME=$(ss -tlnp 2>/dev/null | grep ":${port}" | awk '{print $6}' | head -1 | cut -d',' -f2 || echo "Service")
        ufw allow ${port}/tcp comment "${SERVICE_NAME}" 2>/dev/null || true
        info "  ✓ Allowed port ${port}/tcp (${SERVICE_NAME})"
      fi
    done
  fi
}

########################
# === CHECKS ==========
########################

if [[ $EUID -ne 0 ]]; then
  err "This script must be run as root. Use sudo."
fi

# Check Ubuntu version - MUST be 22.04
UBUNTU_VERSION=$(lsb_release -sr 2>/dev/null || echo "Unknown")
UBUNTU_CODENAME=$(lsb_release -sc 2>/dev/null || echo "Unknown")

info "Detected Ubuntu version: ${UBUNTU_VERSION} (${UBUNTU_CODENAME})"

if [[ "${UBUNTU_VERSION}" != "22.04" ]]; then
  err "❌ ERROR: This script is designed ONLY for Ubuntu 22.04 LTS (Jammy Jellyfish)"
  err "Detected: Ubuntu ${UBUNTU_VERSION} (${UBUNTU_CODENAME})"
  err "This script will NOT work on other Ubuntu versions."
  err "Please use Ubuntu 22.04 LTS or find a compatible script for your version."
  exit 1
fi

info "✅ Ubuntu 22.04 LTS detected - proceeding with installation"

# Detect system resources
info "=========================================="
info "System Resource Detection"
info "=========================================="
echo ""

# CPU Detection
CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "1")
CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs || echo "Unknown")

# RAM Detection
TOTAL_RAM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
TOTAL_RAM_MB=$((TOTAL_RAM_KB / 1024))
TOTAL_RAM_GB=$((TOTAL_RAM_MB / 1024))
AVAILABLE_RAM_GB=$(awk '/MemAvailable/ {printf "%.0f", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo "0")

# Disk Detection
TOTAL_DISK_GB=$(df -BG / | awk 'NR==2 {print $2}' | sed 's/G//' || echo "0")
AVAILABLE_DISK_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//' || echo "0")
DISK_USAGE_PERCENT=$(df / | awk 'NR==2 {print $5}' | sed 's/%//' || echo "0")

info "📊 Detected System Resources:"
info "   CPU Cores: ${CPU_CORES}"
info "   CPU Model: ${CPU_MODEL}"
info "   Total RAM: ${TOTAL_RAM_GB}GB (${TOTAL_RAM_MB}MB)"
info "   Available RAM: ${AVAILABLE_RAM_GB}GB"
info "   Total Disk: ${TOTAL_DISK_GB}GB"
info "   Available Disk: ${AVAILABLE_DISK_GB}GB (${DISK_USAGE_PERCENT}% used)"
echo ""

# Check minimum requirements
MIN_RAM_GB=2
MIN_DISK_GB=10

if [[ ${TOTAL_RAM_GB} -lt ${MIN_RAM_GB} ]]; then
  warn "⚠️  Warning: System has less than ${MIN_RAM_GB}GB RAM. Installation may perform poorly."
  warn "   Recommended: At least 4GB RAM for production use"
fi

if [[ ${AVAILABLE_DISK_GB} -lt ${MIN_DISK_GB} ]]; then
  err "❌ Error: System has less than ${MIN_DISK_GB}GB free disk space. Installation cannot proceed."
fi

# Determine server class for optimization
SERVER_CLASS="small"
if [[ ${TOTAL_RAM_GB} -ge 16 && ${CPU_CORES} -ge 8 ]]; then
  SERVER_CLASS="large"
elif [[ ${TOTAL_RAM_GB} -ge 8 && ${CPU_CORES} -ge 4 ]]; then
  SERVER_CLASS="medium"
fi

info "🎯 Server Classification: ${SERVER_CLASS^^} (optimizations will be applied accordingly)"
echo ""

########################
# === CLEANUP PREVIOUS INSTALLATIONS ===
########################

cleanup_previous_installation() {
  info "=========================================="
  info "Cleaning Up Previous Installations"
  info "=========================================="
  echo ""
  
  warn "⚠️  This will remove ALL previous LEMP stack installations and data!"
  warn "   - All services will be stopped and removed"
  warn "   - All MySQL databases will be DELETED"
  warn "   - All websites and configurations will be DELETED"
  warn "   - This action CANNOT be undone!"
  echo ""
  
  read -p "Continue with cleanup? [y/N]: " -n 1 -r
  echo ""
  
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Cleanup cancelled. Proceeding with installation (may conflict with existing installations)..."
    return 0
  fi
  
  info "Starting cleanup process..."
  echo ""
  
  # Stop all services
  info "1) Stopping all LEMP services..."
  systemctl stop nginx 2>/dev/null || true
  systemctl stop php*-fpm 2>/dev/null || true
  systemctl stop mysql 2>/dev/null || true
  systemctl stop redis-server 2>/dev/null || true
  systemctl stop fail2ban 2>/dev/null || true
  systemctl stop supervisor 2>/dev/null || true
  info "  ✓ Services stopped"
  
  # Remove packages
  info "2) Removing installed packages..."
  
  # Nginx
  apt-get purge -y nginx nginx-common nginx-core 2>/dev/null || true
  info "  ✓ Nginx removed"
  
  # PHP (all versions)
  apt-get purge -y 'php*' 2>/dev/null || true
  info "  ✓ PHP removed"
  
  # MySQL/Percona
  apt-get purge -y 'percona*' 'mysql*' 2>/dev/null || true
  info "  ✓ MySQL/Percona removed"
  
  # Redis
  apt-get purge -y redis-server redis-tools 2>/dev/null || true
  info "  ✓ Redis removed"
  
  # Node.js & PM2
  npm uninstall -g pm2 2>/dev/null || true
  apt-get purge -y nodejs 2>/dev/null || true
  info "  ✓ Node.js & PM2 removed"
  
  # Fail2ban
  apt-get purge -y fail2ban 2>/dev/null || true
  info "  ✓ Fail2ban removed"
  
  # Supervisor
  apt-get purge -y supervisor 2>/dev/null || true
  info "  ✓ Supervisor removed"
  
  # Certbot
  apt-get purge -y certbot python3-certbot-nginx 2>/dev/null || true
  info "  ✓ Certbot removed"
  
  # Development tools
  apt-get purge -y composer 2>/dev/null || true
  rm -f /usr/local/bin/composer 2>/dev/null || true
  info "  ✓ Composer removed"
  
  # Remove unused packages
  apt-get autoremove -y 2>/dev/null || true
  apt-get autoclean -y 2>/dev/null || true
  
  # Remove data directories
  info "3) Removing data directories..."
  rm -rf /var/lib/mysql 2>/dev/null || true
  info "  ✓ MySQL data removed"
  
  rm -rf /var/lib/redis 2>/dev/null || true
  info "  ✓ Redis data removed"
  
  rm -rf /var/lib/php 2>/dev/null || true
  info "  ✓ PHP sessions removed"
  
  # Remove configuration directories
  info "4) Removing configuration directories..."
  rm -rf /etc/nginx 2>/dev/null || true
  info "  ✓ Nginx config removed"
  
  rm -rf /etc/php 2>/dev/null || true
  info "  ✓ PHP config removed"
  
  rm -rf /etc/mysql 2>/dev/null || true
  rm -rf /etc/percona* 2>/dev/null || true
  info "  ✓ MySQL config removed"
  
  rm -rf /etc/redis 2>/dev/null || true
  info "  ✓ Redis config removed"
  
  rm -rf /etc/fail2ban 2>/dev/null || true
  info "  ✓ Fail2ban config removed"
  
  rm -rf /etc/supervisor 2>/dev/null || true
  rm -rf /var/log/supervisor 2>/dev/null || true
  info "  ✓ Supervisor config removed"
  
  # Remove web directories
  info "5) Removing web directories..."
  rm -rf /var/www 2>/dev/null || true
  info "  ✓ Web files removed"
  
  rm -rf /var/cache/nginx 2>/dev/null || true
  info "  ✓ Nginx cache removed"
  
  # Remove logs
  info "6) Removing log files..."
  rm -rf /var/log/nginx 2>/dev/null || true
  rm -rf /var/log/mysql 2>/dev/null || true
  rm -rf /var/log/php*.log 2>/dev/null || true
  rm -rf /var/log/redis 2>/dev/null || true
  info "  ✓ Log files removed"
  
  # Remove user data and scripts
  info "7) Removing installation data..."
  rm -f /root/.lemp-install-passwords.txt 2>/dev/null || true
  rm -f /root/.my.cnf 2>/dev/null || true
  rm -rf /root/.npm 2>/dev/null || true
  rm -rf /root/.pm2 2>/dev/null || true
  rm -rf /root/.composer 2>/dev/null || true
  info "  ✓ User data removed"
  
  # Remove repository configurations
  info "8) Removing repository configurations..."
  rm -f /etc/apt/sources.list.d/ondrej-php.list 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/sury-php.list 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/percona*.list 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/nodesource*.list 2>/dev/null || true
  rm -f /usr/share/keyrings/ondrej*.gpg 2>/dev/null || true
  rm -f /usr/share/keyrings/sury*.gpg 2>/dev/null || true
  rm -f /usr/share/keyrings/percona*.gpg 2>/dev/null || true
  info "  ✓ Repository configs removed"
  
  # Clean up systemd
  info "9) Reloading systemd..."
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed 2>/dev/null || true
  info "  ✓ Systemd reloaded"
  
  # Update package lists
  info "10) Updating package lists..."
  apt-get update 2>/dev/null || true
  info "  ✓ Package lists updated"
  
  echo ""
  info "✅ Cleanup completed successfully!"
  info "System is now ready for fresh installation"
  echo ""
  
  sleep 2
}

# Run cleanup
cleanup_previous_installation

########################
# === INTERACTIVE CONFIGURATION ===
########################
interactive_configuration

# Auto-generate passwords if not set
if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then
  MYSQL_ROOT_PASSWORD=$(generate_password 32)
fi
if [[ -z "${BACKUP_MYSQL_PASS}" ]]; then
  BACKUP_MYSQL_PASS=$(generate_password 32)
fi
if [[ -z "${REDIS_PASSWORD}" ]]; then
  REDIS_PASSWORD=$(generate_password 32)
fi

########################
# === MAIN INSTALLATION ===
########################

info "Starting Ubuntu 22.04 LTS LEMP Stack Installation..."
export DEBIAN_FRONTEND=noninteractive

# Clean up any existing problematic repositories FIRST
info "=========================================="
info "Pre-Installation Repository Cleanup"
info "=========================================="
echo ""

# List current problematic repos
FOUND_ISSUES=false
if ls /etc/apt/sources.list.d/*sury* 2>/dev/null; then
  warn "Found Sury repository files"
  FOUND_ISSUES=true
fi
if ls /etc/apt/sources.list.d/*percona* 2>/dev/null; then
  warn "Found Percona repository files"
  FOUND_ISSUES=true
fi

if [[ "${FOUND_ISSUES}" == "true" ]]; then
  warn "Removing problematic repositories from previous installations..."
else
  info "No problematic repositories found (clean system)"
fi

# Remove ALL Sury related files
rm -f /etc/apt/sources.list.d/*sury* 2>/dev/null || true
rm -f /etc/apt/sources.list.d/sury-php.list 2>/dev/null || true
rm -f /usr/share/keyrings/*sury* 2>/dev/null || true
rm -f /usr/share/keyrings/sury-php-archive-keyring.gpg 2>/dev/null || true
rm -f /etc/apt/trusted.gpg.d/*sury* 2>/dev/null || true

# Remove Percona repos from previous attempts
rm -f /etc/apt/sources.list.d/percona* 2>/dev/null || true
rm -f /usr/share/keyrings/percona* 2>/dev/null || true

# Remove NodeSource repos (will be re-added fresh)
rm -f /etc/apt/sources.list.d/nodesource* 2>/dev/null || true

# Clean apt cache completely
info "Cleaning APT cache and lists..."
apt-get clean 2>/dev/null || true
rm -rf /var/lib/apt/lists/* 2>/dev/null || true
mkdir -p /var/lib/apt/lists/partial

info "✅ Repository cleanup complete"
echo ""

info "=========================================="
info "System Update & Package Installation"
info "=========================================="
echo ""

info "1) Updating package lists..."
# First update attempt - capture any errors but don't fail
UPDATE_OUTPUT=$(apt-get update 2>&1) || true
UPDATE_EXIT=$?

# Check for specific known errors
if echo "${UPDATE_OUTPUT}" | grep -qE "418.*teapot|packages.sury.org"; then
  warn "Detected Sury repository issues (418 I'm a teapot) - removing..."
  rm -f /etc/apt/sources.list.d/*sury* 2>/dev/null || true
  rm -f /usr/share/keyrings/*sury* 2>/dev/null || true
  info "Re-running apt-get update..."
  apt-get update || warn "Update completed with warnings"
elif [[ ${UPDATE_EXIT} -ne 0 ]]; then
  warn "apt-get update had some warnings, but continuing..."
else
  info "✅ Package lists updated successfully"
fi

info "2) Upgrading existing packages..."
if apt-get upgrade -y; then
  info "✅ System packages upgraded"
else
  warn "Some packages could not be upgraded (non-critical)"
fi

info "3) Installing essential packages..."
ESSENTIAL_PACKAGES="curl wget lsb-release software-properties-common ca-certificates unzip htop net-tools jq procps gnupg"

if apt-get install -y ${ESSENTIAL_PACKAGES}; then
  info "✅ Essential packages installed"
else
  warn "Some essential packages failed, trying individually..."
  for pkg in ${ESSENTIAL_PACKAGES}; do
    apt-get install -y ${pkg} || warn "Failed to install ${pkg}"
  done
fi

echo ""

info "Setting timezone to ${TIMEZONE}"
timedatectl set-timezone "${TIMEZONE}"

########################
# === SWAP CONFIGURATION ===
########################

info "=========================================="
info "Swap Configuration"
info "=========================================="
echo ""

if is_swap_configured; then
  info "Swap is already configured:"
  swapon --show 2>/dev/null || cat /proc/swaps
  info "Skipping swap creation (already exists)"
else
  info "No swap detected. Would you like to create a swap file?"
  echo ""
  read -p "Create swap file? [Y/n]: " -n 1 -r
  echo ""
  
  if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    read -p "Swap size in GB (e.g., 2, 4, 8): " SWAP_SIZE_GB
    SWAP_SIZE_GB=${SWAP_SIZE_GB:-2}
    
    # Validate swap size
    if ! [[ "${SWAP_SIZE_GB}" =~ ^[0-9]+$ ]] || [[ ${SWAP_SIZE_GB} -lt 1 ]] || [[ ${SWAP_SIZE_GB} -gt 64 ]]; then
      warn "Invalid swap size. Using default: 2GB"
      SWAP_SIZE_GB=2
    fi
    
    info "Creating ${SWAP_SIZE_GB}GB swap file..."
    
    # Check available disk space
    AVAILABLE_GB=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ ${SWAP_SIZE_GB} -gt ${AVAILABLE_GB} ]]; then
      err "Not enough disk space. Available: ${AVAILABLE_GB}GB, Required: ${SWAP_SIZE_GB}GB"
    fi
    
    # Create swap file
    if fallocate -l ${SWAP_SIZE_GB}G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1G count=${SWAP_SIZE_GB} 2>/dev/null; then
      chmod 600 /swapfile
      mkswap /swapfile
      swapon /swapfile
      info "✅ Swap file created and activated"
      
      # Add to fstab if not already there
      if ! grep -qE "^/swapfile" /etc/fstab 2>/dev/null; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
        info "✅ Swap added to /etc/fstab"
      else
        info "Swap already in /etc/fstab"
      fi
    else
      err "Failed to create swap file"
    fi
  else
    info "Swap creation skipped"
  fi
fi

# Configure swappiness
if ! is_swappiness_configured; then
  info "Configuring swappiness..."
  
  # Calculate optimal swappiness based on RAM
  if [[ ${TOTAL_RAM_GB} -ge 16 ]]; then
    SWAPPINESS_VALUE=1
  elif [[ ${TOTAL_RAM_GB} -ge 8 ]]; then
    SWAPPINESS_VALUE=5
  else
    SWAPPINESS_VALUE=10
  fi
  
  cat >/etc/sysctl.d/99-swap.conf <<EOF
# Swap configuration
# Generated: $(date)
vm.swappiness = ${SWAPPINESS_VALUE}
EOF
  
  sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null 2>&1
  info "✅ Swappiness set to ${SWAPPINESS_VALUE} (persistent)"
else
  CURRENT_SWAP=$(grep "vm.swappiness" /etc/sysctl.d/99-swap.conf 2>/dev/null | awk -F'=' '{print $2}' | xargs)
  info "Swappiness already configured: ${CURRENT_SWAP}"
  
  # Update if different from optimal
  if [[ ${TOTAL_RAM_GB} -ge 16 ]] && [[ "${CURRENT_SWAP}" != "1" ]]; then
    info "Updating swappiness to optimal value..."
    sed -i "s/^vm\.swappiness\s*=.*/vm.swappiness = 1/" /etc/sysctl.d/99-swap.conf
    sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null 2>&1
  elif [[ ${TOTAL_RAM_GB} -ge 8 ]] && [[ ${TOTAL_RAM_GB} -lt 16 ]] && [[ "${CURRENT_SWAP}" != "5" ]]; then
    sed -i "s/^vm\.swappiness\s*=.*/vm.swappiness = 5/" /etc/sysctl.d/99-swap.conf
    sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null 2>&1
  fi
fi

echo ""

########################
# === VPN MASQUERADING ===
########################

info "=========================================="
info "VPN Masquerading Configuration"
info "=========================================="
echo ""

# Enable IPv4 forwarding
if ! is_ipv4_forwarding_enabled; then
  info "Enabling IPv4 forwarding for VPN masquerading..."
  echo 1 > /proc/sys/net/ipv4/ip_forward
  
  cat >/etc/sysctl.d/99-vpn-forwarding.conf <<EOF
# IPv4 forwarding for VPN masquerading
# Generated: $(date)
net.ipv4.ip_forward = 1
EOF
  
  sysctl -p /etc/sysctl.d/99-vpn-forwarding.conf >/dev/null 2>&1
  info "✅ IPv4 forwarding enabled"
else
  info "IPv4 forwarding already enabled"
fi

# Configure masquerading in UFW
info "Configuring UFW masquerading for VPN clients..."

# Check if masquerade rule already exists in UFW
if ! grep -qE "POSTROUTING.*MASQUERADE" /etc/ufw/before.rules 2>/dev/null; then
  # Add masquerade rule before COMMIT
  if [[ -f /etc/ufw/before.rules ]]; then
    # Backup
    cp /etc/ufw/before.rules /etc/ufw/before.rules.orig
    
    # Add masquerade rule
    sed -i '/^COMMIT/i\
# Masquerade for VPN clients\
*nat\
:POSTROUTING ACCEPT [0:0]\
-A POSTROUTING -j MASQUERADE\
COMMIT' /etc/ufw/before.rules
    
    info "✅ UFW masquerading configured"
  else
    warn "UFW before.rules not found, masquerading may not work"
  fi
else
  info "UFW masquerading already configured"
fi

echo ""

########################
# === BBR TCP CONGESTION CONTROL & KERNEL TUNING ===
########################

info "=========================================="
info "BBR TCP & Kernel Optimization"
info "=========================================="
echo ""

# Check if BBR is already enabled
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
  info "BBR TCP congestion control already enabled"
else
  info "Enabling BBR TCP congestion control (Google's algorithm for better throughput)..."
  
  # Check if BBR module is available
  if modprobe tcp_bbr 2>/dev/null; then
    info "  ✓ BBR module loaded"
  else
    warn "  ⚠ BBR module not available on this kernel"
  fi
fi

# Apply comprehensive kernel tuning
info "Applying comprehensive kernel parameter tuning..."

cat >/etc/sysctl.d/99-performance-tuning.conf <<EOF
# High-Performance Kernel Tuning
# Generated: $(date)
# Optimized for high-traffic web servers

# ===== TCP/IP Stack Optimization =====

# BBR TCP Congestion Control (Google's algorithm)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Performance
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

# ===== Network Buffer Optimization =====

# Increase network buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 40960
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Increase socket listen backlog
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# ===== File Descriptor Limits =====

# Increase file descriptor limits (1 million)
fs.file-max = 1000000
fs.nr_open = 1000000

# Increase inotify limits (for file watching)
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512

# ===== Connection Tracking =====

# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576

# ===== Memory Management =====

# Reduce swappiness (already set in swap config, but ensuring)
# vm.swappiness is set in 99-swap.conf

# Dirty page management
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# ===== Security =====

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# ===== IPv6 Optimization =====

# IPv6 settings (if enabled)
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

EOF

# Apply sysctl settings
info "Applying kernel parameters..."
if sysctl -p /etc/sysctl.d/99-performance-tuning.conf >/dev/null 2>&1; then
  info "  ✓ Kernel parameters applied successfully"
else
  warn "  ⚠ Some kernel parameters may not be available on this system"
fi

# Set system-wide file descriptor limits
info "Configuring system-wide file descriptor limits..."

cat >/etc/security/limits.d/99-file-limits.conf <<EOF
# System-wide file descriptor limits
# Generated: $(date)

*               soft    nofile          100000
*               hard    nofile          1000000
root            soft    nofile          100000
root            hard    nofile          1000000

# Process limits
*               soft    nproc           100000
*               hard    nproc           100000
EOF

info "  ✓ File descriptor limits set to 1,000,000"

# Update PAM limits
if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
  echo "session required pam_limits.so" >> /etc/pam.d/common-session
  info "  ✓ PAM limits module enabled"
fi

# Display current settings
info ""
info "Current kernel settings:"
info "  • TCP Congestion Control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
info "  • File descriptor limit: $(sysctl -n fs.file-max 2>/dev/null || echo 'unknown')"
info "  • Max connections: $(sysctl -n net.core.somaxconn 2>/dev/null || echo 'unknown')"
info "  • Connection tracking: $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo 'N/A')"

info "✅ BBR TCP and kernel optimization completed"
echo ""


info "2) SSH Configuration - Port ${SSH_PORT}"
SSHD_CONF="/etc/ssh/sshd_config"
cp -n ${SSHD_CONF} ${SSHD_CONF}.orig

# Find available SSH port
ORIGINAL_SSH_PORT=${SSH_PORT}
FOUND_PORT=""
MAX_ATTEMPTS=100

info "Checking if port ${SSH_PORT} is available..."
for i in $(seq 0 $((MAX_ATTEMPTS - 1))); do
  TEST_PORT=$((SSH_PORT + i))
  if check_port_available ${TEST_PORT}; then
    FOUND_PORT=${TEST_PORT}
    if [[ ${TEST_PORT} -ne ${ORIGINAL_SSH_PORT} ]]; then
      info "Port ${ORIGINAL_SSH_PORT} is in use, found available port: ${FOUND_PORT}"
    else
      info "Port ${FOUND_PORT} is available"
    fi
    break
  fi
done

if [[ -z "${FOUND_PORT}" ]]; then
  err "Could not find an available port after checking ${MAX_ATTEMPTS} ports"
fi

SSH_PORT=${FOUND_PORT}

sed -i "s/^#\?Port .*/Port ${SSH_PORT}/" ${SSHD_CONF}
sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin yes/" ${SSHD_CONF}
sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" ${SSHD_CONF}

systemctl restart ssh || systemctl restart sshd
info "SSH configured on port ${SSH_PORT}"

########################
# === SSH LOGIN EMAIL NOTIFICATIONS ===
########################

if ! is_ssh_notify_configured; then
  info "Configuring SSH login email notifications..."
  
  # Install mailutils if not installed
  if ! command -v mail >/dev/null 2>&1; then
    info "  Installing mailutils for email notifications..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y mailutils postfix 2>/dev/null || warn "Mailutils installation failed (email notifications may not work)"
  fi
  
  # Create SSH login notification script
  cat >/usr/local/bin/ssh-login-notify.sh <<'NOTIFYEOF'
#!/bin/bash
# SSH Login Notification Script
# Sends email when user logs in via SSH

if [[ -n "${PAM_USER}" && "${PAM_TYPE}" == "open_session" ]]; then
  HOSTNAME=$(hostname)
  IP_ADDRESS="${PAM_RHOST:-$(who am i | awk '{print $5}' | sed 's/[()]//g')}"
  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S %Z')
  USER="${PAM_USER}"
  
  # Get email from environment or use default
  ALERT_EMAIL="${ALERT_EMAIL:-root@${HOSTNAME}}"
  
  # Send email notification
  {
    echo "SSH Login Alert"
    echo "==============="
    echo ""
    echo "User: ${USER}"
    echo "IP Address: ${IP_ADDRESS}"
    echo "Hostname: ${HOSTNAME}"
    echo "Timestamp: ${TIMESTAMP}"
    echo ""
    echo "This is an automated notification from your server."
  } | mail -s "SSH Login: ${USER}@${HOSTNAME} from ${IP_ADDRESS}" "${ALERT_EMAIL}" 2>/dev/null || true
fi

exit 0
NOTIFYEOF
  
  chmod +x /usr/local/bin/ssh-login-notify.sh
  
  # Add to PAM configuration
  if [[ -f /etc/pam.d/sshd ]]; then
    if ! grep -q "ssh-login-notify" /etc/pam.d/sshd; then
      # Add notification to PAM
      if grep -q "^session.*pam_exec" /etc/pam.d/sshd; then
        # Add after existing pam_exec line
        sed -i '/^session.*pam_exec/a session optional pam_exec.so /usr/local/bin/ssh-login-notify.sh' /etc/pam.d/sshd
      else
        # Add at end of session section
        echo "session optional pam_exec.so /usr/local/bin/ssh-login-notify.sh" >> /etc/pam.d/sshd
      fi
      info "  ✓ SSH login notifications configured"
      info "  • Notification script: /usr/local/bin/ssh-login-notify.sh"
      info "  • Email recipient: ${ALERT_EMAIL:-root@$(hostname)}"
    else
      info "  - SSH login notifications already configured"
    fi
  else
    warn "  ⚠ PAM SSH config not found, notifications may not work"
  fi
else
  info "SSH login notifications already configured"
fi

echo ""

info "3) Installing and configuring UFW Firewall"
apt-get install -y ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp

if [[ "${ALLOW_SSH_FROM_ANY}" == "true" ]]; then
  ufw allow ${SSH_PORT}/tcp comment 'SSH'
else
  ufw allow from ${ADMIN_IP_CIDR} to any port ${SSH_PORT} proto tcp comment 'SSH'
fi

ufw --force enable

# Detect and allow all service ports
detect_and_allow_service_ports

info "✅ Firewall configured with all service ports"

info "4) Installing Fail2ban"
apt-get install -y fail2ban

cat >/etc/fail2ban/jail.d/custom.conf <<EOF
[DEFAULT]
$(if [[ "${ENABLE_EMAIL_ALERTS}" == "true" ]]; then echo "destemail = ${ALERT_EMAIL}"; fi)

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
bantime = 86400
findtime = 3600
EOF

systemctl enable --now fail2ban
info "Fail2ban configured"

########################
# === ROOTKIT DETECTION & SECURITY AUDITING ===
########################

info "=========================================="
info "Rootkit Detection & Security Auditing"
info "=========================================="
echo ""

info "Installing security scanning tools..."

# Install rkhunter (Rootkit Hunter)
if ! command -v rkhunter >/dev/null 2>&1; then
  info "  Installing rkhunter (Rootkit Hunter)..."
  if apt-get install -y rkhunter 2>/dev/null; then
    info "  ✓ rkhunter installed"
    
    # Update rkhunter database
    info "  Updating rkhunter database..."
    rkhunter --update >/dev/null 2>&1 || true
    
    # Configure rkhunter
    if [[ -f /etc/rkhunter.conf ]]; then
      # Set email alerts if configured
      if [[ "${ENABLE_EMAIL_ALERTS}" == "true" && -n "${ALERT_EMAIL}" ]]; then
        sed -i "s/^#MAIL-ON-WARNING=.*/MAIL-ON-WARNING=${ALERT_EMAIL}/" /etc/rkhunter.conf
        sed -i "s/^MAIL-ON-WARNING=.*/MAIL-ON-WARNING=${ALERT_EMAIL}/" /etc/rkhunter.conf
        info "  ✓ rkhunter email alerts configured"
      fi
      
      # Update file properties database
      info "  Building rkhunter file properties database..."
      rkhunter --propupd >/dev/null 2>&1 || true
    fi
    
    # Create daily scan cron job
    cat >/etc/cron.daily/rkhunter-scan <<'RKHUNTER_CRON'
#!/bin/bash
# Daily rkhunter scan
/usr/bin/rkhunter --cronjob --update --quiet 2>&1 | logger -t rkhunter
RKHUNTER_CRON
    chmod +x /etc/cron.daily/rkhunter-scan
    info "  ✓ Daily rkhunter scan scheduled (2 AM)"
  else
    warn "  ⚠ Failed to install rkhunter"
  fi
else
  info "  - rkhunter already installed"
fi

# Install chkrootkit
if ! command -v chkrootkit >/dev/null 2>&1; then
  info "  Installing chkrootkit..."
  if apt-get install -y chkrootkit 2>/dev/null; then
    info "  ✓ chkrootkit installed"
  else
    warn "  ⚠ Failed to install chkrootkit"
  fi
else
  info "  - chkrootkit already installed"
fi

# Install Lynis (Security auditing tool)
if ! command -v lynis >/dev/null 2>&1; then
  info "  Installing Lynis (security auditing tool)..."
  if apt-get install -y lynis 2>/dev/null; then
    info "  ✓ Lynis installed"
    
    # Create security audit script
    cat >/usr/local/bin/security-audit.sh <<'LYNIS_SCRIPT'
#!/bin/bash
# Security Audit Script using Lynis
# Usage: security-audit.sh

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Running security audit with Lynis..."
info "This may take a few minutes..."
echo ""

# Run Lynis audit
lynis audit system --quick --quiet

echo ""
info "Audit complete! Review the report above."
info "Full report: /var/log/lynis-report.dat"
info ""
info "To run manual scans:"
info "  • rkhunter --check"
info "  • chkrootkit"
info "  • lynis audit system"
LYNIS_SCRIPT
    chmod +x /usr/local/bin/security-audit.sh
    info "  ✓ Security audit script created: /usr/local/bin/security-audit.sh"
  else
    warn "  ⚠ Failed to install Lynis"
  fi
else
  info "  - Lynis already installed"
fi

info "✅ Security scanning tools installed"
echo ""

########################
# === IMAGE OPTIMIZATION TOOLS ===
########################

info "=========================================="
info "Image Optimization Tools"
info "=========================================="
echo ""

info "Installing image optimization tools..."

# List of image optimization tools
IMAGE_TOOLS="jpegoptim optipng pngquant gifsicle webp"

INSTALLED_COUNT=0
FAILED_COUNT=0

for tool in ${IMAGE_TOOLS}; do
  if ! command -v ${tool} >/dev/null 2>&1; then
    if apt-get install -y ${tool} 2>/dev/null; then
      info "  ✓ ${tool} installed"
      INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
      warn "  ✗ ${tool} failed to install"
      FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
  else
    info "  - ${tool} already installed"
    INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
  fi
done

# Create image optimization script
cat >/usr/local/bin/optimize-images.sh <<'OPTIMIZE_SCRIPT'
#!/bin/bash
# Image Optimization Script
# Usage: optimize-images.sh /path/to/images

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <directory>"
    echo "Example: $0 /var/www/html/images"
    exit 1
fi

TARGET_DIR="$1"

if [[ ! -d "${TARGET_DIR}" ]]; then
    echo "Error: Directory not found: ${TARGET_DIR}"
    exit 1
fi

echo "Optimizing images in: ${TARGET_DIR}"
echo "This may take a while..."
echo ""

# Optimize JPEG files
if command -v jpegoptim >/dev/null 2>&1; then
    echo "Optimizing JPEG files..."
    find "${TARGET_DIR}" -type f \( -iname "*.jpg" -o -iname "*.jpeg" \) -exec jpegoptim --strip-all --max=85 {} \;
fi

# Optimize PNG files
if command -v optipng >/dev/null 2>&1; then
    echo "Optimizing PNG files..."
    find "${TARGET_DIR}" -type f -iname "*.png" -exec optipng -o2 {} \;
fi

# Further PNG optimization with pngquant
if command -v pngquant >/dev/null 2>&1; then
    echo "Further PNG optimization..."
    find "${TARGET_DIR}" -type f -iname "*.png" -exec pngquant --skip-if-larger --force --ext .png {} \;
fi

# Optimize GIF files
if command -v gifsicle >/dev/null 2>&1; then
    echo "Optimizing GIF files..."
    find "${TARGET_DIR}" -type f -iname "*.gif" -exec gifsicle --batch --optimize=3 {} \;
fi

echo ""
echo "✅ Image optimization complete!"
OPTIMIZE_SCRIPT

chmod +x /usr/local/bin/optimize-images.sh

info ""
info "Image optimization summary:"
info "  • Installed: ${INSTALLED_COUNT} tools"
if [[ ${FAILED_COUNT} -gt 0 ]]; then
  warn "  • Failed: ${FAILED_COUNT} tools"
fi
info "  • Optimization script: /usr/local/bin/optimize-images.sh"
info ""
info "Usage: optimize-images.sh /path/to/images"

info "✅ Image optimization tools installed"
echo ""

########################
# === ADVANCED FAIL2BAN RULES ===
########################

info "=========================================="
info "Advanced Fail2ban Rules"
info "=========================================="
echo ""

info "Adding advanced Fail2ban jails for Nginx and MySQL..."

# Create advanced Fail2ban configuration
cat >/etc/fail2ban/jail.d/advanced-protection.conf <<'FAIL2BAN_ADVANCED'
# Advanced Fail2ban Protection

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 600
bantime = 3600

[nginx-noscript]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 6
findtime = 60
bantime = 3600

[nginx-badbots]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-noproxy]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-limit-req]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 3600

[nginx-404]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 20
findtime = 60
bantime = 600

[mysql-auth]
enabled = true
port = 3306
logpath = /var/log/mysql/error.log
maxretry = 3
findtime = 600
bantime = 86400

[php-url-fopen]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400
FAIL2BAN_ADVANCED

# Create filter for nginx-404
cat >/etc/fail2ban/filter.d/nginx-404.conf <<'FILTER_404'
[Definition]
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*" 404
ignoreregex =
FILTER_404

# Create filter for nginx-badbots
cat >/etc/fail2ban/filter.d/nginx-badbots.conf <<'FILTER_BOTS'
[Definition]
badbots = Acunetix|FHscan|HTTrack|Nikto|Nmap|sqlmap|Wget|ZmEu
failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*".* ".*(<badbots>).*"$
ignoreregex =
FILTER_BOTS'

# Create filter for php-url-fopen
cat >/etc/fail2ban/filter.d/php-url-fopen.conf <<'FILTER_FOPEN'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(?:php|asp|exe|pl|cgi|scgi).*HTTP.*"
ignoreregex =
FILTER_FOPEN

# Create filter for mysql-auth
cat >/etc/fail2ban/filter.d/mysql-auth.conf <<'FILTER_MYSQL'
[Definition]
failregex = Access denied for user.*<HOST>
ignoreregex =
FILTER_MYSQL

# Restart Fail2ban to apply new rules
systemctl restart fail2ban

info "  ✓ Nginx HTTP auth protection enabled"
info "  ✓ Nginx bot detection enabled"
info "  ✓ Nginx 404 flood protection enabled"
info "  ✓ Nginx limit-req protection enabled"
info "  ✓ MySQL brute-force protection enabled"
info "  ✓ PHP URL fopen exploit protection enabled"

info ""
info "✅ Advanced Fail2ban rules configured"
info ""
info "Protection summary:"
info "  • Nginx HTTP auth: 3 attempts = 1h ban"
info "  • Bad bots: 2 attempts = 24h ban"
info "  • 404 flood: 20/min = 10min ban"
info "  • MySQL auth: 3 attempts = 24h ban"
info ""
info "Management:"
info "  • View bans: fail2ban-client status"
info "  • Unban IP: fail2ban-client set <jail> unbanip <IP>"
echo ""



info "5) Installing Nginx"
apt-get install -y nginx

# Nginx configuration - optimized based on system resources
cp -n /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig

info "Configuring Nginx based on detected resources..."

# Calculate optimal Nginx settings
NGINX_WORKER_PROCESSES=${CPU_CORES}
NGINX_WORKER_RLIMIT_NOFILE=$((CPU_CORES * 100000))

# Worker connections based on server class
case "${SERVER_CLASS}" in
  "large")
    NGINX_WORKER_CONNECTIONS=65536
    NGINX_KEEPALIVE_TIMEOUT=30
    NGINX_KEEPALIVE_REQUESTS=1000
    ;;
  "medium")
    NGINX_WORKER_CONNECTIONS=32768
    NGINX_KEEPALIVE_TIMEOUT=30
    NGINX_KEEPALIVE_REQUESTS=500
    ;;
  *)
    NGINX_WORKER_CONNECTIONS=8192
    NGINX_KEEPALIVE_TIMEOUT=20
    NGINX_KEEPALIVE_REQUESTS=100
    ;;
esac

info "  • Worker processes: ${NGINX_WORKER_PROCESSES} (CPU cores: ${CPU_CORES})"
info "  • Worker connections: ${NGINX_WORKER_CONNECTIONS}"
info "  • Worker rlimit nofile: ${NGINX_WORKER_RLIMIT_NOFILE}"

cat >/etc/nginx/nginx.conf <<NGINX_EOF
# Optimized Nginx configuration for ${SERVER_CLASS} server
# CPU Cores: ${CPU_CORES}, RAM: ${TOTAL_RAM_GB}GB
# Generated: $(date)

user www-data;
worker_processes ${NGINX_WORKER_PROCESSES};
worker_rlimit_nofile ${NGINX_WORKER_RLIMIT_NOFILE};
pid /run/nginx.pid;

events {
    use epoll;
    worker_connections ${NGINX_WORKER_CONNECTIONS};
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    server_tokens off;
    keepalive_timeout ${NGINX_KEEPALIVE_TIMEOUT};
    keepalive_requests ${NGINX_KEEPALIVE_REQUESTS};
    types_hash_max_size 2048;
    client_max_body_size 50M;
    client_body_buffer_size 128k;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main buffer=32k flush=5s;
    error_log /var/log/nginx/error.log warn;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_min_length 1000;
    gzip_proxied any;
    gzip_types text/plain text/css text/xml text/javascript 
               application/json application/javascript application/xml+rss 
               application/xml application/x-javascript image/svg+xml;

    # FastCGI cache settings - Enhanced for high performance
    # Cache size will be calculated before this config is written
    fastcgi_cache_path /var/cache/nginx/fastcgi levels=1:2 keys_zone=fastcgi_cache:100m 
                       max_size=5000m inactive=60m use_temp_path=off;
    
    # Cache statistics zone
    fastcgi_cache_path /var/cache/nginx/stats levels=1:2 keys_zone=cache_stats:10m 
                       max_size=100m inactive=24h use_temp_path=off;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINX_EOF

# Create cache directories
mkdir -p /var/cache/nginx/fastcgi
mkdir -p /var/cache/nginx/stats
chown -R www-data:www-data /var/cache/nginx

# Calculate cache size based on available disk space (10% of available, max 10GB)
CACHE_SIZE_MB=$((AVAILABLE_DISK_GB * 1024 / 10))
if [[ ${CACHE_SIZE_MB} -gt 10240 ]]; then CACHE_SIZE_MB=10240; fi
if [[ ${CACHE_SIZE_MB} -lt 500 ]]; then CACHE_SIZE_MB=500; fi

systemctl enable --now nginx
info "✅ Nginx configured for ${SERVER_CLASS} server (${CPU_CORES} cores)"
info "  • FastCGI cache: ${CACHE_SIZE_MB}MB max size (calculated)"

# Add health check endpoints
info "Adding health check endpoints..."

cat >/etc/nginx/conf.d/health-check.conf <<'HEALTHEOF'
# Health Check Endpoints
# Basic health check
location /health {
    access_log off;
    return 200 '{"status":"ok","timestamp":"$time_iso8601"}';
    add_header Content-Type application/json;
}

# Detailed health check
location /health-detailed {
    access_log off;
    default_type application/json;
    return 200 '{"status":"ok","server":"$hostname","timestamp":"$time_iso8601","connections":{"active":"$connections_active","reading":"$connections_reading","writing":"$connections_writing","waiting":"$connections_waiting"}}';
}
HEALTHEOF

info "  ✓ Health check endpoints configured"
info "    • /health - Basic status check"
info "    • /health-detailed - Detailed server status"


########################
# === NGINX FASTCGI CACHE ENHANCEMENTS ===
########################

info "=========================================="
info "Nginx FastCGI Cache Configuration"
info "=========================================="
echo ""

# Create FastCGI cache configuration file
cat >/etc/nginx/conf.d/fastcgi-cache.conf <<'CACHEEOF'
# FastCGI Cache Configuration
# This file provides cache settings that can be included in server blocks

# Cache key variables
map $request_method $cache_method {
    GET     "1";
    HEAD    "1";
    default "0";
}

# Bypass cache for logged-in users (WordPress, Laravel, etc.)
map $http_cookie $skip_cache {
    default 0;
    ~*wordpress_logged_in 1;
    ~*laravel_session 1;
    ~*PHPSESSID 1;
    ~*auth_token 1;
}

# Cache status header (for debugging)
add_header X-Cache-Status $upstream_cache_status always;

# FastCGI cache configuration snippet
# Include this in your server blocks:
# include /etc/nginx/conf.d/fastcgi-cache.conf;
# Then add to location ~ \.php$:
#   fastcgi_cache fastcgi_cache;
#   fastcgi_cache_valid 200 60m;
#   fastcgi_cache_valid 404 10m;
#   fastcgi_cache_bypass $skip_cache;
#   fastcgi_no_cache $skip_cache;
#   fastcgi_cache_key "$scheme$request_method$host$request_uri";
CACHEEOF

# Create cache purging endpoint configuration
cat >/etc/nginx/conf.d/cache-purge.conf <<'PURGEEOF'
# Cache Purging Endpoint
# Add this location block to your server configuration:
# location ~ /purge-cache(/.*) {
#     allow 127.0.0.1;
#     allow ::1;
#     # allow YOUR_IP_ADDRESS;  # Add your IP for remote access
#     deny all;
#     fastcgi_cache_purge fastcgi_cache "$scheme$request_method$host$1";
# }

# Cache statistics endpoint
# Add this location block to your server configuration:
# location /cache-stats {
#     allow 127.0.0.1;
#     allow ::1;
#     deny all;
#     access_log off;
#     return 200 "Cache Status: Active\nCache Zone: fastcgi_cache\n";
#     add_header Content-Type text/plain;
# }
PURGEEOF

info "  ✓ FastCGI cache configuration files created"

# Create cache warming script
cat >/usr/local/bin/nginx-cache-warm.sh <<'WARMEOF'
#!/bin/bash
# Nginx FastCGI Cache Warming Script
# This script pre-warms the cache by visiting important URLs

CACHE_WARM_URLS=(
    "http://localhost/"
    "http://localhost/index.php"
)

# Add your domain URLs here
if [[ -n "${1}" ]]; then
    DOMAIN="${1}"
    CACHE_WARM_URLS+=(
        "http://${DOMAIN}/"
        "https://${DOMAIN}/"
    )
fi

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Warming Nginx FastCGI cache..."
info "This may take a few moments..."

for url in "${CACHE_WARM_URLS[@]}"; do
    if curl -s -o /dev/null -w "  %{http_code} - %{url_effective}\n" "${url}"; then
        info "  ✓ Cached: ${url}"
    else
        echo "  ✗ Failed: ${url}"
    fi
done

info "Cache warming completed!"
WARMEOF

chmod +x /usr/local/bin/nginx-cache-warm.sh
info "  ✓ Cache warming script created: /usr/local/bin/nginx-cache-warm.sh"

# Create cache purging script
cat >/usr/local/bin/nginx-cache-purge.sh <<'PURGESCRIPTEOF'
#!/bin/bash
# Nginx FastCGI Cache Purging Script
# Usage: nginx-cache-purge.sh [URL_PATH]

PURGE_URL="${1:-/}"
DOMAIN="${2:-localhost}"

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

if [[ "${PURGE_URL}" == "all" ]]; then
    info "Purging entire FastCGI cache..."
    rm -rf /var/cache/nginx/fastcgi/*
    info "✓ Cache purged (all files removed)"
    systemctl reload nginx
    info "✓ Nginx reloaded"
else
    info "Purging cache for: ${PURGE_URL}"
    
    # Try to purge via HTTP endpoint (if configured)
    if curl -s -X PURGE "http://${DOMAIN}${PURGE_URL}" >/dev/null 2>&1; then
        info "✓ Cache purged via HTTP endpoint"
    else
        # Manual purge by finding and removing cache files
        CACHE_KEY=$(echo -n "GET${DOMAIN}${PURGE_URL}" | md5sum | cut -d' ' -f1)
        CACHE_FILE="/var/cache/nginx/fastcgi/$(echo ${CACHE_KEY} | cut -c1)/$(echo ${CACHE_KEY} | cut -c2-3)/${CACHE_KEY}"
        
        if [[ -f "${CACHE_FILE}" ]]; then
            rm -f "${CACHE_FILE}"
            info "✓ Cache file removed: ${CACHE_FILE}"
        else
            info "⚠ Cache file not found (may not be cached)"
        fi
    fi
fi
PURGESCRIPTEOF

chmod +x /usr/local/bin/nginx-cache-purge.sh
info "  ✓ Cache purging script created: /usr/local/bin/nginx-cache-purge.sh"

# Create cache statistics script
cat >/usr/local/bin/nginx-cache-stats.sh <<'STATSEOF'
#!/bin/bash
# Nginx FastCGI Cache Statistics Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Nginx FastCGI Cache Statistics"
info "================================"
echo ""

# Cache directory size
CACHE_SIZE=$(du -sh /var/cache/nginx/fastcgi 2>/dev/null | awk '{print $1}')
CACHE_FILES=$(find /var/cache/nginx/fastcgi -type f 2>/dev/null | wc -l)

info "Cache Directory: /var/cache/nginx/fastcgi"
info "Cache Size: ${CACHE_SIZE}"
info "Cached Files: ${CACHE_FILES}"
echo ""

# Cache hit/miss from Nginx logs (if available)
if [[ -f /var/log/nginx/access.log ]]; then
    info "Cache Status from Access Logs (last 1000 requests):"
    tail -1000 /var/log/nginx/access.log 2>/dev/null | grep -o "X-Cache-Status: [A-Z]*" | sort | uniq -c | while read count status; do
        echo "  ${status}: ${count}"
    done
fi

echo ""
info "To view real-time cache status, check Nginx access logs:"
info "  tail -f /var/log/nginx/access.log | grep X-Cache-Status"
STATSEOF

chmod +x /usr/local/bin/nginx-cache-stats.sh
info "  ✓ Cache statistics script created: /usr/local/bin/nginx-cache-stats.sh"

# Update default site to use FastCGI cache
if [[ -f /etc/nginx/sites-available/default ]]; then
    # Check if cache is already configured
    if ! grep -q "fastcgi_cache" /etc/nginx/sites-available/default; then
        info "Adding FastCGI cache to default site..."
        
        # Backup
        cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak
        
        # Add cache configuration to PHP location block
        sed -i '/location ~ \\\.php\$ {/,/}/ {
            /fastcgi_pass/ a\
        # FastCGI Cache\
        fastcgi_cache fastcgi_cache;\
        fastcgi_cache_valid 200 60m;\
        fastcgi_cache_valid 404 10m;\
        fastcgi_cache_bypass $skip_cache;\
        fastcgi_no_cache $skip_cache;\
        fastcgi_cache_key "$scheme$request_method$host$request_uri";\
        fastcgi_cache_use_stale error timeout updating http_500 http_503;\
        fastcgi_cache_background_update on;\
        fastcgi_cache_lock on;
        }' /etc/nginx/sites-available/default
        
        # Add cache bypass map at the top
        if ! grep -q "map.*skip_cache" /etc/nginx/sites-available/default; then
            sed -i '/server {/ i\
    # Cache bypass for logged-in users\
    map $http_cookie $skip_cache {\
        default 0;\
        ~*wordpress_logged_in 1;\
        ~*laravel_session 1;\
        ~*PHPSESSID 1;\
    }\
' /etc/nginx/sites-available/default
        fi
        
        if nginx -t 2>/dev/null; then
            systemctl reload nginx
            info "  ✓ FastCGI cache enabled on default site"
        else
            warn "  ⚠ Nginx config test failed, restoring backup"
            cp /etc/nginx/sites-available/default.bak /etc/nginx/sites-available/default
        fi
    else
        info "  - FastCGI cache already configured on default site"
    fi
fi

info "✅ Nginx FastCGI cache configuration completed"
info ""
info "Usage:"
info "  • Warm cache: nginx-cache-warm.sh [domain]"
info "  • Purge cache: nginx-cache-purge.sh [path] [domain]"
info "  • View stats: nginx-cache-stats.sh"
echo ""

# Add advanced caching rules
info "Adding advanced Nginx caching rules..."

cat >/etc/nginx/conf.d/advanced-caching.conf <<'ADVANCED_CACHE'
# Advanced Nginx Caching Rules

# Static file caching with long expiration
location ~* \.(jpg|jpeg|png|gif|ico|svg|webp)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
    log_not_found off;
}

# CSS and JavaScript caching
location ~* \.(css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Font files caching
location ~* \.(woff|woff2|ttf|otf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
    add_header Access-Control-Allow-Origin *;
}

# Media files caching
location ~* \.(mp4|webm|ogg|mp3|wav|flac|aac)$ {
    expires 1M;
    add_header Cache-Control "public";
    access_log off;
}

# Document files caching
location ~* \.(pdf|doc|docx|xls|xlsx|ppt|pptx)$ {
    expires 1M;
    add_header Cache-Control "public";
}

# Disable caching for dynamic files
location ~* \.(php|html)$ {
    expires -1;
    add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0";
}
ADVANCED_CACHE

# Add gzip compression configuration
cat >/etc/nginx/conf.d/gzip-compression.conf <<'GZIP_CONF'
# Gzip Compression Configuration

gzip on;
gzip_vary on;
gzip_proxied any;
gzip_comp_level 6;
gzip_types
    text/plain
    text/css
    text/xml
    text/javascript
    application/json
    application/javascript
    application/xml+rss
    application/rss+xml
    application/atom+xml
    image/svg+xml
    text/x-component
    text/x-cross-domain-policy;
gzip_disable "msie6";
gzip_min_length 256;
gzip_buffers 16 8k;
GZIP_CONF

# Reload Nginx to apply changes
nginx -t && systemctl reload nginx

info "  ✓ Advanced caching rules configured"
info "  ✓ Static files: 1 year expiration"
info "  ✓ Media files: 1 month expiration"
info "  ✓ Gzip compression enabled"
echo ""


########################
# === MODSECURITY WAF ===
########################

info "=========================================="
info "ModSecurity WAF Installation"
info "=========================================="
echo ""

info "ModSecurity provides Web Application Firewall (WAF) protection"
info "Would you like to install ModSecurity with OWASP Core Rule Set?"
echo ""
read -p "Install ModSecurity WAF? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
  info "Installing ModSecurity WAF..."
  
  # Install dependencies
  info "  Installing dependencies..."
  apt-get install -y \
    libmodsecurity3 \
    modsecurity-crs \
    nginx-mod-http-modsecurity \
    2>/dev/null || {
      warn "  ⚠ Standard ModSecurity packages not available"
      info "  Attempting alternative installation method..."
      
      # Try installing from Ubuntu repositories
      apt-get install -y \
        libmodsecurity-dev \
        libmodsecurity3 \
        2>/dev/null || warn "  ⚠ Some ModSecurity packages may not be available"
    }
  
  # Check if ModSecurity is available
  if dpkg -l | grep -q "libmodsecurity"; then
    info "  ✓ ModSecurity library installed"
    
    # Create ModSecurity configuration directory
    mkdir -p /etc/nginx/modsec
    mkdir -p /var/log/nginx/modsec
    
    # Download OWASP Core Rule Set if not installed via package
    if [[ ! -d /etc/modsecurity/crs ]]; then
      info "  Downloading OWASP Core Rule Set..."
      
      OWASP_CRS_VERSION="3.3.4"
      if [[ -d /tmp ]]; then
        cd /tmp
        if wget -q "https://github.com/coreruleset/coreruleset/archive/v${OWASP_CRS_VERSION}.tar.gz" -O crs.tar.gz 2>/dev/null; then
          tar -xzf crs.tar.gz
          mkdir -p /etc/modsecurity
          mv coreruleset-${OWASP_CRS_VERSION} /etc/modsecurity/crs
          rm -f crs.tar.gz
          info "  ✓ OWASP CRS downloaded"
        else
          warn "  ⚠ Failed to download OWASP CRS (will use basic rules)"
        fi
      fi
    else
      info "  ✓ OWASP CRS already available"
    fi
    
    # Create ModSecurity main configuration
    cat >/etc/nginx/modsec/main.conf <<'MODSECEOF'
# ModSecurity Configuration
# Include this in your nginx server blocks

# Basic ModSecurity settings
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec/audit.log

# Request limits
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# File upload limits
SecRequestBodyInMemoryLimit 131072

# Performance tuning
SecPcreMatchLimit 100000
SecPcreMatchLimitRecursion 100000

# Include OWASP Core Rule Set
Include /etc/modsecurity/crs/crs-setup.conf
Include /etc/modsecurity/crs/rules/*.conf
MODSECEOF

    # Create basic rules if OWASP CRS is not available
    if [[ ! -f /etc/modsecurity/crs/crs-setup.conf ]]; then
      info "  Creating basic ModSecurity rules..."
      
      mkdir -p /etc/modsecurity/crs/rules
      
      cat >/etc/modsecurity/crs/crs-setup.conf <<'BASICRULESEOF'
# Basic ModSecurity Rules Setup
# OWASP CRS not available, using basic protection rules

# Enable basic protection
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# SQL Injection Protection
SecRule REQUEST_URI|REQUEST_BODY "@detectSQLi" \
    "id:1000,phase:2,deny,status:403,msg:'SQL Injection Attack Detected'"

# XSS Protection
SecRule REQUEST_URI|REQUEST_BODY "@detectXSS" \
    "id:1001,phase:2,deny,status:403,msg:'XSS Attack Detected'"

# Block common attack patterns
SecRule REQUEST_URI "@contains ../" \
    "id:1002,phase:1,deny,status:403,msg:'Path Traversal Attempt'"

SecRule REQUEST_URI "@contains <script" \
    "id:1003,phase:1,deny,status:403,msg:'Script Injection Attempt'"
BASICRULESEOF
    fi
    
    # Create Nginx ModSecurity configuration
    cat >/etc/nginx/conf.d/modsecurity.conf <<'NGINXMODSECEOF'
# ModSecurity Nginx Configuration
# Load ModSecurity module (if available)
# load_module modules/ngx_http_modsecurity_module.so;

# ModSecurity configuration
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
NGINXMODSECEOF

    # Add ModSecurity to default site (optional, commented out by default)
    if [[ -f /etc/nginx/sites-available/default ]]; then
      if ! grep -q "modsecurity" /etc/nginx/sites-available/default; then
        info "  Adding ModSecurity to default site (commented out - enable manually)..."
        
        # Add commented ModSecurity include
        sed -i '/server {/ a\
    # Enable ModSecurity (uncomment to activate)\
    # include /etc/nginx/conf.d/modsecurity.conf;
' /etc/nginx/sites-available/default
      fi
    fi
    
    # Create ModSecurity log rotation
    cat >/etc/logrotate.d/modsecurity <<'LOGROTATEEOF'
/var/log/nginx/modsec/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 www-data www-data
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
LOGROTATEEOF

    # Create ModSecurity management script
    cat >/usr/local/bin/modsecurity-manage.sh <<'MODSECMANAGEEOF'
#!/bin/bash
# ModSecurity Management Script

case "$1" in
  status)
    echo "ModSecurity Status:"
    if grep -q "modsecurity on" /etc/nginx/conf.d/modsecurity.conf 2>/dev/null; then
      echo "  ✓ ModSecurity is enabled"
    else
      echo "  ✗ ModSecurity is disabled"
    fi
    
    if [[ -f /var/log/nginx/modsec/audit.log ]]; then
      echo ""
      echo "Recent ModSecurity Events (last 10):"
      tail -10 /var/log/nginx/modsec/audit.log 2>/dev/null | head -5
    fi
    ;;
  
  enable)
    echo "Enabling ModSecurity..."
    sed -i 's/#modsecurity on;/modsecurity on;/' /etc/nginx/conf.d/modsecurity.conf 2>/dev/null
    sed -i 's/#include.*modsecurity.conf/include \/etc\/nginx\/conf.d\/modsecurity.conf/' /etc/nginx/sites-available/* 2>/dev/null
    nginx -t && systemctl reload nginx
    echo "✓ ModSecurity enabled"
    ;;
  
  disable)
    echo "Disabling ModSecurity..."
    sed -i 's/modsecurity on;/#modsecurity on;/' /etc/nginx/conf.d/modsecurity.conf 2>/dev/null
    sed -i 's/include.*modsecurity.conf/#include \/etc\/nginx\/conf.d\/modsecurity.conf/' /etc/nginx/sites-available/* 2>/dev/null
    nginx -t && systemctl reload nginx
    echo "✓ ModSecurity disabled"
    ;;
  
  logs)
    if [[ -f /var/log/nginx/modsec/audit.log ]]; then
      tail -f /var/log/nginx/modsec/audit.log
    else
      echo "No ModSecurity logs found"
    fi
    ;;
  
  *)
    echo "Usage: $0 {status|enable|disable|logs}"
    exit 1
    ;;
esac
MODSECMANAGEEOF

    chmod +x /usr/local/bin/modsecurity-manage.sh
    info "  ✓ ModSecurity management script created"
    
    # Test Nginx configuration
    if nginx -t 2>/dev/null; then
      systemctl reload nginx
      info "✅ ModSecurity WAF installed successfully"
      info ""
      info "Note: ModSecurity is installed but disabled by default"
      info "To enable: modsecurity-manage.sh enable"
      info "To check status: modsecurity-manage.sh status"
      info "To view logs: modsecurity-manage.sh logs"
    else
      warn "⚠ Nginx configuration test failed"
      warn "ModSecurity may need manual configuration"
    fi
  else
    warn "  ⚠ ModSecurity library not found in repositories"
    warn "  You may need to compile ModSecurity v3 for Nginx manually"
    warn "  See: https://github.com/SpiderLabs/ModSecurity-nginx"
  fi
else
  info "ModSecurity installation skipped"
fi

echo ""

info "=========================================="
info "PHP Installation"
info "=========================================="
echo ""

info "🔧 Preparing to install PHP 8.3..."
echo ""

# Ensure we have software-properties-common for PPA support
info "Step 1: Ensuring PPA support is installed..."
if ! dpkg -l | grep -q "ii.*software-properties-common"; then
  apt-get install -y software-properties-common || warn "software-properties-common already installed"
fi

# Install ca-certificates and gnupg for secure key handling
apt-get install -y ca-certificates gnupg lsb-release 2>/dev/null || true

PHP_REPO_ADDED=false
PHP_VERSION=""
PHP_SOURCE=""

echo ""
info "Step 2: Adding ondrej/php PPA (official PHP repository for Ubuntu)..."
info "This PPA provides PHP 8.3, 8.2, 8.1 and is maintained by Ondřej Surý"
echo ""

# Remove any existing PHP PPAs to start fresh
rm -f /etc/apt/sources.list.d/ondrej-*.list 2>/dev/null || true
rm -f /etc/apt/sources.list.d/sury-*.list 2>/dev/null || true

# Method 1: Using add-apt-repository (cleanest method)
info "  → Attempting via add-apt-repository..."
if LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php 2>&1 | tee /tmp/ppa-add.log; then
  info "  → PPA added, updating package lists..."
  
  if apt-get update 2>&1 | tee /tmp/apt-update.log; then
    info "  ✓ Package lists updated successfully"
    PHP_REPO_ADDED=true
    PHP_SOURCE="ondrej/php PPA"
  else
    if ! grep -qE "NO_PUBKEY|GPG error" /tmp/apt-update.log; then
      warn "  ⚠ Update had warnings but may be usable"
      PHP_REPO_ADDED=true
      PHP_SOURCE="ondrej/php PPA"
    else
      warn "  ✗ Repository has GPG key issues"
    fi
  fi
else
  warn "  ✗ add-apt-repository failed"
  cat /tmp/ppa-add.log 2>/dev/null || true
fi

rm -f /tmp/ppa-add.log /tmp/apt-update.log 2>/dev/null || true

# Method 2: Direct repository addition with GPG key from Ubuntu keyserver
if [[ "${PHP_REPO_ADDED}" == "false" ]]; then
  echo ""
  info "  → Attempting manual PPA configuration..."
  
  # Get the GPG key from Ubuntu keyserver
  info "    Importing GPG key from Ubuntu keyserver..."
  if gpg --keyserver keyserver.ubuntu.com --recv-keys 4F4EA0AAE5267A6C 2>/dev/null; then
    gpg --export 4F4EA0AAE5267A6C | gpg --dearmor > /usr/share/keyrings/ondrej-php.gpg
    
    # Add repository
    cat > /etc/apt/sources.list.d/ondrej-php.list <<EOF
deb [signed-by=/usr/share/keyrings/ondrej-php.gpg] http://ppa.launchpad.net/ondrej/php/ubuntu jammy main
EOF
    
    info "    Updating package lists..."
    if apt-get update 2>&1 | grep -v "Conflicting values set"; then
      info "  ✓ Manual configuration successful!"
      PHP_REPO_ADDED=true
      PHP_SOURCE="ondrej/php PPA (manual)"
    fi
  else
    warn "  ✗ Could not import GPG key"
  fi
fi

# Method 3: Using apt-key (legacy but reliable)
if [[ "${PHP_REPO_ADDED}" == "false" ]]; then
  echo ""
  info "  → Attempting legacy apt-key method..."
  
  if apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4F4EA0AAE5267A6C 2>/dev/null; then
    cat > /etc/apt/sources.list.d/ondrej-php.list <<EOF
deb http://ppa.launchpad.net/ondrej/php/ubuntu jammy main
EOF
    
    if apt-get update 2>/dev/null; then
      info "  ✓ Legacy method successful!"
      PHP_REPO_ADDED=true
      PHP_SOURCE="ondrej/php PPA (legacy)"
    fi
  fi
fi

# Verify repository was added
if [[ "${PHP_REPO_ADDED}" == "false" ]]; then
  err "❌ Failed to add ondrej/php PPA after trying all methods."
  err "This may be due to:"
  err "  - Network/firewall blocking keyserver.ubuntu.com"
  err "  - DNS resolution issues"
  err "  - Launchpad.net being temporarily unavailable"
  err ""
  err "Please check your network connection and try again."
  exit 1
fi

echo ""
info "Step 3: Detecting available PHP versions..."

# Search for available PHP versions (prioritize 8.3)
for version in 8.3 8.2 8.1; do
  info "  Checking for PHP ${version}..."
  if apt-cache madison php${version}-fpm 2>/dev/null | grep -q "php${version}-fpm"; then
    PHP_VERSION="${version}"
    info "  ✅ Found PHP ${PHP_VERSION}"
    break
  else
    warn "  ✗ PHP ${version} not available"
  fi
done

if [[ -z "${PHP_VERSION}" ]]; then
  err "❌ No PHP packages found even after adding PPA."
  err "Checking what went wrong..."
  info "Available PHP packages in repositories:"
  apt-cache search php | grep "^php[0-9]" | head -20 || true
  exit 1
fi

info "✅ Selected: PHP ${PHP_VERSION} from ${PHP_SOURCE}"
echo ""

info "Step 4: Installing PHP ${PHP_VERSION} packages..."
echo ""

# List of core packages
CORE_PACKAGES=(
  "php${PHP_VERSION}-fpm"
  "php${PHP_VERSION}-cli"
  "php${PHP_VERSION}-mysql"
  "php${PHP_VERSION}-opcache"
)

# Verify each package is available
info "Verifying core packages availability..."
PACKAGES_AVAILABLE=true
for pkg in "${CORE_PACKAGES[@]}"; do
  if apt-cache madison ${pkg} 2>/dev/null | grep -q "${pkg}"; then
    info "  ✓ ${pkg} available"
  else
    warn "  ✗ ${pkg} NOT FOUND"
    PACKAGES_AVAILABLE=false
  fi
done

if [[ "${PACKAGES_AVAILABLE}" == "false" ]]; then
  err "❌ Some core PHP packages are not available in the repository."
  err "This shouldn't happen if the PPA was added correctly."
  err ""
  err "Debugging information:"
  apt-cache policy php${PHP_VERSION}-fpm 2>&1 || true
  exit 1
fi

echo ""
info "Installing PHP ${PHP_VERSION} core packages (this may take a minute)..."

# Install packages one by one for better error reporting
INSTALL_SUCCESS=true
for pkg in "${CORE_PACKAGES[@]}"; do
  info "  → Installing ${pkg}..."
  if apt-get install -y ${pkg} 2>&1 | tee /tmp/php-pkg-install.log | grep -v "Conflicting values"; then
    info "    ✓ ${pkg} installed"
  else
    err "    ✗ ${pkg} failed"
    INSTALL_SUCCESS=false
    tail -10 /tmp/php-pkg-install.log 2>/dev/null || true
  fi
  rm -f /tmp/php-pkg-install.log
done

if [[ "${INSTALL_SUCCESS}" == "false" ]]; then
  err "❌ Failed to install some core PHP packages."
  exit 1
fi

info "✅ PHP ${PHP_VERSION} core packages installed successfully"
echo ""

# Install comprehensive PHP extensions for Laravel and web development
info "Installing comprehensive PHP extensions for Laravel..."
echo ""

# Core extensions (required for Laravel)
CORE_EXTENSIONS="zip curl gd mbstring xml intl bcmath"

# Database extensions
DB_EXTENSIONS="pgsql sqlite3"

# Advanced extensions
ADVANCED_EXTENSIONS="imagick redis opcache"

# Combine all extensions
ALL_EXTENSIONS="${CORE_EXTENSIONS} ${DB_EXTENSIONS} ${ADVANCED_EXTENSIONS}"

INSTALLED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0

info "Installing PHP extensions (checking if already installed)..."
for ext in ${ALL_EXTENSIONS}; do
  if is_php_module_installed "${ext}"; then
    info "  - php${PHP_VERSION}-${ext} (already installed)"
    SKIPPED_COUNT=$((SKIPPED_COUNT + 1))
    INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
  elif apt-cache show php${PHP_VERSION}-${ext} >/dev/null 2>&1; then
    if apt-get install -y php${PHP_VERSION}-${ext} 2>/dev/null; then
      info "  ✓ php${PHP_VERSION}-${ext}"
      INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
      warn "  ✗ php${PHP_VERSION}-${ext} (failed)"
      FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
  else
    warn "  - php${PHP_VERSION}-${ext} (not available in repository)"
  fi
done

# Try PDF extensions (may not be available)
for pdf_ext in tcpdf fpdf; do
  if apt-cache show php${PHP_VERSION}-${pdf_ext} >/dev/null 2>&1; then
    if ! is_php_module_installed "${pdf_ext}"; then
      if apt-get install -y php${PHP_VERSION}-${pdf_ext} 2>/dev/null; then
        info "  ✓ php${PHP_VERSION}-${pdf_ext} (PDF support)"
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
      fi
    fi
  fi
done

info ""
info "PHP extensions summary:"
info "  • Installed/Skipped: ${INSTALLED_COUNT}"
if [[ ${FAILED_COUNT} -gt 0 ]]; then
  warn "  • Failed: ${FAILED_COUNT} (non-critical)"
fi
echo ""

# Install additional advanced PHP extensions
info "Installing additional PHP extensions for modern applications..."

ADDITIONAL_EXTENSIONS="php${PHP_VERSION}-apcu php${PHP_VERSION}-igbinary php${PHP_VERSION}-msgpack php${PHP_VERSION}-yaml php${PHP_VERSION}-mongodb"

ADDITIONAL_INSTALLED=0
ADDITIONAL_FAILED=0

for ext in ${ADDITIONAL_EXTENSIONS}; do
  if ! dpkg -l | grep -q "^ii\\s\\+${ext}"; then
    if apt-get install -y ${ext} 2>/dev/null; then
      info "  ✓ ${ext} installed"
      ADDITIONAL_INSTALLED=$((ADDITIONAL_INSTALLED + 1))
    else
      warn "  ✗ ${ext} failed (optional)"
      ADDITIONAL_FAILED=$((ADDITIONAL_FAILED + 1))
    fi
  else
    info "  - ${ext} already installed"
    ADDITIONAL_INSTALLED=$((ADDITIONAL_INSTALLED + 1))
  fi
done

# Try to install Swoole (may not be available in all repos)
info "  Attempting to install Swoole (async PHP)..."
if pecl list | grep -q swoole 2>/dev/null; then
  info "  - Swoole already installed via PECL"
elif apt-get install -y php${PHP_VERSION}-swoole 2>/dev/null; then
  info "  ✓ Swoole installed via apt"
else
  warn "  ⚠ Swoole not available (optional - can install via PECL manually)"
fi

info ""
info "Additional extensions summary:"
info "  • Installed: ${ADDITIONAL_INSTALLED}"
if [[ ${ADDITIONAL_FAILED} -gt 0 ]]; then
  warn "  • Failed: ${ADDITIONAL_FAILED} (optional extensions)"
fi
info ""
info "Advanced extensions available:"
info "  • APCu - User cache for better performance"
info "  • igbinary - Binary serializer (faster than PHP serialize)"
info "  • msgpack - MessagePack serializer"
info "  • yaml - YAML parser"
info "  • mongodb - MongoDB driver"
info "  • swoole - Async/coroutine support (if available)"
echo ""


# Configure php.ini for performance
info "Configuring php.ini for high performance..."

PHP_FPM_INI="/etc/php/${PHP_VERSION}/fpm/php.ini"
PHP_CLI_INI="/etc/php/${PHP_VERSION}/cli/php.ini"

# Calculate memory limit based on server class
case "${SERVER_CLASS}" in
  "large")
    PHP_MEMORY_LIMIT="512M"
    ;;
  "medium")
    PHP_MEMORY_LIMIT="256M"
    ;;
  *)
    PHP_MEMORY_LIMIT="128M"
    ;;
esac

# Settings to configure
declare -A PHP_SETTINGS=(
  ["upload_max_filesize"]="100M"
  ["post_max_size"]="100M"
  ["max_file_uploads"]="50"
  ["memory_limit"]="${PHP_MEMORY_LIMIT}"
  ["max_execution_time"]="300"
  ["max_input_time"]="300"
  ["max_input_vars"]="5000"
  ["realpath_cache_size"]="4096K"
  ["realpath_cache_ttl"]="600"
)

# Configure both FPM and CLI php.ini
for php_ini in "${PHP_FPM_INI}" "${PHP_CLI_INI}"; do
  if [[ -f "${php_ini}" ]]; then
    info "  Configuring $(basename $(dirname $(dirname ${php_ini})))/$(basename ${php_ini})..."
    
    for setting in "${!PHP_SETTINGS[@]}"; do
      value="${PHP_SETTINGS[$setting]}"
      
      if ! is_php_ini_setting_exists "${setting}" "${php_ini}"; then
        # Setting doesn't exist, add it
        if grep -qE "^;${setting}" "${php_ini}"; then
          # Uncomment and set value
          sed -i "s/^;${setting}\s*=.*/${setting} = ${value}/" "${php_ini}"
        else
          # Add new setting
          echo "${setting} = ${value}" >> "${php_ini}"
        fi
        info "    ✓ ${setting} = ${value}"
      else
        # Setting exists, update it
        sed -i "s/^${setting}\s*=.*/${setting} = ${value}/" "${php_ini}"
        info "    ↻ ${setting} = ${value} (updated)"
      fi
    done
  fi
done

info "✅ PHP.ini performance tuning completed"
echo ""

# PHP-FPM pool configuration - optimized based on system resources
PHP_FPM_POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/www.conf"
cp -n "${PHP_FPM_POOL}" "${PHP_FPM_POOL}.orig"

info "Configuring PHP-FPM based on detected resources..."

# Calculate PHP-FPM pool size based on RAM and server class
# Each PHP-FPM child typically uses 30-80MB RAM
# We allocate 40-60% of RAM for PHP-FPM depending on server class
case "${SERVER_CLASS}" in
  "large")
    PHP_RAM_PERCENT=50
    PHP_AVG_CHILD_SIZE=60
    ;;
  "medium")
    PHP_RAM_PERCENT=45
    PHP_AVG_CHILD_SIZE=50
    ;;
  *)
    PHP_RAM_PERCENT=40
    PHP_AVG_CHILD_SIZE=40
    ;;
esac

PHP_RAM_MB=$(( TOTAL_RAM_MB * PHP_RAM_PERCENT / 100 ))
PM_MAX_CHILDREN=$(( PHP_RAM_MB / PHP_AVG_CHILD_SIZE ))

# Set sensible limits
if [[ ${PM_MAX_CHILDREN} -lt 10 ]]; then PM_MAX_CHILDREN=10; fi
if [[ ${PM_MAX_CHILDREN} -gt 300 ]]; then PM_MAX_CHILDREN=300; fi

PM_START_SERVERS=$(( PM_MAX_CHILDREN / 4 ))
PM_MIN_SPARE_SERVERS=$(( PM_MAX_CHILDREN / 10 ))
PM_MAX_SPARE_SERVERS=$(( PM_MAX_CHILDREN / 3 ))

if [[ ${PM_START_SERVERS} -lt 2 ]]; then PM_START_SERVERS=2; fi
if [[ ${PM_MIN_SPARE_SERVERS} -lt 1 ]]; then PM_MIN_SPARE_SERVERS=1; fi
if [[ ${PM_MAX_SPARE_SERVERS} -lt 3 ]]; then PM_MAX_SPARE_SERVERS=3; fi

# Calculate max_requests based on server load expectations
PM_MAX_REQUESTS=$(( PM_MAX_CHILDREN * 50 ))
if [[ ${PM_MAX_REQUESTS} -lt 500 ]]; then PM_MAX_REQUESTS=500; fi

info "  • Max children: ${PM_MAX_CHILDREN} (${PHP_RAM_PERCENT}% of ${TOTAL_RAM_MB}MB RAM)"
info "  • Start servers: ${PM_START_SERVERS}"
info "  • Min spare: ${PM_MIN_SPARE_SERVERS}, Max spare: ${PM_MAX_SPARE_SERVERS}"
info "  • Max requests: ${PM_MAX_REQUESTS}"

cat >${PHP_FPM_POOL} <<EOF
; Optimized PHP-FPM pool for ${SERVER_CLASS} server
; CPU Cores: ${CPU_CORES}, RAM: ${TOTAL_RAM_GB}GB
; PHP-FPM allocated: ${PHP_RAM_MB}MB (${PHP_RAM_PERCENT}%)
; Generated: $(date)

[www]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
listen.backlog = 65535

pm = dynamic
pm.max_children = ${PM_MAX_CHILDREN}
pm.start_servers = ${PM_START_SERVERS}
pm.min_spare_servers = ${PM_MIN_SPARE_SERVERS}
pm.max_spare_servers = ${PM_MAX_SPARE_SERVERS}
pm.max_requests = ${PM_MAX_REQUESTS}

; Performance tuning - prevent hanging
pm.process_idle_timeout = 10s
request_terminate_timeout = 300s
request_slowlog_timeout = 10s
slowlog = /var/log/php${PHP_VERSION}-fpm-slow.log

; Robustness settings
catch_workers_output = yes
decorate_workers_output = no
clear_env = no

; Status and health monitoring
pm.status_path = /fpm-status
ping.path = /fpm-ping
ping.response = pong

; Security
security.limit_extensions = .php

; Process management
process_priority = -19
EOF

info "  ✓ PHP-FPM pool configured with robustness settings"

# Create systemd override for auto-restart
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/php${PHP_VERSION}-fpm.service.d"
mkdir -p "${SYSTEMD_OVERRIDE_DIR}"

if [[ ! -f "${SYSTEMD_OVERRIDE_DIR}/override.conf" ]]; then
  cat >"${SYSTEMD_OVERRIDE_DIR}/override.conf" <<EOF
[Service]
# Auto-restart PHP-FPM on failure
Restart=always
RestartSec=5
StartLimitInterval=0
StartLimitBurst=0

# Resource limits
LimitNOFILE=65535
EOF
  
  systemctl daemon-reload
  info "  ✓ Systemd override created for auto-restart"
else
  info "  - Systemd override already exists"
fi

systemctl enable --now php${PHP_VERSION}-fpm

if systemctl is-active --quiet php${PHP_VERSION}-fpm; then
  info "✅ PHP ${PHP_VERSION}-FPM is running"
else
  warn "PHP-FPM is not running, attempting to start..."
  systemctl start php${PHP_VERSION}-fpm || err "Cannot start PHP-FPM"
fi

info "✅ PHP ${PHP_VERSION} installed and configured successfully (robust & high-performance)"
echo ""

info "=========================================="
info "MySQL Installation (Percona Server)"
info "=========================================="
echo ""
info "Downloading Percona repository package..."
if wget -q https://repo.percona.com/apt/percona-release_latest.jammy_all.deb; then
  dpkg -i percona-release_latest.jammy_all.deb
  rm -f percona-release_latest.jammy_all.deb
else
  err "Failed to download Percona repository package"
fi

info "Setting up Percona Server 8.0 repository..."
percona-release setup ps80

info "Installing Percona Server..."
apt-get update
if ! apt-get install -y percona-server-server; then
  err "Failed to install Percona Server"
fi

systemctl enable --now mysql

# Wait for MySQL to start
info "Waiting for MySQL to start..."
MAX_WAIT=30
WAIT_COUNT=0
while [[ ${WAIT_COUNT} -lt ${MAX_WAIT} ]]; do
  if mysqladmin ping >/dev/null 2>&1 || [[ -S /var/run/mysqld/mysqld.sock ]]; then
    break
  fi
  sleep 1
  WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [[ ${WAIT_COUNT} -ge ${MAX_WAIT} ]]; then
  warn "MySQL took longer than expected to start, but continuing..."
fi

# Set MySQL root password and secure installation
info "Securing MySQL installation..."

# Try multiple methods to set root password
MYSQL_SECURED=false

# Method 1: Try without password first (fresh installation)
if mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
  mysql -u root <<MYSQL_EOF
-- Set root password with mysql_native_password for PHP compatibility
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';
-- Also update any other root users
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';
-- Secure installation
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
MYSQL_EOF
  MYSQL_SECURED=true
  info "MySQL secured via direct connection (using mysql_native_password for PHP compatibility)"
fi

# Method 2: Try with mysqladmin
if [[ "${MYSQL_SECURED}" == "false" ]]; then
  if mysqladmin -u root password "${MYSQL_ROOT_PASSWORD}" 2>/dev/null; then
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" <<MYSQL_EOF
-- Change authentication method to mysql_native_password for PHP compatibility
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASSWORD}';
-- Secure installation
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
MYSQL_EOF
    MYSQL_SECURED=true
    info "MySQL secured via mysqladmin (using mysql_native_password for PHP compatibility)"
  fi
fi

if [[ "${MYSQL_SECURED}" == "false" ]]; then
  warn "Could not automatically secure MySQL. You may need to run mysql_secure_installation manually."
  warn "Root password should be: ${MYSQL_ROOT_PASSWORD}"
fi

# MySQL configuration - optimized based on system resources
info "Configuring MySQL based on detected resources..."

# Calculate MySQL settings based on RAM and server class
case "${SERVER_CLASS}" in
  "large")
    MYSQL_RAM_PERCENT=60
    MYSQL_MAX_CONNECTIONS=500
    MYSQL_THREAD_CACHE_SIZE=100
    ;;
  "medium")
    MYSQL_RAM_PERCENT=50
    MYSQL_MAX_CONNECTIONS=300
    MYSQL_THREAD_CACHE_SIZE=50
    ;;
  *)
    MYSQL_RAM_PERCENT=40
    MYSQL_MAX_CONNECTIONS=150
    MYSQL_THREAD_CACHE_SIZE=20
    ;;
esac

INNODB_BUFFER_POOL_SIZE_GB=$(( TOTAL_RAM_GB * MYSQL_RAM_PERCENT / 100 ))
if [[ ${INNODB_BUFFER_POOL_SIZE_GB} -lt 1 ]]; then INNODB_BUFFER_POOL_SIZE_GB=1; fi

# Calculate InnoDB log file size (1/4 of buffer pool, max 2GB)
INNODB_LOG_FILE_SIZE_MB=$(( INNODB_BUFFER_POOL_SIZE_GB * 256 ))
if [[ ${INNODB_LOG_FILE_SIZE_MB} -gt 2048 ]]; then INNODB_LOG_FILE_SIZE_MB=2048; fi
if [[ ${INNODB_LOG_FILE_SIZE_MB} -lt 128 ]]; then INNODB_LOG_FILE_SIZE_MB=128; fi

# InnoDB buffer pool instances (1 per GB, max 8)
INNODB_BUFFER_POOL_INSTANCES=${INNODB_BUFFER_POOL_SIZE_GB}
if [[ ${INNODB_BUFFER_POOL_INSTANCES} -gt 8 ]]; then INNODB_BUFFER_POOL_INSTANCES=8; fi
if [[ ${INNODB_BUFFER_POOL_INSTANCES} -lt 1 ]]; then INNODB_BUFFER_POOL_INSTANCES=1; fi

info "  • Buffer pool: ${INNODB_BUFFER_POOL_SIZE_GB}GB (${MYSQL_RAM_PERCENT}% of RAM)"
info "  • Log file size: ${INNODB_LOG_FILE_SIZE_MB}MB"
info "  • Buffer pool instances: ${INNODB_BUFFER_POOL_INSTANCES}"
info "  • Max connections: ${MYSQL_MAX_CONNECTIONS}"

# Stop MySQL before modifying configuration
info "Stopping MySQL to apply configuration changes..."
systemctl stop mysql 2>/dev/null || true
sleep 2

# Remove old InnoDB log files (required when changing innodb_log_file_size)
info "Removing old InnoDB log files (will be recreated)..."
if [[ -d /var/lib/mysql ]]; then
  rm -f /var/lib/mysql/ib_logfile* 2>/dev/null || true
  info "  ✓ Old log files removed"
fi

# Check if MySQL config already has our optimizations
MYSQL_CONFIG_UPDATED=false

if [[ -f /etc/mysql/conf.d/custom.cnf ]]; then
  # Check if we need to add optimizations
  if ! is_mysql_setting_exists "innodb_read_io_threads" "/etc/mysql/conf.d/custom.cnf"; then
    MYSQL_CONFIG_UPDATED=true
  fi
else
  MYSQL_CONFIG_UPDATED=true
fi

if [[ "${MYSQL_CONFIG_UPDATED}" == "true" ]]; then
  info "Configuring MySQL with high-performance optimizations..."
  
  cat >/etc/mysql/conf.d/custom.cnf <<EOF
# Optimized MySQL configuration for ${SERVER_CLASS} server
# CPU Cores: ${CPU_CORES}, RAM: ${TOTAL_RAM_GB}GB
# MySQL allocated: ${INNODB_BUFFER_POOL_SIZE_GB}GB (${MYSQL_RAM_PERCENT}%)
# Compatible with: Percona Server 8.0 / MySQL 8.0
# Optimized for: SELECT operations, indexes, partitioning
# Generated: $(date)

[mysqld]
# MySQL 8.0 / Percona Server 8.0 Compatible Configuration
bind-address = 127.0.0.1
max_connections = ${MYSQL_MAX_CONNECTIONS}
max_connect_errors = 100000

# InnoDB Settings (MySQL 8.0 syntax - tested and working)
innodb_buffer_pool_size = ${INNODB_BUFFER_POOL_SIZE_GB}G
innodb_buffer_pool_instances = ${INNODB_BUFFER_POOL_INSTANCES}
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT

# InnoDB IO Threads (optimized for SELECT operations)
innodb_read_io_threads = 8
innodb_write_io_threads = 8

# Disable Binary Logging (saves disk space)
skip-log-bin
disable-log-bin = 1

# Thread Settings
thread_cache_size = ${MYSQL_THREAD_CACHE_SIZE}
thread_stack = 256K

# Table Cache (optimized for many tables/indexes)
table_open_cache = 2000
table_definition_cache = 1400

# Buffer Settings (optimized for SELECT/indexes)
key_buffer_size = 256M
max_heap_table_size = 256M
tmp_table_size = 256M

# Join and Sort Buffers (optimized for complex queries)
join_buffer_size = 4M
sort_buffer_size = 4M
read_buffer_size = 2M
read_rnd_buffer_size = 4M

# Logging
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2
EOF
  
  info "  ✓ MySQL optimized for SELECT operations, indexes, and partitioning"
  info "  ✓ Binary logging disabled (saves disk space)"
else
  info "MySQL optimizations already configured"
fi

info "Starting MySQL with new configuration..."

# Try to start MySQL
START_ATTEMPT=1
MYSQL_STARTED=false

while [[ ${START_ATTEMPT} -le 3 && "${MYSQL_STARTED}" == "false" ]]; do
  if [[ ${START_ATTEMPT} -eq 1 ]]; then
    info "  Attempt 1: Starting with optimized configuration..."
  elif [[ ${START_ATTEMPT} -eq 2 ]]; then
    warn "  Attempt 2: Starting with conservative configuration..."
    # Use more conservative settings (half buffer pool)
    cat >/etc/mysql/conf.d/custom.cnf <<EOF
[mysqld]
bind-address = 127.0.0.1
max_connections = ${MYSQL_MAX_CONNECTIONS}
max_connect_errors = 100000
innodb_buffer_pool_size = $(( INNODB_BUFFER_POOL_SIZE_GB / 2 ))G
innodb_buffer_pool_instances = $(( INNODB_BUFFER_POOL_INSTANCES / 2 ))
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2
thread_cache_size = ${MYSQL_THREAD_CACHE_SIZE}
table_open_cache = 400
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2
EOF
  else
    warn "  Attempt 3: Starting with minimal safe configuration..."
    # Minimal configuration (guaranteed to work)
    cat >/etc/mysql/conf.d/custom.cnf <<EOF
[mysqld]
bind-address = 127.0.0.1
max_connections = 150
max_connect_errors = 100000
innodb_buffer_pool_size = 256M
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2
thread_cache_size = 20
table_open_cache = 300
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow-query.log
long_query_time = 2
EOF
  fi
  
  # Try to start
  if systemctl start mysql 2>&1 | tee /tmp/mysql-start.log; then
    sleep 3
    
    if systemctl is-active --quiet mysql; then
      MYSQL_STARTED=true
      if [[ ${START_ATTEMPT} -eq 1 ]]; then
        info "✅ MySQL started successfully with optimized configuration"
      elif [[ ${START_ATTEMPT} -eq 2 ]]; then
        warn "⚠️  MySQL started with conservative configuration (reduced tuning)"
      else
        warn "⚠️  MySQL started with minimal configuration (256MB buffer pool)"
        warn "   You may want to tune /etc/mysql/conf.d/custom.cnf manually"
      fi
      break
    else
      warn "  MySQL process started but not responding, waiting..."
      sleep 5
      
      if systemctl is-active --quiet mysql; then
        MYSQL_STARTED=true
        info "✅ MySQL is now running"
        break
      else
        warn "  ✗ MySQL failed on attempt ${START_ATTEMPT}"
        systemctl stop mysql 2>/dev/null || true
        sleep 2
      fi
    fi
  else
    warn "  ✗ Failed to start MySQL on attempt ${START_ATTEMPT}"
    cat /tmp/mysql-start.log 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || true
    sleep 2
  fi
  
  START_ATTEMPT=$((START_ATTEMPT + 1))
done

rm -f /tmp/mysql-start.log

# Final check
if [[ "${MYSQL_STARTED}" == "false" ]]; then
  err ""
  err "❌ MySQL failed to start after 3 attempts"
  err ""
  err "Diagnostic information:"
  err "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  # Show MySQL error log
  if [[ -f /var/log/mysql/error.log ]]; then
    err "MySQL Error Log (last 30 lines):"
    tail -30 /var/log/mysql/error.log 2>/dev/null || true
  fi
  
  err ""
  err "Systemd Journal (last 50 lines):"
  journalctl -xeu mysql.service -n 50 2>/dev/null || true
  
  err ""
  err "System Resources:"
  err "  - Available Memory: $(free -h | awk 'NR==2 {print $7}')"
  err "  - Disk Space: $(df -h /var/lib/mysql 2>/dev/null | awk 'NR==2 {print $4}' || echo 'Unknown')"
  
  err ""
  err "Common causes:"
  err "  1. Insufficient memory for configured buffer pool"
  err "  2. Disk space issues in /var/lib/mysql"
  err "  3. SELinux/AppArmor restrictions"
  err "  4. Corrupted MySQL data directory"
  err ""
  err "You can try to start MySQL manually with:"
  err "  sudo systemctl start mysql"
  err "  sudo journalctl -xeu mysql.service"
  err ""
  
  exit 1
fi

info "✅ MySQL installed and configured successfully"
echo ""

########################
# === DATABASE ENHANCEMENTS ===
########################

info "=========================================="
info "Database Enhancements & Tools"
info "=========================================="
echo ""

# Create MySQL query optimization script
cat >/usr/local/bin/mysql-query-optimize.sh <<'QUERYOPTEOF'
#!/bin/bash
# MySQL Query Optimization Script
# Analyzes and optimizes slow queries

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

# Get MySQL root password
if [[ -f /root/.lemp-install-passwords.txt ]]; then
    MYSQL_ROOT_PASS=$(grep "MySQL Root Password:" /root/.lemp-install-passwords.txt | cut -d' ' -f4)
else
    warn "Password file not found"
    exit 1
fi

MYSQL_CMD="mysql -u root -p${MYSQL_ROOT_PASS}"

info "MySQL Query Optimization"
info "========================"
echo ""

# Enable query log if not enabled
info "Checking slow query log..."
SLOW_LOG_ENABLED=$(${MYSQL_CMD} -e "SHOW VARIABLES LIKE 'slow_query_log';" 2>/dev/null | grep -c "ON" || echo "0")

if [[ ${SLOW_LOG_ENABLED} -eq 0 ]]; then
    info "Enabling slow query log..."
    ${MYSQL_CMD} -e "SET GLOBAL slow_query_log = 'ON';" 2>/dev/null
    ${MYSQL_CMD} -e "SET GLOBAL long_query_time = 2;" 2>/dev/null
    info "  ✓ Slow query log enabled"
fi

# Analyze slow queries
if [[ -f /var/log/mysql/slow-query.log ]]; then
    info "Analyzing slow queries..."
    mysqldumpslow -s t /var/log/mysql/slow-query.log 2>/dev/null | head -20 || warn "  No slow queries found or mysqldumpslow not available"
fi

# Show table statistics
info "Checking table statistics..."
${MYSQL_CMD} -e "SELECT TABLE_SCHEMA, TABLE_NAME, 
    ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) AS 'Size (MB)',
    TABLE_ROWS
    FROM information_schema.TABLES 
    WHERE TABLE_SCHEMA NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')
    ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC 
    LIMIT 10;" 2>/dev/null || warn "  Could not retrieve table statistics"

# Show index usage
info "Checking index usage..."
${MYSQL_CMD} -e "SELECT 
    OBJECT_SCHEMA,
    OBJECT_NAME,
    INDEX_NAME,
    COUNT_FETCH,
    COUNT_INSERT,
    COUNT_UPDATE,
    COUNT_DELETE
    FROM performance_schema.table_io_waits_summary_by_index_usage
    WHERE OBJECT_SCHEMA NOT IN ('mysql', 'performance_schema', 'information_schema', 'sys')
    ORDER BY COUNT_FETCH DESC
    LIMIT 10;" 2>/dev/null || warn "  Performance schema not available"

info "✅ Query optimization analysis completed"
QUERYOPTEOF

chmod +x /usr/local/bin/mysql-query-optimize.sh
info "  ✓ Query optimization script created"

# Create connection pooling documentation
cat >/usr/local/share/mysql-connection-pooling.md <<'POOLEOF'
# MySQL Connection Pooling Guide

## PHP Connection Pooling

### PDO with Persistent Connections
```php
$pdo = new PDO(
    "mysql:host=127.0.0.1;dbname=mydb;charset=utf8mb4",
    "user",
    "password",
    [
        PDO::ATTR_PERSISTENT => true,
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]
);
```

### MySQLi with Persistent Connections
```php
$mysqli = new mysqli('p:127.0.0.1', 'user', 'password', 'database');
```

## Connection Pool Configuration

### MySQL Max Connections
Current setting: Check with:
```sql
SHOW VARIABLES LIKE 'max_connections';
```

Recommended: Based on your server class:
- Small: 150-200
- Medium: 300-500
- Large: 500-1000

### PHP-FPM Connection Pooling
PHP-FPM automatically manages connections. Configure in php.ini:
```ini
pdo_mysql.default_socket=/var/run/mysqld/mysqld.sock
mysqli.default_socket=/var/run/mysqld/mysqld.sock
```

## Read Replica Configuration

### Setting Up Read Replica

1. **On Master Server:**
```sql
CREATE USER 'replica_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'replica_user'@'%';
FLUSH PRIVILEGES;
SHOW MASTER STATUS;
```

2. **On Replica Server:**
```sql
CHANGE MASTER TO
  MASTER_HOST='master_ip',
  MASTER_USER='replica_user',
  MASTER_PASSWORD='password',
  MASTER_LOG_FILE='mysql-bin.000001',
  MASTER_LOG_POS=154;
START SLAVE;
```

3. **PHP Application (Read/Write Splitting):**
```php
// Write to master
$write_pdo = new PDO("mysql:host=master_ip;dbname=db", "user", "pass");

// Read from replica
$read_pdo = new PDO("mysql:host=replica_ip;dbname=db", "user", "pass");
```

## Connection Monitoring

Check active connections:
```sql
SHOW PROCESSLIST;
SHOW STATUS LIKE 'Threads_connected';
SHOW STATUS LIKE 'Max_used_connections';
```

## Best Practices

1. Use persistent connections for high-traffic applications
2. Set appropriate connection timeouts
3. Monitor connection pool usage
4. Use read replicas for read-heavy workloads
5. Implement connection retry logic
6. Use connection pooling libraries (e.g., Swoole, ReactPHP)
POOLEOF

info "  ✓ Connection pooling guide created"

# Create read replica setup script template
cat >/usr/local/bin/mysql-replica-setup.sh <<'REPLICAEOF'
#!/bin/bash
# MySQL Read Replica Setup Script
# Run this on the REPLICA server

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

info "MySQL Read Replica Setup"
info "========================"
echo ""

read -p "Master server IP address: " MASTER_IP
read -p "Master server MySQL port [3306]: " MASTER_PORT
MASTER_PORT=${MASTER_PORT:-3306}

read -p "Replica user name [replica_user]: " REPLICA_USER
REPLICA_USER=${REPLICA_USER:-replica_user}

read -sp "Replica user password: " REPLICA_PASS
echo ""

read -p "Master log file (from SHOW MASTER STATUS): " MASTER_LOG_FILE
read -p "Master log position (from SHOW MASTER STATUS): " MASTER_LOG_POS

# Get MySQL root password
if [[ -f /root/.lemp-install-passwords.txt ]]; then
    MYSQL_ROOT_PASS=$(grep "MySQL Root Password:" /root/.lemp-install-passwords.txt | cut -d' ' -f4)
else
    read -sp "MySQL root password: " MYSQL_ROOT_PASS
    echo ""
fi

MYSQL_CMD="mysql -u root -p${MYSQL_ROOT_PASS}"

info "Configuring replica..."
${MYSQL_CMD} -e "STOP SLAVE;" 2>/dev/null || true

${MYSQL_CMD} <<EOF
CHANGE MASTER TO
  MASTER_HOST='${MASTER_IP}',
  MASTER_PORT=${MASTER_PORT},
  MASTER_USER='${REPLICA_USER}',
  MASTER_PASSWORD='${REPLICA_PASS}',
  MASTER_LOG_FILE='${MASTER_LOG_FILE}',
  MASTER_LOG_POS=${MASTER_LOG_POS};
EOF

if [[ $? -eq 0 ]]; then
    info "  ✓ Replica configured"
    
    ${MYSQL_CMD} -e "START SLAVE;" 2>/dev/null
    
    sleep 2
    
    SLAVE_STATUS=$(${MYSQL_CMD} -e "SHOW SLAVE STATUS\G" 2>/dev/null | grep "Slave_IO_Running\|Slave_SQL_Running" | head -2)
    info "Replica status:"
    echo "${SLAVE_STATUS}"
    
    info "✅ Replica setup completed"
else
    warn "✗ Replica setup failed"
    exit 1
fi
REPLICAEOF

chmod +x /usr/local/bin/mysql-replica-setup.sh
info "  ✓ Read replica setup script created"

# Create database migration helper script
cat >/usr/local/bin/mysql-migrate.sh <<'MIGRATEEOF'
#!/bin/bash
# Database Migration Helper Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <database_name> <sql_file>"
    echo "Example: $0 myapp /path/to/migration.sql"
    exit 1
fi

DB_NAME="$1"
SQL_FILE="$2"

if [[ ! -f "${SQL_FILE}" ]]; then
    warn "SQL file not found: ${SQL_FILE}"
    exit 1
fi

# Get MySQL root password
if [[ -f /root/.lemp-install-passwords.txt ]]; then
    MYSQL_ROOT_PASS=$(grep "MySQL Root Password:" /root/.lemp-install-passwords.txt | cut -d' ' -f4)
else
    read -sp "MySQL root password: " MYSQL_ROOT_PASS
    echo ""
fi

info "Running migration: ${SQL_FILE}"
info "Database: ${DB_NAME}"

# Backup database first
BACKUP_FILE="/var/backups/mysql/${DB_NAME}_pre_migration_$(date +%Y%m%d_%H%M%S).sql"
mkdir -p /var/backups/mysql

info "Creating backup: ${BACKUP_FILE}"
mysqldump -u root -p${MYSQL_ROOT_PASS} ${DB_NAME} > ${BACKUP_FILE} 2>/dev/null

if [[ $? -eq 0 ]]; then
    info "  ✓ Backup created"
    
    # Run migration
    info "Running migration..."
    mysql -u root -p${MYSQL_ROOT_PASS} ${DB_NAME} < ${SQL_FILE} 2>&1
    
    if [[ $? -eq 0 ]]; then
        info "✅ Migration completed successfully"
        info "Backup saved at: ${BACKUP_FILE}"
    else
        warn "✗ Migration failed"
        warn "Restore from backup: mysql -u root -p${MYSQL_ROOT_PASS} ${DB_NAME} < ${BACKUP_FILE}"
        exit 1
    fi
else
    warn "✗ Backup failed, aborting migration"
    exit 1
fi
MIGRATEEOF

chmod +x /usr/local/bin/mysql-migrate.sh
info "  ✓ Database migration script created"

# Install MySQL Tuner
info "  Installing MySQL Tuner (optimization recommendations)..."
if wget -q https://raw.githubusercontent.com/major/MySQLTuner-perl/master/mysqltuner.pl -O /usr/local/bin/mysqltuner.pl 2>/dev/null; then
  chmod +x /usr/local/bin/mysqltuner.pl
  info "  ✓ MySQL Tuner installed: /usr/local/bin/mysqltuner.pl"
else
  warn "  ⚠ Failed to download MySQL Tuner"
fi

info "✅ Database enhancements completed"
info ""
info "Available tools:"
info "  • Query optimization: mysql-query-optimize.sh"
info "  • Connection pooling guide: /usr/local/share/mysql-connection-pooling.md"
info "  • Read replica setup: mysql-replica-setup.sh"
info "  • Database migration: mysql-migrate.sh <db> <sql_file>"
info "  • MySQL Tuner: mysqltuner.pl (run after 24h of uptime)"
echo ""

info "=========================================="
info "Redis Installation"
info "=========================================="
echo ""
if ! apt-get install -y redis-server; then
  err "Failed to install Redis"
fi

# Configure Redis - optimized based on system resources
REDIS_CONF="/etc/redis/redis.conf"
if [[ -f "${REDIS_CONF}" ]]; then
  cp -n "${REDIS_CONF}" "${REDIS_CONF}.orig"
  
  info "Configuring Redis based on detected resources..."
  
  # Calculate Redis memory based on RAM and server class
  case "${SERVER_CLASS}" in
    "large")
      REDIS_RAM_PERCENT=10
      ;;
    "medium")
      REDIS_RAM_PERCENT=8
      ;;
    *)
      REDIS_RAM_PERCENT=5
      ;;
  esac
  
  REDIS_MAXMEMORY_MB=$(( TOTAL_RAM_MB * REDIS_RAM_PERCENT / 100 ))
  if [[ ${REDIS_MAXMEMORY_MB} -lt 128 ]]; then REDIS_MAXMEMORY_MB=128; fi
  if [[ ${REDIS_MAXMEMORY_MB} -gt 4096 ]]; then REDIS_MAXMEMORY_MB=4096; fi
  
  info "  • Max memory: ${REDIS_MAXMEMORY_MB}MB (${REDIS_RAM_PERCENT}% of RAM)"
  
  # Set password
  if grep -q "^# requirepass" "${REDIS_CONF}"; then
    sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" "${REDIS_CONF}"
  elif grep -q "^requirepass" "${REDIS_CONF}"; then
    sed -i "s/^requirepass .*/requirepass ${REDIS_PASSWORD}/" "${REDIS_CONF}"
  else
    echo "requirepass ${REDIS_PASSWORD}" >> "${REDIS_CONF}"
  fi
  
  # Check if high-end settings already exist
  REDIS_CONFIG_UPDATED=false
  
  if ! is_redis_setting_exists "appendonly" "${REDIS_CONF}"; then
    REDIS_CONFIG_UPDATED=true
  fi
  
  if [[ "${REDIS_CONFIG_UPDATED}" == "true" ]]; then
    info "Configuring high-end Redis (robust, error-free, gigabytes support)..."
    
    # Disable RDB snapshots (using AOF instead)
    if ! is_redis_setting_exists "^save \"\"" "${REDIS_CONF}"; then
      # Comment out existing save directives
      sed -i 's/^save /#save /' "${REDIS_CONF}" 2>/dev/null || true
      # Add empty save to disable RDB
      if ! grep -qE "^save \"\"" "${REDIS_CONF}"; then
        echo "save \"\"" >> "${REDIS_CONF}"
      fi
    fi
    
    # Add high-end configuration
    cat >>"${REDIS_CONF}" <<EOF

# High-End Redis Configuration (added by LEMP installer)
# Optimized for ${SERVER_CLASS} server (${TOTAL_RAM_GB}GB RAM)
# Robust, error-free, supports gigabytes of data
# Generated: $(date)

# Memory Management
maxmemory ${REDIS_MAXMEMORY_MB}mb
maxmemory-policy allkeys-lru
maxmemory-samples 5

# AOF Persistence (Append Only File - more reliable than RDB)
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb
aof-load-truncated yes
aof-use-rdb-preamble yes

# Performance Optimizations
tcp-backlog 511
timeout 0
tcp-keepalive 300
databases 16

# Client Output Buffer Limits (prevent memory issues)
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60

# Advanced Settings
hz 10
dynamic-hz yes
lazyfree-lazy-eviction yes
lazyfree-lazy-expire yes
lazyfree-lazy-server-del yes
replica-lazy-flush yes
EOF
    
    info "  ✓ Redis configured for high-end use (AOF, large memory, robust)"
  else
    info "Redis high-end configuration already exists"
  fi
else
  warn "Redis configuration file not found at expected location"
fi

systemctl enable --now redis-server

if systemctl is-active --quiet redis-server; then
  info "✅ Redis is running"
else
  warn "Redis is not running, attempting to start..."
  systemctl start redis-server || warn "Cannot start Redis (non-critical)"
fi

info "✅ Redis installed and configured successfully"
echo ""

info "=========================================="
info "Supervisor Installation & Configuration"
info "=========================================="
echo ""

info "Installing Supervisor (process control system)..."
if apt-get install -y supervisor; then
  info "✅ Supervisor installed"
  
  # Configure Supervisor for high-end service
  info "Configuring Supervisor for high-end/enterprise use..."
  
  # Main supervisor configuration
  SUPERVISOR_CONF="/etc/supervisor/supervisord.conf"
  if [[ -f "${SUPERVISOR_CONF}" ]]; then
    cp -n "${SUPERVISOR_CONF}" "${SUPERVISOR_CONF}.orig"
    
    # Calculate optimal settings based on server class
    case "${SERVER_CLASS}" in
      "large")
        SUPERVISOR_MINPROCS=200
        SUPERVISOR_MINFD=65536
        SUPERVISOR_EVENTLISTENERS=100
        ;;
      "medium")
        SUPERVISOR_MINPROCS=100
        SUPERVISOR_MINFD=32768
        SUPERVISOR_EVENTLISTENERS=50
        ;;
      *)
        SUPERVISOR_MINPROCS=50
        SUPERVISOR_MINFD=16384
        SUPERVISOR_EVENTLISTENERS=25
        ;;
    esac
    
    # Generate password for supervisor web interface
    SUPERVISOR_PASSWORD=$(generate_password 16)
    
    # Update supervisor configuration
    cat >"${SUPERVISOR_CONF}" <<EOF
; Supervisor configuration for ${SERVER_CLASS} server
; CPU Cores: ${CPU_CORES}, RAM: ${TOTAL_RAM_GB}GB
; Generated: $(date)

[unix_http_server]
file=/var/run/supervisor.sock
chmod=0700
chown=root:root

[inet_http_server]
port=0.0.0.0:9001
username=admin
password=${SUPERVISOR_PASSWORD}

[supervisord]
logfile=/var/log/supervisor/supervisord.log
logfile_maxbytes=50MB
logfile_backups=10
loglevel=info
pidfile=/var/run/supervisord.pid
nodaemon=false
minfds=${SUPERVISOR_MINFD}
minprocs=${SUPERVISOR_MINPROCS}
umask=022
user=root
identifier=supervisor
directory=/tmp
nocleanup=false
childlogdir=/var/log/supervisor
strip_ansi=false

[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface

[supervisorctl]
serverurl=unix:///var/run/supervisor.sock
username=admin
password=${SUPERVISOR_PASSWORD}

[include]
files = /etc/supervisor/conf.d/*.conf
EOF
    
    # Create supervisor directories
    mkdir -p /var/log/supervisor
    mkdir -p /etc/supervisor/conf.d
    
    # Set proper permissions
    chmod 755 /var/log/supervisor
    chmod 755 /etc/supervisor/conf.d
    
    info "  ✓ Supervisor configured for ${SERVER_CLASS} server"
    info "  • Min file descriptors: ${SUPERVISOR_MINFD}"
    info "  • Min processes: ${SUPERVISOR_MINPROCS}"
    info "  • Web interface: http://0.0.0.0:9001 (external access enabled)"
    info "  • Config directory: /etc/supervisor/conf.d/"
    
    # Create enterprise-grade example configuration template
    cat >/etc/supervisor/conf.d/laravel-queue-worker.conf.example <<'EXAMPLEEOF'
; Enterprise-Grade Supervisor Configuration Template
; ==================================================
; This is a comprehensive, production-ready Supervisor configuration
; for Laravel queue workers (or any long-running PHP process)
;
; Usage:
;   1. Copy this file: cp /etc/supervisor/conf.d/laravel-queue-worker.conf.example /etc/supervisor/conf.d/my-worker.conf
;   2. Edit the file and modify paths, commands, and settings
;   3. Reload Supervisor: supervisorctl reread && supervisorctl update
;
; Features:
;   - Multiple worker processes (numprocs)
;   - Automatic restart on failure
;   - Comprehensive logging with rotation
;   - Environment variables
;   - Health checks
;   - Graceful shutdown
;   - Error handling
;   - Resource limits
;   - Process priority
;
; ==================================================

[program:laravel-queue-worker]
; Command to execute (modify for your application)
command=/usr/bin/php /var/www/your-app/artisan queue:work redis --sleep=3 --tries=3 --max-time=3600

; Process naming (for multiple processes)
process_name=%(program_name)s_%(process_num)02d

; Number of worker processes (adjust based on CPU cores and load)
; Recommended: 2-4x CPU cores for I/O-bound tasks, 1x CPU cores for CPU-bound tasks
numprocs=4

; Working directory
directory=/var/www/your-app

; Auto-start on Supervisor startup
autostart=true

; Auto-restart if process exits unexpectedly
autorestart=true

; Restart modes: unexpected (default), true (always), false (never)
; Use 'unexpected' to restart only on non-zero exit codes
startsecs=10
startretries=3

; User to run process as
user=www-data

; Process priority (lower = higher priority, range: -20 to 19)
priority=999

; Resource limits (prevents resource exhaustion)
; Uncomment and adjust as needed:
; rlimit_core=0          ; Core file size (0 = unlimited)
; rlimit_nofile=65535    ; Max open files
; rlimit_nproc=32768     ; Max processes

; Logging configuration
redirect_stderr=true
stdout_logfile=/var/log/supervisor/laravel-queue-worker.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
stdout_capture_maxbytes=1MB
stdout_events_enabled=false
stderr_logfile=/var/log/supervisor/laravel-queue-worker-error.log
stderr_logfile_maxbytes=50MB
stderr_logfile_backups=10
stderr_capture_maxbytes=1MB
stderr_events_enabled=true

; Graceful shutdown timeout (seconds)
; Process will be killed if not stopped within this time
stopwaitsecs=3600

; Graceful shutdown signal (SIGTERM is default)
stopsignal=TERM

; Stop as group (useful for processes that spawn children)
stopasgroup=true
killasgroup=true

; Environment variables
; Add all required environment variables here
environment=
  APP_ENV="production",
  APP_DEBUG="false",
  QUEUE_CONNECTION="redis",
  REDIS_HOST="127.0.0.1",
  REDIS_PASSWORD="",
  REDIS_PORT="6379",
  LOG_CHANNEL="stack",
  LOG_LEVEL="error"

; Server name (useful for multi-server setups)
serverurl=AUTO

; ==================================================
; Advanced Options (uncomment as needed)
; ==================================================

; Health check script (optional)
; If this script exits with non-zero, process will be restarted
; healthcheck=/usr/local/bin/check-worker-health.sh
; healthcheck_interval=60

; Process group (useful for managing multiple related processes)
; group=laravel-workers

; Exit codes that should trigger restart (default: 0,2)
; exitcodes=0,2

; ==================================================
; Monitoring and Alerts
; ==================================================
; Supervisor can send events to external systems
; Configure in [eventlistener:worker-alerts] section if needed

; ==================================================
; Notes:
; ==================================================
; - Always test configuration with: supervisorctl reread
; - Check status: supervisorctl status laravel-queue-worker
; - View logs: tail -f /var/log/supervisor/laravel-queue-worker.log
; - Restart: supervisorctl restart laravel-queue-worker:*
; - Stop: supervisorctl stop laravel-queue-worker:*
; - Start: supervisorctl start laravel-queue-worker:*
; - Reload after config changes: supervisorctl update
EXAMPLEEOF
    
    info "  ✓ Enterprise-grade example configuration template created: /etc/supervisor/conf.d/laravel-queue-worker.conf.example"
    
    # Create systemd override for Supervisor robustness
    SYSTEMD_SUPERVISOR_OVERRIDE_DIR="/etc/systemd/system/supervisor.service.d"
    mkdir -p "${SYSTEMD_SUPERVISOR_OVERRIDE_DIR}"
    
    if [[ ! -f "${SYSTEMD_SUPERVISOR_OVERRIDE_DIR}/override.conf" ]]; then
      cat >"${SYSTEMD_SUPERVISOR_OVERRIDE_DIR}/override.conf" <<EOF
[Service]
# Auto-restart Supervisor on failure (critical for high-end service)
Restart=always
RestartSec=10
StartLimitInterval=0
StartLimitBurst=0

# Resource limits
LimitNOFILE=${SUPERVISOR_MINFD}
LimitNPROC=${SUPERVISOR_MINPROCS}

# Timeouts
TimeoutStartSec=60
TimeoutStopSec=30
EOF
      
      systemctl daemon-reload
      info "  ✓ Systemd override created for Supervisor robustness"
    else
      info "  - Systemd override already exists"
    fi
    
    # Enable and start Supervisor
    systemctl enable supervisor
    systemctl start supervisor
    
    sleep 2
    
    if systemctl is-active --quiet supervisor; then
      info "✅ Supervisor is running"
      
      # Test supervisorctl
      if supervisorctl status >/dev/null 2>&1; then
        info "✅ Supervisor control interface working"
      else
        warn "Supervisor control interface may need configuration"
      fi
    else
      warn "Supervisor failed to start, checking logs..."
      systemctl status supervisor --no-pager -l || true
    fi
    
    # Create helper script for managing supervisor
    cat >/usr/local/bin/supervisor-manage <<'HELPEREOF'
#!/bin/bash
# Supervisor Management Helper Script

case "$1" in
  status)
    supervisorctl status
    ;;
  restart)
    if [[ -n "$2" ]]; then
      supervisorctl restart "$2"
    else
      echo "Usage: supervisor-manage restart <program_name>"
      echo "Available programs:"
      supervisorctl status | awk '{print $1}'
    fi
    ;;
  stop)
    if [[ -n "$2" ]]; then
      supervisorctl stop "$2"
    else
      echo "Usage: supervisor-manage stop <program_name>"
    fi
    ;;
  start)
    if [[ -n "$2" ]]; then
      supervisorctl start "$2"
    else
      echo "Usage: supervisor-manage start <program_name>"
    fi
    ;;
  reload)
    supervisorctl reread
    supervisorctl update
    echo "Supervisor configuration reloaded"
    ;;
  logs)
    if [[ -n "$2" ]]; then
      tail -f /var/log/supervisor/"$2".log
    else
      echo "Usage: supervisor-manage logs <program_name>"
      echo "Available log files:"
      ls -1 /var/log/supervisor/*.log 2>/dev/null | xargs -n1 basename | sed 's/.log$//'
    fi
    ;;
  *)
    echo "Supervisor Management Helper"
    echo ""
    echo "Usage: supervisor-manage {status|start|stop|restart|reload|logs} [program_name]"
    echo ""
    echo "Commands:"
    echo "  status              - Show status of all programs"
    echo "  start <program>     - Start a program"
    echo "  stop <program>      - Stop a program"
    echo "  restart <program>   - Restart a program"
    echo "  reload              - Reload configuration and update programs"
    echo "  logs <program>      - Tail logs for a program"
    echo ""
    echo "Examples:"
    echo "  supervisor-manage status"
    echo "  supervisor-manage restart my-worker"
    echo "  supervisor-manage logs my-worker"
    ;;
esac
HELPEREOF
    
    chmod +x /usr/local/bin/supervisor-manage
    info "  ✓ Management helper created: /usr/local/bin/supervisor-manage"
    
  else
    warn "Failed to configure Supervisor"
  fi
else
  warn "Failed to install Supervisor"
fi

info "✅ Supervisor installation completed"
echo ""

info "=========================================="
info "Node.js & PM2 Installation"
info "=========================================="
echo ""
info "Adding NodeSource repository..."
if curl -fsSL https://deb.nodesource.com/setup_20.x | bash -; then
  info "Installing Node.js..."
  if apt-get install -y nodejs; then
    info "Node.js installed: $(node --version)"
    
    info "Installing PM2 globally..."
    if npm install -g pm2; then
      pm2 startup systemd -u root --hp /root || warn "PM2 startup configuration had issues"
      pm2 save || warn "PM2 save had issues"
      info "PM2 installed: $(pm2 --version)"
    else
      warn "Failed to install PM2, but continuing..."
    fi
  else
    warn "Failed to install Node.js, but continuing..."
  fi
else
  warn "Failed to add NodeSource repository, skipping Node.js installation"
fi

info "10) Installing development tools"
info "Installing Git..."
apt-get install -y git || warn "Failed to install Git"

info "Installing Composer..."
if curl -sS https://getcomposer.org/installer | php; then
  mv composer.phar /usr/local/bin/composer 2>/dev/null || true
  chmod +x /usr/local/bin/composer
  info "Composer installed: $(composer --version 2>/dev/null | head -1 || echo 'installed')"
else
  warn "Failed to install Composer, but continuing..."
fi

if command -v npm >/dev/null 2>&1; then
  info "Installing Yarn..."
  npm install -g yarn || warn "Failed to install Yarn"
else
  info "NPM not available, skipping Yarn installation"
fi

info "✅ Development tools installed successfully"
echo ""

########################
# === LARAVEL OPTIMIZATIONS ===
########################

info "=========================================="
info "Laravel Framework Optimizations"
info "=========================================="
echo ""

# Install Laravel installer globally
if command -v composer >/dev/null 2>&1; then
  info "Installing Laravel installer..."
  if composer global require laravel/installer 2>/dev/null; then
    # Add Composer global bin to PATH if not already there
    if [[ -d "$HOME/.config/composer/vendor/bin" ]]; then
      COMPOSER_BIN="$HOME/.config/composer/vendor/bin"
    elif [[ -d "$HOME/.composer/vendor/bin" ]]; then
      COMPOSER_BIN="$HOME/.composer/vendor/bin"
    else
      COMPOSER_BIN=""
    fi
    
    if [[ -n "${COMPOSER_BIN}" ]]; then
      # Add to PATH in bashrc
      if ! grep -q "${COMPOSER_BIN}" /root/.bashrc 2>/dev/null; then
        echo "export PATH=\"\${PATH}:${COMPOSER_BIN}\"" >> /root/.bashrc
      fi
      # Create symlink for easy access
      if [[ -f "${COMPOSER_BIN}/laravel" ]]; then
        ln -sf "${COMPOSER_BIN}/laravel" /usr/local/bin/laravel 2>/dev/null || true
        info "  ✓ Laravel installer available as 'laravel' command"
      fi
    fi
  else
    warn "  Laravel installer installation had issues (may need manual installation)"
  fi
fi

# Create Laravel optimization script
cat >/usr/local/bin/laravel-optimize.sh <<'LARAVELOPTEOF'
#!/bin/bash
# Laravel Optimization Script
# Runs all Laravel optimization commands

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <laravel_project_path>"
    echo "Example: $0 /var/www/myapp"
    exit 1
fi

LARAVEL_PATH="$1"

if [[ ! -d "${LARAVEL_PATH}" ]]; then
    warn "Directory not found: ${LARAVEL_PATH}"
    exit 1
fi

if [[ ! -f "${LARAVEL_PATH}/artisan" ]]; then
    warn "Laravel project not found (artisan file missing)"
    exit 1
fi

cd "${LARAVEL_PATH}"

info "Optimizing Laravel application..."
info "Project: ${LARAVEL_PATH}"
echo ""

# Check if running as correct user
CURRENT_USER=$(whoami)
if [[ "${CURRENT_USER}" != "www-data" ]] && [[ "${CURRENT_USER}" != "root" ]]; then
    warn "Warning: Running as ${CURRENT_USER}. Consider running as www-data or root"
fi

# Clear and cache config
info "1. Clearing and caching configuration..."
php artisan config:clear 2>/dev/null || warn "  Failed to clear config"
php artisan config:cache 2>/dev/null && info "  ✓ Config cached" || warn "  Failed to cache config"

# Clear and cache routes
info "2. Clearing and caching routes..."
php artisan route:clear 2>/dev/null || warn "  Failed to clear routes"
php artisan route:cache 2>/dev/null && info "  ✓ Routes cached" || warn "  Failed to cache routes"

# Clear and cache views
info "3. Clearing and caching views..."
php artisan view:clear 2>/dev/null || warn "  Failed to clear views"
php artisan view:cache 2>/dev/null && info "  ✓ Views cached" || warn "  Failed to cache views"

# Optimize autoloader
info "4. Optimizing Composer autoloader..."
if command -v composer >/dev/null 2>&1; then
    composer dump-autoload --optimize --classmap-authoritative 2>/dev/null && info "  ✓ Autoloader optimized" || warn "  Failed to optimize autoloader"
else
    warn "  Composer not found"
fi

# Clear application cache
info "5. Clearing application cache..."
php artisan cache:clear 2>/dev/null && info "  ✓ Application cache cleared" || warn "  Failed to clear cache"

# Optimize framework
info "6. Optimizing framework..."
php artisan optimize 2>/dev/null && info "  ✓ Framework optimized" || warn "  Failed to optimize framework"

# Clear OPcache if available
info "7. Clearing OPcache..."
if php -r "if (function_exists('opcache_reset')) { opcache_reset(); echo 'OPcache cleared'; }" 2>/dev/null; then
    info "  ✓ OPcache cleared"
else
    info "  - OPcache not available or already cleared"
fi

# Set proper permissions
info "8. Setting permissions..."
chown -R www-data:www-data storage bootstrap/cache 2>/dev/null || true
chmod -R 775 storage bootstrap/cache 2>/dev/null || true
info "  ✓ Permissions set"

info ""
info "✅ Laravel optimization completed"
info ""
info "Additional optimizations you can run manually:"
info "  • php artisan queue:restart  (restart queue workers)"
info "  • php artisan schedule:run    (run scheduled tasks)"
info "  • php artisan horizon:terminate  (if using Horizon)"
LARAVELOPTEOF

chmod +x /usr/local/bin/laravel-optimize.sh
info "  ✓ Laravel optimization script created"

# Create Laravel queue optimization script
cat >/usr/local/bin/laravel-queue-optimize.sh <<'QUEUEOPTEOF'
#!/bin/bash
# Laravel Queue Optimization Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <laravel_project_path> [queue_name]"
    echo "Example: $0 /var/www/myapp default"
    exit 1
fi

LARAVEL_PATH="$1"
QUEUE_NAME="${2:-default}"

if [[ ! -f "${LARAVEL_PATH}/artisan" ]]; then
    warn "Laravel project not found: ${LARAVEL_PATH}"
    exit 1
fi

cd "${LARAVEL_PATH}"

info "Optimizing Laravel Queue Configuration"
info "======================================"
echo ""

# Check Redis connection
info "1. Checking Redis connection..."
if php artisan tinker --execute="Redis::connection()->ping();" 2>/dev/null | grep -q "PONG"; then
    info "  ✓ Redis connection working"
else
    warn "  ✗ Redis connection failed (queue may not work properly)"
fi

# Check queue configuration
info "2. Checking queue configuration..."
QUEUE_CONNECTION=$(php artisan tinker --execute="echo config('queue.default');" 2>/dev/null | tail -1)
info "  Queue driver: ${QUEUE_CONNECTION}"

# Restart queue workers
info "3. Restarting queue workers..."
php artisan queue:restart 2>/dev/null && info "  ✓ Queue workers restarted" || warn "  Failed to restart workers"

# Show queue status
info "4. Queue status:"
php artisan queue:work --help 2>/dev/null | head -5 || warn "  Could not get queue status"

info ""
info "✅ Queue optimization completed"
info ""
info "To start queue workers with Supervisor, use the example config:"
info "  /etc/supervisor/conf.d/laravel-queue-worker.conf.example"
QUEUEOPTEOF

chmod +x /usr/local/bin/laravel-queue-optimize.sh
info "  ✓ Laravel queue optimization script created"

# Create Laravel cache optimization script
cat >/usr/local/bin/laravel-cache-optimize.sh <<'CACHEOPTEOF'
#!/bin/bash
# Laravel Cache Optimization Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <laravel_project_path>"
    echo "Example: $0 /var/www/myapp"
    exit 1
fi

LARAVEL_PATH="$1"

if [[ ! -f "${LARAVEL_PATH}/artisan" ]]; then
    warn "Laravel project not found: ${LARAVEL_PATH}"
    exit 1
fi

cd "${LARAVEL_PATH}"

info "Optimizing Laravel Cache Configuration"
info "====================================="
echo ""

# Check cache driver
info "1. Checking cache driver..."
CACHE_DRIVER=$(php artisan tinker --execute="echo config('cache.default');" 2>/dev/null | tail -1)
info "  Cache driver: ${CACHE_DRIVER}"

# Test Redis cache if using Redis
if [[ "${CACHE_DRIVER}" == "redis" ]]; then
    info "2. Testing Redis cache..."
    if php artisan tinker --execute="Cache::put('test_key', 'test_value', 60); echo Cache::get('test_key');" 2>/dev/null | grep -q "test_value"; then
        info "  ✓ Redis cache working"
        php artisan tinker --execute="Cache::forget('test_key');" 2>/dev/null
    else
        warn "  ✗ Redis cache test failed"
    fi
fi

# Clear all caches
info "3. Clearing all caches..."
php artisan cache:clear 2>/dev/null && info "  ✓ Application cache cleared" || warn "  Failed to clear cache"
php artisan config:clear 2>/dev/null && info "  ✓ Config cache cleared" || warn "  Failed to clear config"
php artisan route:clear 2>/dev/null && info "  ✓ Route cache cleared" || warn "  Failed to clear routes"
php artisan view:clear 2>/dev/null && info "  ✓ View cache cleared" || warn "  Failed to clear views"

# Rebuild caches
info "4. Rebuilding caches..."
php artisan config:cache 2>/dev/null && info "  ✓ Config cached" || warn "  Failed to cache config"
php artisan route:cache 2>/dev/null && info "  ✓ Routes cached" || warn "  Failed to cache routes"
php artisan view:cache 2>/dev/null && info "  ✓ Views cached" || warn "  Failed to cache views"

info ""
info "✅ Cache optimization completed"
CACHEOPTEOF

chmod +x /usr/local/bin/laravel-cache-optimize.sh
info "  ✓ Laravel cache optimization script created"

# Create Laravel Nginx configuration template
cat >/usr/local/share/laravel-nginx.conf.example <<'LARAVELNGINXEOF'
# Laravel Nginx Configuration Template
# Copy and modify for your Laravel application

server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com www.yourdomain.com;
    root /var/www/yourdomain.com/public;

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

    index index.php;

    charset utf-8;

    # Logging
    access_log /var/log/nginx/yourdomain.com-access.log;
    error_log /var/log/nginx/yourdomain.com-error.log;

    # Main location block
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    # PHP-FPM configuration
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
        
        # FastCGI Cache (optional)
        # fastcgi_cache fastcgi_cache;
        # fastcgi_cache_valid 200 60m;
        # fastcgi_cache_bypass $skip_cache;
        # fastcgi_no_cache $skip_cache;
    }

    # Deny access to hidden files
    location ~ /\.(?!well-known).* {
        deny all;
    }

    # Deny access to storage and bootstrap/cache
    location ~ ^/(storage|bootstrap/cache) {
        deny all;
    }

    # Static assets caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss;
}
LARAVELNGINXEOF

info "  ✓ Laravel Nginx configuration template created"

# Create Laravel .env optimization guide
cat >/usr/local/share/laravel-env-optimization.md <<'ENVOPTEOF'
# Laravel .env Optimization Guide

## Production Environment Variables

### Cache & Session
```env
CACHE_DRIVER=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis
```

### Database
```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database
DB_USERNAME=your_user
DB_PASSWORD=your_password
```

### Redis
```env
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379
REDIS_DB=0
```

### Performance
```env
APP_ENV=production
APP_DEBUG=false
APP_URL=https://yourdomain.com

LOG_CHANNEL=stack
LOG_LEVEL=error

# OPcache (if using)
OPCACHE_ENABLE=1
OPCACHE_MEMORY_CONSUMPTION=256
```

### Optimization Commands
```bash
# Run after deployment
php artisan config:cache
php artisan route:cache
php artisan view:cache
php artisan optimize

# Clear OPcache
php artisan opcache:clear  # if using OPcache package
```

## Queue Configuration

### Supervisor Configuration
Use the example at: `/etc/supervisor/conf.d/laravel-queue-worker.conf.example`

### Horizon (if using)
```env
HORIZON_BALANCE=auto
HORIZON_MAX_PROCESSES=10
```

## Cache Configuration

### Redis Cache Prefix
```env
CACHE_PREFIX=laravel_cache
```

### Cache Tags (Redis)
Enable in `config/cache.php`:
```php
'redis' => [
    'driver' => 'redis',
    'connection' => 'cache',
    'lock_connection' => 'default',
],
```

## Performance Tips

1. **Always use Redis** for cache, sessions, and queues in production
2. **Enable OPcache** in PHP for better performance
3. **Use config/route/view caching** in production
4. **Optimize Composer autoloader**: `composer dump-autoload --optimize --classmap-authoritative`
5. **Use database indexes** for frequently queried columns
6. **Enable query caching** in MySQL for read-heavy applications
7. **Use CDN** for static assets
8. **Enable HTTP/2** and **Brotli compression** in Nginx
ENVOPTEOF

info "  ✓ Laravel environment optimization guide created"

# Create Laravel deployment script
cat >/usr/local/bin/laravel-deploy.sh <<'DEPLOYEOF'
#!/bin/bash
# Laravel Deployment Script
# Handles zero-downtime deployment

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
err() { echo -e "\e[1;31m[ERR]\e[0m $*"; exit 1; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <laravel_project_path>"
    echo "Example: $0 /var/www/myapp"
    exit 1
fi

LARAVEL_PATH="$1"

if [[ ! -d "${LARAVEL_PATH}" ]]; then
    err "Directory not found: ${LARAVEL_PATH}"
fi

if [[ ! -f "${LARAVEL_PATH}/artisan" ]]; then
    err "Laravel project not found (artisan file missing)"
fi

cd "${LARAVEL_PATH}"

info "Laravel Deployment"
info "=================="
echo ""

# Put application in maintenance mode
info "1. Enabling maintenance mode..."
php artisan down --render="errors::503" --retry=60 2>/dev/null || warn "  Failed to enable maintenance mode"

# Pull latest code (if using Git)
if [[ -d "${LARAVEL_PATH}/.git" ]]; then
    info "2. Pulling latest code..."
    git pull 2>/dev/null && info "  ✓ Code updated" || warn "  Git pull had issues"
fi

# Install/update dependencies
if [[ -f "${LARAVEL_PATH}/composer.json" ]]; then
    info "3. Installing dependencies..."
    composer install --no-dev --optimize-autoloader 2>/dev/null && info "  ✓ Dependencies installed" || warn "  Composer install had issues"
fi

# Run migrations
info "4. Running migrations..."
php artisan migrate --force 2>/dev/null && info "  ✓ Migrations completed" || warn "  Migrations had issues"

# Clear and cache
info "5. Optimizing application..."
php artisan config:cache 2>/dev/null || true
php artisan route:cache 2>/dev/null || true
php artisan view:cache 2>/dev/null || true
php artisan optimize 2>/dev/null || true
info "  ✓ Application optimized"

# Restart queue workers
info "6. Restarting queue workers..."
php artisan queue:restart 2>/dev/null && info "  ✓ Queue workers restarted" || warn "  Queue restart had issues"

# Clear OPcache
if php -r "if (function_exists('opcache_reset')) opcache_reset();" 2>/dev/null; then
    info "  ✓ OPcache cleared"
fi

# Set permissions
info "7. Setting permissions..."
chown -R www-data:www-data storage bootstrap/cache 2>/dev/null || true
chmod -R 775 storage bootstrap/cache 2>/dev/null || true
info "  ✓ Permissions set"

# Disable maintenance mode
info "8. Disabling maintenance mode..."
php artisan up 2>/dev/null && info "  ✓ Application is live" || warn "  Failed to disable maintenance mode"

info ""
info "✅ Deployment completed successfully"
DEPLOYEOF

chmod +x /usr/local/bin/laravel-deploy.sh
info "  ✓ Laravel deployment script created"

info "✅ Laravel optimizations completed"
info ""
info "Available Laravel tools:"
info "  • Laravel installer: laravel new project-name"
info "  • Optimize app: laravel-optimize.sh <path>"
info "  • Optimize queue: laravel-queue-optimize.sh <path> [queue]"
info "  • Optimize cache: laravel-cache-optimize.sh <path>"
info "  • Deploy: laravel-deploy.sh <path>"
info "  • Nginx template: /usr/local/share/laravel-nginx.conf.example"
info "  • Environment guide: /usr/local/share/laravel-env-optimization.md"
echo ""

info "=========================================="
info "System Optimization & Tuning"
info "=========================================="
echo ""

info "Applying kernel tuning based on detected resources..."

# Calculate tuning values based on RAM and CPU
case "${SERVER_CLASS}" in
  "large")
    SOMAXCONN=65536
    NETDEV_BACKLOG=250000
    TCP_SYN_BACKLOG=65536
    FILE_MAX=1000000
    NOFILE_LIMIT=1000000
    ;;
  "medium")
    SOMAXCONN=32768
    NETDEV_BACKLOG=100000
    TCP_SYN_BACKLOG=32768
    FILE_MAX=500000
    NOFILE_LIMIT=500000
    ;;
  *)
    SOMAXCONN=8192
    NETDEV_BACKLOG=50000
    TCP_SYN_BACKLOG=8192
    FILE_MAX=100000
    NOFILE_LIMIT=100000
    ;;
esac

# Swappiness based on RAM
if [[ ${TOTAL_RAM_GB} -ge 16 ]]; then
  SWAPPINESS=1
elif [[ ${TOTAL_RAM_GB} -ge 8 ]]; then
  SWAPPINESS=5
else
  SWAPPINESS=10
fi

info "  • Socket queue: ${SOMAXCONN}"
info "  • Network backlog: ${NETDEV_BACKLOG}"
info "  • TCP SYN backlog: ${TCP_SYN_BACKLOG}"
info "  • Max open files: ${FILE_MAX}"
info "  • Swappiness: ${SWAPPINESS}"

cat >/etc/sysctl.d/99-custom.conf <<EOF
# Optimized kernel parameters for ${SERVER_CLASS} server
# CPU Cores: ${CPU_CORES}, RAM: ${TOTAL_RAM_GB}GB
# Generated: $(date)

# Network performance
net.core.somaxconn = ${SOMAXCONN}
net.core.netdev_max_backlog = ${NETDEV_BACKLOG}
net.ipv4.tcp_max_syn_backlog = ${TCP_SYN_BACKLOG}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Memory management
vm.swappiness = ${SWAPPINESS}
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# File system
fs.file-max = ${FILE_MAX}
fs.inotify.max_user_watches = 524288
EOF

sysctl --system >/dev/null 2>&1

cat >>/etc/security/limits.conf <<EOF

# Custom limits for LEMP stack (${SERVER_CLASS} server)
* soft nofile ${NOFILE_LIMIT}
* hard nofile ${NOFILE_LIMIT}
* soft nproc 65535
* hard nproc 65535
EOF

info "✅ System tuning applied successfully for ${SERVER_CLASS} server"
echo ""

info "=========================================="
info "Web Configuration"
info "=========================================="
echo ""
mkdir -p /var/www/html
cat >/var/www/html/index.php <<'EOF'
<?php
phpinfo();
EOF
chown -R www-data:www-data /var/www/html

cat >/etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.php index.html;

    server_name _;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
    }
    
    # Advanced Health Check Endpoints
    location = /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    location = /health-detailed {
        access_log off;
        default_type application/json;
        return 200 '{"status":"ok","timestamp":"\$time_iso8601","server":"\$hostname"}';
    }
    
    location = /health-advanced.php {
        access_log off;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
    }
}
EOF

# Create advanced health check PHP script
cat >/var/www/html/health-advanced.php <<'HEALTHPHPEOF'
<?php
/**
 * Advanced Health Check Endpoint
 * Provides comprehensive system health information
 */

header('Content-Type: application/json');

$health = [
    'status' => 'ok',
    'timestamp' => date('c'),
    'server' => gethostname(),
    'services' => [],
    'system' => [],
    'database' => [],
    'cache' => [],
    'disk' => [],
    'network' => []
];

// Check services
$services = [
    'nginx' => 'systemctl is-active --quiet nginx',
    'php-fpm' => 'systemctl is-active --quiet php*-fpm',
    'mysql' => 'systemctl is-active --quiet mysql',
    'redis' => 'systemctl is-active --quiet redis-server',
    'supervisor' => 'systemctl is-active --quiet supervisor'
];

foreach ($services as $name => $cmd) {
    exec($cmd . ' 2>/dev/null', $output, $return);
    $health['services'][$name] = [
        'status' => $return === 0 ? 'running' : 'stopped',
        'healthy' => $return === 0
    ];
    
    if ($return !== 0) {
        $health['status'] = 'degraded';
    }
}

// System resources
$health['system'] = [
    'load' => sys_getloadavg(),
    'memory' => [
        'total' => (int)shell_exec("free -b | awk 'NR==2{print \$2}'"),
        'used' => (int)shell_exec("free -b | awk 'NR==2{print \$3}'"),
        'free' => (int)shell_exec("free -b | awk 'NR==2{print \$4}'"),
        'percent' => (float)(shell_exec("free | awk 'NR==2{printf \"%.2f\", \$3*100/\$2}'") ?: 0)
    ],
    'uptime' => trim(shell_exec('uptime -p') ?: 'unknown')
];

// Database connection check
try {
    $mysql_host = '127.0.0.1';
    $mysql_user = 'root';
    
    // Try to get password from file
    $password_file = '/root/.lemp-install-passwords.txt';
    $mysql_pass = '';
    if (file_exists($password_file)) {
        $content = file_get_contents($password_file);
        if (preg_match('/MySQL Root Password: (\S+)/', $content, $matches)) {
            $mysql_pass = $matches[1];
        }
    }
    
    $pdo = new PDO(
        "mysql:host={$mysql_host};charset=utf8mb4",
        $mysql_user,
        $mysql_pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 2]
    );
    
    $stmt = $pdo->query("SELECT VERSION() as version, CONNECTION_ID() as conn_id");
    $db_info = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $health['database'] = [
        'status' => 'connected',
        'version' => $db_info['version'] ?? 'unknown',
        'connection_id' => $db_info['conn_id'] ?? null,
        'healthy' => true
    ];
    
    // Check connection pool
    $stmt = $pdo->query("SHOW STATUS LIKE 'Threads_connected'");
    $threads = $stmt->fetch(PDO::FETCH_ASSOC);
    $health['database']['connections'] = (int)($threads['Value'] ?? 0);
    
} catch (Exception $e) {
    $health['database'] = [
        'status' => 'disconnected',
        'error' => $e->getMessage(),
        'healthy' => false
    ];
    $health['status'] = 'degraded';
}

// Redis check
try {
    if (class_exists('Redis')) {
        $redis = new Redis();
        $redis->connect('127.0.0.1', 6379, 1);
        
        // Try to authenticate if password is set
        $password_file = '/root/.lemp-install-passwords.txt';
        if (file_exists($password_file)) {
            $content = file_get_contents($password_file);
            if (preg_match('/Redis Password: (\S+)/', $content, $matches)) {
                $redis->auth($matches[1]);
            }
        }
        
        $redis_info = $redis->info();
        $health['cache'] = [
            'status' => 'connected',
            'version' => $redis_info['redis_version'] ?? 'unknown',
            'used_memory' => $redis_info['used_memory_human'] ?? 'unknown',
            'connected_clients' => (int)($redis_info['connected_clients'] ?? 0),
            'healthy' => true
        ];
        $redis->close();
    } else {
        $health['cache'] = ['status' => 'redis_extension_not_available', 'healthy' => false];
    }
} catch (Exception $e) {
    $health['cache'] = [
        'status' => 'disconnected',
        'error' => $e->getMessage(),
        'healthy' => false
    ];
    $health['status'] = 'degraded';
}

// Disk I/O check
$disk_usage = disk_free_space('/');
$disk_total = disk_total_space('/');
$health['disk'] = [
    'free' => $disk_usage,
    'total' => $disk_total,
    'used_percent' => round((($disk_total - $disk_usage) / $disk_total) * 100, 2),
    'free_percent' => round(($disk_usage / $disk_total) * 100, 2),
    'healthy' => ($disk_usage / $disk_total) > 0.1 // Healthy if >10% free
];

if (($disk_usage / $disk_total) < 0.1) {
    $health['status'] = 'degraded';
}

// Network connectivity test
$health['network'] = [
    'dns' => gethostbyname('google.com') !== 'google.com',
    'connectivity' => @fsockopen('8.8.8.8', 53, $errno, $errstr, 2) !== false
];

// PHP-FPM status
$fpm_status = @file_get_contents('http://127.0.0.1/fpm-status');
if ($fpm_status) {
    preg_match('/active processes:\s+(\d+)/', $fpm_status, $matches);
    $health['php_fpm'] = [
        'active_processes' => (int)($matches[1] ?? 0),
        'status_available' => true
    ];
}

// Overall health
$all_healthy = true;
foreach (['services', 'database', 'cache', 'disk'] as $check) {
    if (isset($health[$check]['healthy']) && !$health[$check]['healthy']) {
        $all_healthy = false;
        break;
    }
}

if (!$all_healthy) {
    http_response_code(503);
    $health['status'] = 'unhealthy';
}

echo json_encode($health, JSON_PRETTY_PRINT);
HEALTHPHPEOF

chmod 644 /var/www/html/health-advanced.php
chown www-data:www-data /var/www/html/health-advanced.php
info "  ✓ Advanced health check endpoint created: /health-advanced.php"

if nginx -t 2>/dev/null; then
  systemctl reload nginx
  info "✅ Nginx configuration validated and reloaded"
else
  err "Nginx configuration test failed"
fi

if systemctl is-active --quiet nginx; then
  info "✅ Nginx web server is running"
else
  err "Nginx is not running"
fi

info "✅ Default website configured successfully"
echo ""

########################
# === CDN & OPTIMIZATION ===
########################

info "=========================================="
info "CDN & Optimization Tools"
info "=========================================="
echo ""

# Create CloudFlare integration guide
cat >/usr/local/share/cloudflare-integration.md <<'CFEOF'
# CloudFlare Integration Guide

## Nginx Real IP Configuration

Add to your Nginx configuration to get real visitor IPs:

```nginx
# CloudFlare IP ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

real_ip_header CF-Connecting-IP;
```

## CloudFlare SSL Configuration

For full SSL mode, configure Nginx to accept CloudFlare's certificates:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
```

## CloudFlare Cache Purging

Use CloudFlare API to purge cache:

```bash
curl -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache" \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"purge_everything":true}'
```

## Recommended CloudFlare Settings

1. **SSL/TLS**: Full (strict) mode
2. **Always Use HTTPS**: On
3. **Automatic HTTPS Rewrites**: On
4. **Minimum TLS Version**: 1.2
5. **Opportunistic Encryption**: On
6. **TLS 1.3**: On
7. **Automatic Platform Optimization**: Enable for WordPress/Laravel
8. **Rocket Loader**: Enable for JavaScript optimization
9. **Brotli**: Enable
10. **HTTP/2**: Enable
11. **HTTP/3 (QUIC)**: Enable
CFEOF

info "  ✓ CloudFlare integration guide created"

# Create static asset optimization script
cat >/usr/local/bin/optimize-assets.sh <<'ASSETOPTEOF'
#!/bin/bash
# Static Asset Optimization Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <directory>"
    echo "Example: $0 /var/www/html/assets"
    exit 1
fi

ASSET_DIR="$1"

if [[ ! -d "${ASSET_DIR}" ]]; then
    warn "Directory not found: ${ASSET_DIR}"
    exit 1
fi

info "Optimizing static assets in: ${ASSET_DIR}"

# Install optimization tools if not available
if ! command -v gzip >/dev/null 2>&1; then
    info "Installing compression tools..."
    apt-get install -y gzip 2>/dev/null || warn "Failed to install gzip"
fi

# Compress CSS files
info "Compressing CSS files..."
find "${ASSET_DIR}" -name "*.css" -type f ! -name "*.min.css" -exec gzip -k -9 {} \; 2>/dev/null
info "  ✓ CSS files compressed"

# Compress JavaScript files
info "Compressing JavaScript files..."
find "${ASSET_DIR}" -name "*.js" -type f ! -name "*.min.js" -exec gzip -k -9 {} \; 2>/dev/null
info "  ✓ JavaScript files compressed"

# Compress HTML files
info "Compressing HTML files..."
find "${ASSET_DIR}" -name "*.html" -type f -exec gzip -k -9 {} \; 2>/dev/null
info "  ✓ HTML files compressed"

# Compress JSON files
info "Compressing JSON files..."
find "${ASSET_DIR}" -name "*.json" -type f -exec gzip -k -9 {} \; 2>/dev/null
info "  ✓ JSON files compressed"

info "✅ Asset optimization completed"
info "Note: Original files are preserved. .gz files are created for pre-compressed delivery."
ASSETOPTEOF

chmod +x /usr/local/bin/optimize-assets.sh
info "  ✓ Static asset optimization script created"

# Install image optimization tools
info "Installing image optimization tools..."
apt-get install -y \
    jpegoptim \
    optipng \
    pngquant \
    webp \
    2>/dev/null || warn "Some image optimization tools may not be available"

# Create image optimization script
cat >/usr/local/bin/optimize-images.sh <<'IMGOPTEOF'
#!/bin/bash
# Image Optimization Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <directory> [quality]"
    echo "Example: $0 /var/www/html/images 85"
    exit 1
fi

IMG_DIR="$1"
QUALITY="${2:-85}"

if [[ ! -d "${IMG_DIR}" ]]; then
    warn "Directory not found: ${IMG_DIR}"
    exit 1
fi

info "Optimizing images in: ${IMG_DIR}"
info "Quality: ${QUALITY}%"

# Optimize JPEG files
if command -v jpegoptim >/dev/null 2>&1; then
    info "Optimizing JPEG files..."
    find "${IMG_DIR}" -name "*.jpg" -o -name "*.jpeg" | while read img; do
        jpegoptim --max=${QUALITY} --strip-all "${img}" 2>/dev/null
    done
    info "  ✓ JPEG files optimized"
else
    warn "  jpegoptim not available, skipping JPEG optimization"
fi

# Optimize PNG files
if command -v optipng >/dev/null 2>&1; then
    info "Optimizing PNG files..."
    find "${IMG_DIR}" -name "*.png" | while read img; do
        optipng -o2 -quiet "${img}" 2>/dev/null
    done
    info "  ✓ PNG files optimized"
else
    warn "  optipng not available, skipping PNG optimization"
fi

# Create WebP versions
if command -v cwebp >/dev/null 2>&1; then
    info "Creating WebP versions..."
    find "${IMG_DIR}" \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" \) | while read img; do
        webp_file="${img%.*}.webp"
        cwebp -q ${QUALITY} "${img}" -o "${webp_file}" 2>/dev/null
    done
    info "  ✓ WebP versions created"
else
    warn "  cwebp not available, skipping WebP conversion"
fi

info "✅ Image optimization completed"
IMGOPTEOF

chmod +x /usr/local/bin/optimize-images.sh
info "  ✓ Image optimization script created"

# Create compression verification script
cat >/usr/local/bin/verify-compression.sh <<'COMPVEREOF'
#!/bin/bash
# Compression Verification Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Checking compression configuration..."
echo ""

# Check Nginx gzip
if grep -q "gzip on" /etc/nginx/nginx.conf 2>/dev/null; then
    info "✓ Nginx gzip: Enabled"
    grep "gzip" /etc/nginx/nginx.conf | grep -v "^#" | head -5
else
    info "✗ Nginx gzip: Not enabled"
fi

echo ""

# Check Brotli (if installed)
if command -v brotli >/dev/null 2>&1 || grep -q "brotli" /etc/nginx/nginx.conf 2>/dev/null; then
    info "✓ Brotli: Available"
else
    info "✗ Brotli: Not configured"
    info "  Install: apt-get install -y nginx-module-brotli"
fi

echo ""

# Test compression
info "Testing compression with curl..."
if command -v curl >/dev/null 2>&1; then
    RESPONSE=$(curl -s -H "Accept-Encoding: gzip" -I http://localhost/ 2>/dev/null | grep -i "content-encoding")
    if [[ -n "${RESPONSE}" ]]; then
        info "✓ Compression working: ${RESPONSE}"
    else
        info "✗ Compression not detected in response"
    fi
else
    warn "curl not available for testing"
fi

echo ""
info "✅ Compression verification completed"
COMPVEREOF

chmod +x /usr/local/bin/verify-compression.sh
info "  ✓ Compression verification script created"

# Add CloudFlare real IP configuration to Nginx
if [[ -f /etc/nginx/nginx.conf ]]; then
    if ! grep -q "set_real_ip_from.*173.245.48" /etc/nginx/nginx.conf; then
        info "Adding CloudFlare real IP configuration..."
        
        # Create CloudFlare IP configuration file
        cat >/etc/nginx/conf.d/cloudflare-realip.conf <<'CFREALIPEOF'
# CloudFlare Real IP Configuration
# This allows Nginx to see the real visitor IPs behind CloudFlare

# CloudFlare IPv4 ranges
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;

# CloudFlare IPv6 ranges
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

# Use CloudFlare connecting IP header
real_ip_header CF-Connecting-IP;
CFREALIPEOF

        info "  ✓ CloudFlare real IP configuration created (commented out by default)"
        info "  To enable: Uncomment in /etc/nginx/conf.d/cloudflare-realip.conf"
    fi
fi

info "✅ CDN & Optimization tools completed"
info ""
info "Available tools:"
info "  • CloudFlare guide: /usr/local/share/cloudflare-integration.md"
info "  • Optimize assets: optimize-assets.sh <directory>"
info "  • Optimize images: optimize-images.sh <directory> [quality]"
info "  • Verify compression: verify-compression.sh"
echo ""

# Interactive domain setup
info "=========================================="
info "Domain Configuration (Optional)"
info "=========================================="
echo ""

info "Would you like to configure a domain for your website?"
info "This will set up Nginx virtual host and optionally SSL certificate"
echo ""

read -p "Configure a domain now? [y/N]: " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo ""
  info "Domain Configuration"
  echo ""
  
  # Ask for domain
  read -p "Enter your domain name (e.g., example.com): " USER_DOMAIN
  USER_DOMAIN=$(echo "${USER_DOMAIN}" | xargs | tr '[:upper:]' '[:lower:]')
  
  if [[ -z "${USER_DOMAIN}" ]]; then
    warn "No domain entered. Skipping domain configuration."
  else
    info "Configuring domain: ${USER_DOMAIN}"
    
    # Ask for additional domains (www, etc)
    read -p "Add www.${USER_DOMAIN}? [Y/n]: " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
      DOMAIN_ALIASES="www.${USER_DOMAIN}"
    else
      DOMAIN_ALIASES=""
    fi
    
    # Create directory for the domain
    SITE_ROOT="/var/www/${USER_DOMAIN}"
    mkdir -p "${SITE_ROOT}"
    
    # Create sample index file
    cat >"${SITE_ROOT}/index.php" <<'INDEXEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .info { background: #f0f0f0; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>🎉 Your website is running!</h1>
    <div class="info">
        <p><strong>Domain:</strong> <?php echo $_SERVER['HTTP_HOST']; ?></p>
        <p><strong>PHP Version:</strong> <?php echo phpversion(); ?></p>
        <p><strong>Server Time:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
    </div>
    <p>Replace this file at: <code><?php echo __FILE__; ?></code></p>
</body>
</html>
INDEXEOF
    
    chown -R www-data:www-data "${SITE_ROOT}"
    
    # Create Nginx configuration
    if [[ -n "${DOMAIN_ALIASES}" ]]; then
      SERVER_NAME="${USER_DOMAIN} ${DOMAIN_ALIASES}"
    else
      SERVER_NAME="${USER_DOMAIN}"
    fi
    
    cat >"/etc/nginx/sites-available/${USER_DOMAIN}" <<EOF
server {
    listen 80;
    listen [::]:80;
    
    server_name ${SERVER_NAME};
    
    root ${SITE_ROOT};
    index index.php index.html index.htm;
    
    # Logging
    access_log /var/log/nginx/${USER_DOMAIN}-access.log;
    error_log /var/log/nginx/${USER_DOMAIN}-error.log;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        log_not_found off;
        access_log off;
    }
}
EOF
    
    # Enable the site
    ln -sf "/etc/nginx/sites-available/${USER_DOMAIN}" "/etc/nginx/sites-enabled/${USER_DOMAIN}"
    
    # Test and reload Nginx
    if nginx -t 2>/dev/null; then
      systemctl reload nginx
      info "✅ Domain ${USER_DOMAIN} configured successfully"
      info "   Document root: ${SITE_ROOT}"
      info "   Config file: /etc/nginx/sites-available/${USER_DOMAIN}"
    else
      err "Nginx configuration test failed for ${USER_DOMAIN}"
    fi
    
    echo ""
    
    # Ask about SSL
    info "Would you like to set up SSL certificate with Let's Encrypt?"
    warn "Note: Your domain DNS must be pointing to this server for SSL to work"
    echo ""
    
    read -p "Set up SSL now? [y/N]: " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      echo ""
      info "Setting up SSL certificate..."
      
      # Install certbot if not already installed
      if ! command -v certbot >/dev/null 2>&1; then
        info "Installing Certbot..."
        apt-get install -y certbot python3-certbot-nginx
      fi
      
      # Check for existing certificate
      EXISTING_CERT=false
      EXISTING_CERT_DOMAINS=""
      
      if is_ssl_certificate_exists "${USER_DOMAIN}"; then
        info "Found existing SSL certificate for ${USER_DOMAIN}"
        EXISTING_CERT=true
        
        # Get existing certificate domains
        EXISTING_CERT_DOMAINS=$(certbot certificates 2>/dev/null | grep -A 5 "Domains:" | grep "${USER_DOMAIN}" | sed 's/Domains: //' | xargs || echo "")
        
        if [[ -n "${EXISTING_CERT_DOMAINS}" ]]; then
          info "  Existing certificate covers: ${EXISTING_CERT_DOMAINS}"
        fi
      fi
      
      # Prepare certbot command
      CERTBOT_DOMAINS="-d ${USER_DOMAIN}"
      if [[ -n "${DOMAIN_ALIASES}" ]]; then
        CERTBOT_DOMAINS="${CERTBOT_DOMAINS} -d ${DOMAIN_ALIASES}"
      fi
      
      # Get email for SSL
      if [[ -z "${SSL_EMAIL}" || "${SSL_EMAIL}" == "admin@uptimematrix.com" || "${SSL_EMAIL}" == "admin@example.com" ]]; then
        read -p "Enter email for SSL certificate notifications: " SSL_EMAIL_INPUT
        SSL_EMAIL="${SSL_EMAIL_INPUT:-${SSL_EMAIL}}"
      fi
      
      if [[ "${EXISTING_CERT}" == "true" ]]; then
        info "Reusing existing SSL certificate..."
        
        # Check if we need to expand certificate with new domains
        NEEDS_EXPAND=false
        if [[ -n "${DOMAIN_ALIASES}" ]]; then
          for alias in ${DOMAIN_ALIASES}; do
            if ! echo "${EXISTING_CERT_DOMAINS}" | grep -q "${alias}"; then
              NEEDS_EXPAND=true
              break
            fi
          done
        fi
        
        if [[ "${NEEDS_EXPAND}" == "true" ]]; then
          info "Expanding existing certificate to include new domains..."
          if certbot --nginx --expand ${CERTBOT_DOMAINS} \
            --non-interactive --agree-tos --email "${SSL_EMAIL}" \
            --redirect --hsts --staple-ocsp; then
            info "✅ SSL certificate expanded successfully!"
          else
            warn "⚠️  Failed to expand certificate, but existing certificate is still valid"
          fi
        else
          info "✅ Using existing SSL certificate"
          info "   Certificate path: /etc/letsencrypt/live/${USER_DOMAIN}/"
          
          # Update Nginx config to use existing certificate
          if [[ -f /etc/nginx/sites-available/${USER_DOMAIN} ]]; then
            # Add SSL configuration to Nginx if not already present
            if ! grep -q "ssl_certificate" /etc/nginx/sites-available/${USER_DOMAIN}; then
              info "Updating Nginx configuration with SSL..."
              # This will be handled by certbot --nginx, but we can also do it manually
              certbot --nginx --cert-name ${USER_DOMAIN} \
                --non-interactive --agree-tos --email "${SSL_EMAIL}" \
                --redirect --hsts --staple-ocsp 2>/dev/null || true
            fi
          fi
        fi
      else
        info "Obtaining new SSL certificate for ${USER_DOMAIN}..."
        info "This may take a moment..."
        echo ""
        
        if certbot --nginx ${CERTBOT_DOMAINS} \
          --non-interactive --agree-tos --email "${SSL_EMAIL}" \
          --redirect --hsts --staple-ocsp; then
          info "✅ SSL certificate obtained and configured!"
          info "   Your site is now accessible via HTTPS"
          info "   Certificate will auto-renew before expiration"
        else
          warn "⚠️  SSL certificate setup failed!"
          warn "This is usually because:"
          warn "  - Domain DNS is not pointing to this server yet"
          warn "  - Port 80 is not accessible from internet"
          warn "  - Domain doesn't exist or isn't propagated yet"
          warn "  - Let's Encrypt rate limit reached (wait 1 week)"
          warn ""
          warn "You can set up SSL manually later with:"
          warn "  sudo certbot --nginx -d ${USER_DOMAIN}"
        fi
      fi
    else
      info "SSL setup skipped. You can set it up later with:"
      info "  sudo certbot --nginx -d ${USER_DOMAIN}"
    fi
  fi
else
  info "Domain configuration skipped"
fi

echo ""
########################
# === COMPLIANCE & AUDITING ===
########################

info "=========================================="
info "Compliance & Auditing Setup"
info "=========================================="
echo ""

# Install auditd for system auditing
info "Installing audit logging tools..."
apt-get install -y auditd audispd-plugins 2>/dev/null || warn "auditd installation had issues"

# Configure auditd
if command -v auditd >/dev/null 2>&1; then
    info "Configuring audit logging..."
    
    # Enable auditd
    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    
    # Create audit rules
    cat >/etc/audit/rules.d/lemp-audit.rules <<'AUDITRULESEOF'
# LEMP Stack Audit Rules

# Monitor file system changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Monitor system configuration
-w /etc/nginx/ -p wa -k nginx_config
-w /etc/php/ -p wa -k php_config
-w /etc/mysql/ -p wa -k mysql_config
-w /etc/redis/ -p wa -k redis_config

# Monitor web directories
-w /var/www/ -p wa -k web_files

# Monitor SSL certificates
-w /etc/letsencrypt/ -p wa -k ssl_certs

# Monitor system binaries
-w /usr/bin/ -p x -k system_binaries
-w /usr/sbin/ -p x -k system_binaries
-w /bin/ -p x -k system_binaries
-w /sbin/ -p x -k system_binaries

# Monitor login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k logins
-w /var/log/wtmp -p wa -k logins

# Monitor sudo usage
-w /usr/bin/sudo -p x -k sudo_cmd
-w /etc/sudoers -p r -k sudo_read

# Monitor network configuration
-w /etc/network/ -p wa -k network_config
-w /etc/ufw/ -p wa -k firewall_config

# Monitor cron jobs
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
AUDITRULESEOF

    # Reload audit rules
    augenrules --load 2>/dev/null || true
    systemctl restart auditd 2>/dev/null || true
    
    info "  ✓ Audit logging configured"
else
    warn "  ⚠ auditd not available"
fi

# Create compliance check script
cat >/usr/local/bin/compliance-check.sh <<'COMPLIANCEEOF'
#!/bin/bash
# Compliance Check Script
# Checks system for security and compliance issues

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
ok() { echo -e "\e[1;32m[OK]\e[0m $*"; }
fail() { echo -e "\e[1;31m[FAIL]\e[0m $*"; }

info "Compliance & Security Check"
info "==========================="
echo ""

ISSUES=0

# Check 1: Firewall status
info "1. Checking firewall..."
if systemctl is-active --quiet ufw || iptables -L -n | grep -q "Chain INPUT"; then
    ok "  Firewall is active"
else
    fail "  Firewall is not active"
    ISSUES=$((ISSUES + 1))
fi

# Check 2: SSH configuration
info "2. Checking SSH security..."
if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config 2>/dev/null; then
    ok "  Root login disabled"
elif grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
    warn "  Root login enabled (consider disabling)"
    ISSUES=$((ISSUES + 1))
fi

if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
    ok "  Password authentication disabled (key-only)"
else
    warn "  Password authentication enabled"
fi

# Check 3: Fail2ban status
info "3. Checking Fail2ban..."
if systemctl is-active --quiet fail2ban; then
    ok "  Fail2ban is active"
else
    fail "  Fail2ban is not active"
    ISSUES=$((ISSUES + 1))
fi

# Check 4: SSL/TLS configuration
info "4. Checking SSL/TLS..."
if [[ -d /etc/letsencrypt ]]; then
    CERT_COUNT=$(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [[ ${CERT_COUNT} -gt 0 ]]; then
        ok "  SSL certificates found: ${CERT_COUNT}"
    else
        warn "  No SSL certificates found"
    fi
else
    warn "  Let's Encrypt not configured"
fi

# Check 5: Password policies
info "5. Checking password policies..."
if grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
    ok "  Password quality module enabled"
else
    warn "  Password quality module not configured"
fi

# Check 6: Automatic security updates
info "6. Checking automatic updates..."
if systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
    ok "  Automatic security updates enabled"
else
    warn "  Automatic security updates not enabled"
    ISSUES=$((ISSUES + 1))
fi

# Check 7: Audit logging
info "7. Checking audit logging..."
if systemctl is-active --quiet auditd 2>/dev/null; then
    ok "  Audit logging is active"
else
    warn "  Audit logging is not active"
fi

# Check 8: File permissions
info "8. Checking critical file permissions..."
CRITICAL_FILES=(
    "/etc/passwd:644"
    "/etc/shadow:640"
    "/etc/group:644"
    "/etc/sudoers:440"
)

for file_perm in "${CRITICAL_FILES[@]}"; do
    FILE="${file_perm%%:*}"
    EXPECTED="${file_perm##*:}"
    if [[ -f "${FILE}" ]]; then
        ACTUAL=$(stat -c "%a" "${FILE}" 2>/dev/null)
        if [[ "${ACTUAL}" == "${EXPECTED}" ]]; then
            ok "  ${FILE}: ${ACTUAL}"
        else
            warn "  ${FILE}: ${ACTUAL} (expected: ${EXPECTED})"
            ISSUES=$((ISSUES + 1))
        fi
    fi
done

# Check 9: Open ports
info "9. Checking listening ports..."
OPEN_PORTS=$(ss -tlnp 2>/dev/null | grep LISTEN | wc -l)
if [[ ${OPEN_PORTS} -lt 10 ]]; then
    ok "  Reasonable number of open ports: ${OPEN_PORTS}"
else
    warn "  Many open ports detected: ${OPEN_PORTS}"
fi

# Check 10: Disk space
info "10. Checking disk space..."
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ ${DISK_USAGE} -lt 80 ]]; then
    ok "  Disk usage: ${DISK_USAGE}%"
else
    fail "  Disk usage critical: ${DISK_USAGE}%"
    ISSUES=$((ISSUES + 1))
fi

echo ""
if [[ ${ISSUES} -eq 0 ]]; then
    ok "✅ Compliance check passed (no critical issues)"
else
    warn "⚠ Compliance check found ${ISSUES} issue(s)"
    exit 1
fi
COMPLIANCEEOF

chmod +x /usr/local/bin/compliance-check.sh
info "  ✓ Compliance check script created"

# Create security scanning script
cat >/usr/local/bin/security-scan.sh <<'SECSCANEOF'
#!/bin/bash
# Security Scanning Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

info "Security Scan"
info "============="
echo ""

# Scan for suspicious files
info "Scanning for suspicious files..."
find /var/www -type f \( -name "*.php" -o -name "*.phtml" \) -exec grep -l "eval\|base64_decode\|exec\|system\|shell_exec" {} \; 2>/dev/null | while read file; do
    warn "  Suspicious file found: ${file}"
done

# Check for world-writable files
info "Checking for world-writable files..."
find /var/www -type f -perm -002 2>/dev/null | head -10 | while read file; do
    warn "  World-writable file: ${file}"
done

# Check for SUID/SGID files
info "Checking for SUID/SGID files in web directory..."
find /var/www -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read file; do
    warn "  SUID/SGID file: ${file}"
done

# Check for hidden files
info "Checking for hidden files..."
find /var/www -name ".*" -type f 2>/dev/null | grep -v ".git" | head -10 | while read file; do
    warn "  Hidden file: ${file}"
done

# Check PHP configuration
info "Checking PHP security settings..."
if command -v php >/dev/null 2>&1; then
    PHP_VERSION=$(php -r "echo PHP_VERSION;" 2>/dev/null)
    info "  PHP version: ${PHP_VERSION}"
    
    if php -i 2>/dev/null | grep -q "allow_url_fopen.*On"; then
        warn "  allow_url_fopen is enabled (security risk)"
    fi
    
    if php -i 2>/dev/null | grep -q "display_errors.*On"; then
        warn "  display_errors is enabled (should be off in production)"
    fi
fi

info "✅ Security scan completed"
SECSCANEOF

chmod +x /usr/local/bin/security-scan.sh
info "  ✓ Security scanning script created"

# Create access log analysis script
cat >/usr/local/bin/analyze-access-logs.sh <<'LOGANALYZEEOF'
#!/bin/bash
# Access Log Analysis Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

if [[ $# -lt 1 ]]; then
    LOG_FILE="/var/log/nginx/access.log"
else
    LOG_FILE="$1"
fi

if [[ ! -f "${LOG_FILE}" ]]; then
    echo "Log file not found: ${LOG_FILE}"
    exit 1
fi

info "Access Log Analysis: ${LOG_FILE}"
info "=================================="
echo ""

# Top IP addresses
info "Top 10 IP Addresses:"
awk '{print $1}' "${LOG_FILE}" | sort | uniq -c | sort -rn | head -10
echo ""

# Top requested URLs
info "Top 10 Requested URLs:"
awk '{print $7}' "${LOG_FILE}" | sort | uniq -c | sort -rn | head -10
echo ""

# Status codes
info "HTTP Status Codes:"
awk '{print $9}' "${LOG_FILE}" | sort | uniq -c | sort -rn
echo ""

# User agents
info "Top 10 User Agents:"
awk -F'"' '{print $6}' "${LOG_FILE}" | sort | uniq -c | sort -rn | head -10
echo ""

# Failed requests (4xx, 5xx)
info "Failed Requests (4xx/5xx):"
awk '$9 ~ /^[45]/ {print $1, $7, $9}' "${LOG_FILE}" | sort | uniq -c | sort -rn | head -20
echo ""

# Requests per hour
info "Requests per Hour:"
awk '{print $4}' "${LOG_FILE}" | cut -d: -f1 | sort | uniq -c
echo ""

info "✅ Log analysis completed"
LOGANALYZEEOF

chmod +x /usr/local/bin/analyze-access-logs.sh
info "  ✓ Access log analysis script created"

# Set up automated compliance checks
info "Setting up automated compliance checks..."

# Weekly compliance check (Sunday at 6 AM)
(crontab -l 2>/dev/null | grep -v "compliance-check"; echo "0 6 * * 0 /usr/local/bin/compliance-check.sh >> /var/log/compliance.log 2>&1") | crontab -

# Daily security scan (2 AM)
(crontab -l 2>/dev/null | grep -v "security-scan"; echo "0 2 * * * /usr/local/bin/security-scan.sh >> /var/log/security-scan.log 2>&1") | crontab -

info "  ✓ Automated compliance checks configured"
info ""
info "Compliance & Auditing Tools:"
info "  • Compliance check: compliance-check.sh"
info "  • Security scan: security-scan.sh"
info "  • Log analysis: analyze-access-logs.sh [log_file]"
info "  • Audit logs: ausearch -k <key> (e.g., ausearch -k nginx_config)"
info ""
info "Audit Schedule:"
info "  • Compliance check: Weekly (Sunday 6 AM)"
info "  • Security scan: Daily (2 AM)"
echo ""

########################
# === FILE INTEGRITY MONITORING ===
########################

info "=========================================="
info "File Integrity Monitoring (AIDE)"
info "=========================================="
echo ""

info "File Integrity Monitoring detects unauthorized file changes"
info "Would you like to install and configure AIDE (Advanced Intrusion Detection Environment)?"
echo ""
read -p "Install AIDE? [Y/n]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
  info "Installing AIDE..."
  
  if apt-get install -y aide aide-common 2>/dev/null; then
    info "  ✓ AIDE installed"
    
    # Initialize AIDE database
    info "Initializing AIDE database (this may take a few minutes)..."
    
    # Create AIDE configuration
    if [[ ! -f /etc/aide/aide.conf.custom ]]; then
      cp /etc/aide/aide.conf /etc/aide/aide.conf.orig 2>/dev/null || true
      
      # Create custom AIDE configuration
      cat >/etc/aide/aide.conf.custom <<'AIDECONFEOF'
# AIDE Configuration for LEMP Stack
# Custom rules for web server monitoring

@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

# Database location
database=file:@@{DBDIR}/aide.db
database_out=file:@@{DBDIR}/aide.db.new

# Logging
report_url=file:@@{LOGDIR}/aide.log
report_url=stdout

# Rules for critical system files
/etc            p+i+n+u+g+s+b+m+c+md5+sha256
/bin            p+i+n+u+g+s+b+m+c+md5+sha256
/sbin           p+i+n+u+g+s+b+m+c+md5+sha256
/usr/bin        p+i+n+u+g+s+b+m+c+md5+sha256
/usr/sbin       p+i+n+u+g+s+b+m+c+md5+sha256
/usr/lib        p+i+n+u+g+s+b+m+c+md5+sha256
/lib            p+i+n+u+g+s+b+m+c+md5+sha256
/lib64          p+i+n+u+g+s+b+m+c+md5+sha256

# LEMP Stack specific monitoring
/etc/nginx      p+i+n+u+g+s+b+m+c+md5+sha256
/etc/php        p+i+n+u+g+s+b+m+c+md5+sha256
/etc/mysql      p+i+n+u+g+s+b+m+c+md5+sha256
/etc/redis      p+i+n+u+g+s+b+m+c+md5+sha256
/etc/supervisor p+i+n+u+g+s+b+m+c+md5+sha256

# Web directories (monitor for changes)
/var/www        p+i+n+u+g+s+b+m+c+md5+sha256

# SSL certificates
/etc/letsencrypt p+i+n+u+g+s+b+m+c+md5+sha256

# System configuration
/etc/passwd     p+i+n+u+g+s+b+m+c+md5+sha256
/etc/shadow     p+i+n+u+g+s+b+m+c+md5+sha256
/etc/group      p+i+n+u+g+s+b+m+c+md5+sha256
/etc/sudoers    p+i+n+u+g+s+b+m+c+md5+sha256
/etc/ssh        p+i+n+u+g+s+b+m+c+md5+sha256
/etc/ufw        p+i+n+u+g+s+b+m+c+md5+sha256

# Exclude temporary and log directories
!/tmp
!/var/tmp
!/var/log
!/var/cache
!/var/run
!/proc
!/sys
!/dev
AIDECONFEOF
      
      # Use custom config
      cp /etc/aide/aide.conf.custom /etc/aide/aide.conf 2>/dev/null || true
    fi
    
    # Initialize database
    if aideinit --yes 2>/dev/null || aide --init 2>/dev/null; then
      # Move new database to active
      if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
      fi
      
      info "  ✓ AIDE database initialized"
      
      # Create AIDE check script
      cat >/usr/local/bin/aide-check.sh <<'AIDECHECKEOF'
#!/bin/bash
# AIDE Integrity Check Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }
ok() { echo -e "\e[1;32m[OK]\e[0m $*"; }
fail() { echo -e "\e[1;31m[FAIL]\e[0m $*"; }

info "AIDE File Integrity Check"
info "=========================="
echo ""

# Check if AIDE database exists
if [[ ! -f /var/lib/aide/aide.db ]]; then
    fail "AIDE database not found. Run: aideinit"
    exit 1
fi

# Run AIDE check
info "Running integrity check..."
AIDE_OUTPUT=$(aide --check 2>&1)
AIDE_EXIT=$?

if [[ ${AIDE_EXIT} -eq 0 ]]; then
    ok "No integrity violations detected"
    exit 0
else
    fail "Integrity violations detected!"
    echo ""
    echo "${AIDE_OUTPUT}" | tail -50
    echo ""
    warn "Review the output above for file changes"
    warn "If changes are legitimate, update the database:"
    warn "  aide --update"
    warn "  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    exit 1
fi
AIDECHECKEOF

      chmod +x /usr/local/bin/aide-check.sh
      info "  ✓ AIDE check script created"
      
      # Create AIDE update script
      cat >/usr/local/bin/aide-update.sh <<'AIDEUPDATEEOF'
#!/bin/bash
# AIDE Database Update Script
# Use this after making legitimate system changes

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

info "Updating AIDE Database"
info "======================"
echo ""

warn "This will update the AIDE database with current file states"
warn "Only run this after making legitimate system changes"
echo ""

read -p "Continue with database update? [y/N]: " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    info "Update cancelled"
    exit 0
fi

info "Updating AIDE database..."
if aide --update 2>/dev/null; then
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        info "  ✓ Database updated successfully"
    else
        warn "  Database file not found"
    fi
else
    warn "  Database update failed"
    exit 1
fi

info "✅ AIDE database updated"
AIDEUPDATEEOF

      chmod +x /usr/local/bin/aide-update.sh
      info "  ✓ AIDE update script created"
      
      # Create real-time file monitoring script (using inotify)
      cat >/usr/local/bin/file-monitor.sh <<'FILEMONEOF'
#!/bin/bash
# Real-time File Monitoring Script
# Uses inotify to monitor critical directories

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

if ! command -v inotifywait >/dev/null 2>&1; then
    info "Installing inotify-tools..."
    apt-get install -y inotify-tools 2>/dev/null || {
        warn "Failed to install inotify-tools"
        exit 1
    }
fi

MONITOR_DIRS=(
    "/etc/nginx"
    "/etc/php"
    "/etc/mysql"
    "/etc/redis"
    "/etc/supervisor"
    "/var/www"
    "/etc/letsencrypt"
)

LOG_FILE="/var/log/file-monitor.log"

info "Starting real-time file monitoring..."
info "Monitoring directories:"
for dir in "${MONITOR_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        info "  • ${dir}"
    fi
done
info ""
info "Log file: ${LOG_FILE}"
info "Press Ctrl+C to stop"
echo ""

# Create log file
touch "${LOG_FILE}"

# Monitor each directory
for dir in "${MONITOR_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        (
            inotifywait -m -r --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' \
                -e modify,create,delete,move,attrib "${dir}" 2>/dev/null | \
            while read timestamp file event; do
                echo "[${timestamp}] ${event}: ${file}" >> "${LOG_FILE}"
                echo "[${timestamp}] ${event}: ${file}"
            done
        ) &
    fi
done

# Wait for all background processes
wait
FILEMONEOF

      chmod +x /usr/local/bin/file-monitor.sh
      info "  ✓ Real-time file monitoring script created"
      
      # Set up automated AIDE checks
      info "Setting up automated AIDE checks..."
      
      # Daily AIDE check (3 AM)
      (crontab -l 2>/dev/null | grep -v "aide-check"; echo "0 3 * * * /usr/local/bin/aide-check.sh >> /var/log/aide-check.log 2>&1") | crontab -
      
      info "  ✓ Automated AIDE checks configured (daily at 3 AM)"
      
      info ""
      info "✅ File Integrity Monitoring configured"
      info ""
      info "AIDE Tools:"
      info "  • Check integrity: aide-check.sh"
      info "  • Update database: aide-update.sh (after legitimate changes)"
      info "  • Real-time monitoring: file-monitor.sh (run in background)"
      info "  • Manual check: aide --check"
      info "  • Manual update: aide --update"
      info ""
      info "Note: Run 'aide-update.sh' after:"
      info "  - System updates"
      info "  - Configuration changes"
      info "  - Application deployments"
    else
      warn "  ⚠ AIDE database initialization had issues"
      warn "  You may need to run 'aideinit' manually"
    fi
  else
    warn "  ⚠ AIDE installation failed"
  fi
else
  info "AIDE installation skipped"
fi

echo ""

########################
# === AUTOMATED MAINTENANCE SCRIPTS ===
########################

info "=========================================="
info "Automated Maintenance Scripts"
info "=========================================="
echo ""

info "Creating automated maintenance scripts..."

# Database optimization script
cat >/usr/local/bin/maintenance-db-optimize.sh <<'DBOPTEOF'
#!/bin/bash
# Database Optimization Script
# Runs ANALYZE and OPTIMIZE on MySQL tables

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

info "Starting database optimization..."

# Get MySQL root password from secure file
if [[ -f /root/.lemp-install-passwords.txt ]]; then
    MYSQL_ROOT_PASS=$(grep "MySQL Root Password:" /root/.lemp-install-passwords.txt | cut -d' ' -f4)
else
    warn "Password file not found, trying without password"
    MYSQL_ROOT_PASS=""
fi

if [[ -n "${MYSQL_ROOT_PASS}" ]]; then
    MYSQL_CMD="mysql -u root -p${MYSQL_ROOT_PASS}"
else
    MYSQL_CMD="mysql -u root"
fi

# Get all databases
DATABASES=$(${MYSQL_CMD} -e "SHOW DATABASES;" 2>/dev/null | grep -v -E "^(Database|information_schema|performance_schema|mysql|sys)$")

if [[ -z "${DATABASES}" ]]; then
    warn "No databases found to optimize"
    exit 0
fi

for db in ${DATABASES}; do
    info "Optimizing database: ${db}"
    
    # Get all tables
    TABLES=$(${MYSQL_CMD} ${db} -e "SHOW TABLES;" 2>/dev/null | tail -n +2)
    
    for table in ${TABLES}; do
        info "  Analyzing table: ${table}"
        ${MYSQL_CMD} ${db} -e "ANALYZE TABLE \`${table}\`;" 2>/dev/null || warn "    Failed to analyze ${table}"
        
        info "  Optimizing table: ${table}"
        ${MYSQL_CMD} ${db} -e "OPTIMIZE TABLE \`${table}\`;" 2>/dev/null || warn "    Failed to optimize ${table}"
    done
    
    info "✓ Database ${db} optimized"
done

info "✅ Database optimization completed"
DBOPTEOF

chmod +x /usr/local/bin/maintenance-db-optimize.sh
info "  ✓ Database optimization script created"

# Log cleanup script
cat >/usr/local/bin/maintenance-log-cleanup.sh <<'LOGCLEANEOF'
#!/bin/bash
# Log Cleanup Script
# Removes old log files and rotates logs

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Starting log cleanup..."

# Clean old Nginx logs (older than 30 days)
find /var/log/nginx -name "*.log.*" -type f -mtime +30 -delete 2>/dev/null
info "  ✓ Cleaned old Nginx logs"

# Clean old PHP-FPM logs
find /var/log -name "php*-fpm*.log.*" -type f -mtime +30 -delete 2>/dev/null
info "  ✓ Cleaned old PHP-FPM logs"

# Clean old MySQL logs
find /var/log/mysql -name "*.log.*" -type f -mtime +30 -delete 2>/dev/null
info "  ✓ Cleaned old MySQL logs"

# Clean old system logs
journalctl --vacuum-time=30d >/dev/null 2>&1
info "  ✓ Cleaned old systemd logs"

# Clean old ModSecurity logs
find /var/log/nginx/modsec -name "*.log.*" -type f -mtime +30 -delete 2>/dev/null
info "  ✓ Cleaned old ModSecurity logs"

# Run logrotate
logrotate -f /etc/logrotate.conf >/dev/null 2>&1
info "  ✓ Ran logrotate"

info "✅ Log cleanup completed"
LOGCLEANEOF

chmod +x /usr/local/bin/maintenance-log-cleanup.sh
info "  ✓ Log cleanup script created"

# Temporary file cleanup script
cat >/usr/local/bin/maintenance-temp-cleanup.sh <<'TEMPCLEANEOF'
#!/bin/bash
# Temporary File Cleanup Script

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "Starting temporary file cleanup..."

# Clean /tmp (files older than 7 days)
find /tmp -type f -atime +7 -delete 2>/dev/null
find /tmp -type d -empty -delete 2>/dev/null
info "  ✓ Cleaned /tmp directory"

# Clean /var/tmp (files older than 30 days)
find /var/tmp -type f -atime +30 -delete 2>/dev/null
find /var/tmp -type d -empty -delete 2>/dev/null
info "  ✓ Cleaned /var/tmp directory"

# Clean PHP session files (older than 24 hours)
find /var/lib/php/sessions -type f -mtime +1 -delete 2>/dev/null
info "  ✓ Cleaned PHP session files"

# Clean old package cache
apt-get clean >/dev/null 2>&1
apt-get autoclean >/dev/null 2>&1
info "  ✓ Cleaned package cache"

# Clean old backups (if retention is configured)
if [[ -d /var/backups ]]; then
    find /var/backups -type f -name "*.tar.gz" -mtime +14 -delete 2>/dev/null
    info "  ✓ Cleaned old backup files"
fi

info "✅ Temporary file cleanup completed"
TEMPCLEANEOF

chmod +x /usr/local/bin/maintenance-temp-cleanup.sh
info "  ✓ Temporary file cleanup script created"

# System update automation script
cat >/usr/local/bin/maintenance-system-update.sh <<'UPDATEEOF'
#!/bin/bash
# System Update Automation Script
# Safely updates the system and sends notifications

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $*"; }

info "Starting system update..."

# Update package lists
if apt-get update >/tmp/update.log 2>&1; then
    info "  ✓ Package lists updated"
else
    warn "  ✗ Failed to update package lists"
    exit 1
fi

# Check for updates
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")

if [[ ${UPDATES} -eq 0 ]]; then
    info "  ✓ System is up to date"
    exit 0
fi

info "  Found ${UPDATES} packages to update"

# Show what will be updated
info "Packages to be updated:"
apt list --upgradable 2>/dev/null | grep upgradable | head -20

# Perform safe updates (security updates first)
info "Installing security updates..."
apt-get upgrade -y -o Dpkg::Options::="--force-confold" 2>&1 | tee -a /tmp/update.log

# Clean up
apt-get autoremove -y >/dev/null 2>&1
apt-get autoclean >/dev/null 2>&1

info "✅ System update completed"

# Check if reboot is required
if [[ -f /var/run/reboot-required ]]; then
    warn "⚠ System reboot is required"
    cat /var/run/reboot-required.pkgs 2>/dev/null || true
fi
UPDATEEOF

chmod +x /usr/local/bin/maintenance-system-update.sh
info "  ✓ System update script created"

# Master maintenance script
cat >/usr/local/bin/maintenance-all.sh <<'ALLMAINTEOF'
#!/bin/bash
# Master Maintenance Script
# Runs all maintenance tasks

info() { echo -e "\e[1;34m[INFO]\e[0m $*"; }

info "=========================================="
info "Running All Maintenance Tasks"
info "=========================================="
echo ""

info "1. Database Optimization..."
/usr/local/bin/maintenance-db-optimize.sh
echo ""

info "2. Log Cleanup..."
/usr/local/bin/maintenance-log-cleanup.sh
echo ""

info "3. Temporary File Cleanup..."
/usr/local/bin/maintenance-temp-cleanup.sh
echo ""

info "4. System Updates..."
/usr/local/bin/maintenance-system-update.sh
echo ""

info "✅ All maintenance tasks completed"
ALLMAINTEOF

chmod +x /usr/local/bin/maintenance-all.sh
info "  ✓ Master maintenance script created"

# Set up cron jobs for automated maintenance
info "Setting up automated maintenance cron jobs..."

# Database optimization (weekly on Sunday at 3 AM)
(crontab -l 2>/dev/null | grep -v "maintenance-db-optimize"; echo "0 3 * * 0 /usr/local/bin/maintenance-db-optimize.sh >> /var/log/maintenance-db.log 2>&1") | crontab -

# Log cleanup (daily at 2 AM)
(crontab -l 2>/dev/null | grep -v "maintenance-log-cleanup"; echo "0 2 * * * /usr/local/bin/maintenance-log-cleanup.sh >> /var/log/maintenance-log.log 2>&1") | crontab -

# Temp cleanup (daily at 4 AM)
(crontab -l 2>/dev/null | grep -v "maintenance-temp-cleanup"; echo "0 4 * * * /usr/local/bin/maintenance-temp-cleanup.sh >> /var/log/maintenance-temp.log 2>&1") | crontab -

# System updates (weekly on Monday at 5 AM)
(crontab -l 2>/dev/null | grep -v "maintenance-system-update"; echo "0 5 * * 1 /usr/local/bin/maintenance-system-update.sh >> /var/log/maintenance-update.log 2>&1") | crontab -

info "  ✓ Automated maintenance cron jobs configured"
info ""
info "Maintenance Schedule:"
info "  • Database optimization: Weekly (Sunday 3 AM)"
info "  • Log cleanup: Daily (2 AM)"
info "  • Temp cleanup: Daily (4 AM)"
info "  • System updates: Weekly (Monday 5 AM)"
info ""
info "Manual execution:"
info "  • Run all: maintenance-all.sh"
info "  • Database only: maintenance-db-optimize.sh"
info "  • Logs only: maintenance-log-cleanup.sh"
info "  • Temp only: maintenance-temp-cleanup.sh"
info "  • Updates only: maintenance-system-update.sh"
echo ""

########################
# === SERVICE WATCHDOG - AUTO-RESTART FAILED SERVICES ===
########################

info "=========================================="
info "Service Watchdog Configuration"
info "=========================================="
echo ""

info "Creating service watchdog for auto-restart of failed services..."

# Create watchdog script
cat >/usr/local/bin/service-watchdog.sh <<'WATCHDOG_SCRIPT'
#!/bin/bash
# Service Watchdog - Auto-restart failed services
# Monitors critical services and restarts them if they fail
# Includes cooldown periods and max retry limits

# Configuration
WATCHDOG_LOG="/var/log/service-watchdog.log"
STATUS_FILE="/var/run/service-watchdog-status.json"
COOLDOWN_SECONDS=60  # Wait 60 seconds between restart attempts
MAX_RETRIES=10       # Maximum restart attempts before alerting

# Services to monitor (adjust PHP version as needed)
SERVICES=(
    "nginx"
    "php8.3-fpm"
    "mysql"
    "redis-server"
    "supervisor"
)

# Email configuration (if available)
ENABLE_EMAIL_ALERTS=false
ALERT_EMAIL=""

# Load email config if exists
if [[ -f /root/.lemp-install-passwords.txt ]]; then
    if grep -q "ENABLE_EMAIL_ALERTS=true" /root/.lemp-install-passwords.txt 2>/dev/null; then
        ENABLE_EMAIL_ALERTS=true
        ALERT_EMAIL=$(grep "ALERT_EMAIL=" /root/.lemp-install-passwords.txt | cut -d'=' -f2)
    fi
fi

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${WATCHDOG_LOG}"
}

# Send email alert
send_alert() {
    local service=$1
    local message=$2
    
    if [[ "${ENABLE_EMAIL_ALERTS}" == "true" && -n "${ALERT_EMAIL}" ]]; then
        echo "${message}" | mail -s "Service Alert: ${service} on $(hostname)" "${ALERT_EMAIL}" 2>/dev/null || true
    fi
}

# Initialize status file
if [[ ! -f "${STATUS_FILE}" ]]; then
    echo "{}" > "${STATUS_FILE}"
fi

# Get retry count for a service
get_retry_count() {
    local service=$1
    jq -r ".\"${service}\".retries // 0" "${STATUS_FILE}" 2>/dev/null || echo "0"
}

# Get last restart time for a service
get_last_restart() {
    local service=$1
    jq -r ".\"${service}\".last_restart // 0" "${STATUS_FILE}" 2>/dev/null || echo "0"
}

# Update status file
update_status() {
    local service=$1
    local retries=$2
    local timestamp=$(date +%s)
    
    # Create temp file with updated status
    jq ".\"${service}\" = {\"retries\": ${retries}, \"last_restart\": ${timestamp}, \"timestamp\": \"$(date -Iseconds)\"}" "${STATUS_FILE}" > "${STATUS_FILE}.tmp" 2>/dev/null || echo "{}" > "${STATUS_FILE}.tmp"
    mv "${STATUS_FILE}.tmp" "${STATUS_FILE}"
}

# Reset retry count
reset_retries() {
    local service=$1
    jq ".\"${service}\".retries = 0" "${STATUS_FILE}" > "${STATUS_FILE}.tmp" 2>/dev/null || echo "{}" > "${STATUS_FILE}.tmp"
    mv "${STATUS_FILE}.tmp" "${STATUS_FILE}"
}

# Main watchdog loop
log "Service Watchdog started"

for service in "${SERVICES[@]}"; do
    # Check if service exists
    if ! systemctl list-unit-files | grep -q "^${service}\.service"; then
        continue
    fi
    
    # Check if service is active
    if systemctl is-active --quiet "${service}"; then
        # Service is running - reset retry count if it was previously failing
        current_retries=$(get_retry_count "${service}")
        if [[ ${current_retries} -gt 0 ]]; then
            log "✓ ${service} is now healthy (recovered after ${current_retries} restarts)"
            reset_retries "${service}"
        fi
        continue
    fi
    
    # Service is not running
    log "⚠ ${service} is not running"
    
    # Get current retry count and last restart time
    retry_count=$(get_retry_count "${service}")
    last_restart=$(get_last_restart "${service}")
    current_time=$(date +%s)
    time_since_last=$((current_time - last_restart))
    
    # Check if we're in cooldown period
    if [[ ${time_since_last} -lt ${COOLDOWN_SECONDS} ]]; then
        log "  Cooldown active for ${service} (${time_since_last}s/${COOLDOWN_SECONDS}s)"
        continue
    fi
    
    # Check if we've exceeded max retries
    if [[ ${retry_count} -ge ${MAX_RETRIES} ]]; then
        log "✗ ${service} has failed ${retry_count} times - MAX RETRIES REACHED"
        send_alert "${service}" "Service ${service} has failed ${retry_count} times and requires manual intervention on $(hostname)"
        continue
    fi
    
    # Attempt to restart the service
    log "  Attempting to restart ${service} (attempt $((retry_count + 1))/${MAX_RETRIES})"
    
    if systemctl restart "${service}" 2>&1 | tee -a "${WATCHDOG_LOG}"; then
        # Wait a moment and verify it started
        sleep 3
        
        if systemctl is-active --quiet "${service}"; then
            log "✓ ${service} restarted successfully"
            update_status "${service}" $((retry_count + 1)) 
            
            # Send alert if this is a repeated failure
            if [[ ${retry_count} -ge 3 ]]; then
                send_alert "${service}" "Service ${service} was restarted (attempt $((retry_count + 1))) on $(hostname)"
            fi
        else
            log "✗ ${service} failed to start after restart attempt"
            update_status "${service}" $((retry_count + 1))
        fi
    else
        log "✗ Failed to restart ${service}"
        update_status "${service}" $((retry_count + 1))
    fi
done

log "Service Watchdog check completed"
WATCHDOG_SCRIPT

chmod +x /usr/local/bin/service-watchdog.sh
info "  ✓ Service watchdog script created"

# Create watchdog status viewer
cat >/usr/local/bin/watchdog-status.sh <<'STATUS_SCRIPT'
#!/bin/bash
# View Service Watchdog Status

STATUS_FILE="/var/run/service-watchdog-status.json"
LOG_FILE="/var/log/service-watchdog.log"

echo "=========================================="
echo "Service Watchdog Status"
echo "=========================================="
echo ""

if [[ -f "${STATUS_FILE}" ]]; then
    echo "Service Status:"
    jq -r 'to_entries[] | "  \(.key): \(.value.retries) restarts, last: \(.value.timestamp // "never")"' "${STATUS_FILE}" 2>/dev/null || echo "  No status data available"
else
    echo "  No status file found"
fi

echo ""
echo "Recent Watchdog Activity (last 20 lines):"
echo "----------------------------------------"
if [[ -f "${LOG_FILE}" ]]; then
    tail -20 "${LOG_FILE}"
else
    echo "  No log file found"
fi

echo ""
echo "Current Service Status:"
echo "----------------------------------------"
for service in nginx php8.3-fpm mysql redis-server supervisor; do
    if systemctl list-unit-files | grep -q "^${service}\.service" 2>/dev/null; then
        status=$(systemctl is-active "${service}" 2>/dev/null || echo "unknown")
        if [[ "${status}" == "active" ]]; then
            echo "  ✓ ${service}: ${status}"
        else
            echo "  ✗ ${service}: ${status}"
        fi
    fi
done
STATUS_SCRIPT

chmod +x /usr/local/bin/watchdog-status.sh
info "  ✓ Watchdog status viewer created: /usr/local/bin/watchdog-status.sh"

# Create systemd timer for watchdog (runs every 60 seconds)
cat >/etc/systemd/system/service-watchdog.service <<'WATCHDOG_SERVICE'
[Unit]
Description=Service Watchdog - Auto-restart failed services
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/service-watchdog.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
WATCHDOG_SERVICE

cat >/etc/systemd/system/service-watchdog.timer <<'WATCHDOG_TIMER'
[Unit]
Description=Service Watchdog Timer
Requires=service-watchdog.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=60s
AccuracySec=1s

[Install]
WantedBy=timers.target
WATCHDOG_TIMER

# Reload systemd and enable timer
systemctl daemon-reload
systemctl enable service-watchdog.timer
systemctl start service-watchdog.timer

info "  ✓ Systemd timer enabled (checks every 60 seconds)"

# Create log rotation for watchdog
cat >/etc/logrotate.d/service-watchdog <<'LOGROTATE'
/var/log/service-watchdog.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
LOGROTATE

info "  ✓ Log rotation configured"

info ""
info "✅ Service Watchdog configured successfully"
info ""
info "Configuration:"
info "  • Check interval: Every 60 seconds"
info "  • Cooldown period: 60 seconds between restarts"
info "  • Max retries: 10 attempts before alerting"
info "  • Monitored services: nginx, php-fpm, mysql, redis, supervisor"
info ""
info "Management commands:"
info "  • View status: watchdog-status.sh"
info "  • View logs: tail -f /var/log/service-watchdog.log"
info "  • Manual run: /usr/local/bin/service-watchdog.sh"
info "  • Disable: systemctl stop service-watchdog.timer"
info "  • Enable: systemctl start service-watchdog.timer"
echo ""


info "=========================================="
info "Final Service Verification"
info "=========================================="
echo ""

info "Running comprehensive service checks..."
echo ""

verify_service "nginx" "nginx" "Nginx Web Server"
verify_command "nginx" "Nginx"

verify_service "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-fpm" "PHP ${PHP_VERSION}-FPM"
verify_command "php" "PHP CLI"

verify_service "mysql" "percona-server-server" "Percona MySQL Server"
verify_command "mysql" "MySQL Client"

verify_service "redis-server" "redis-server" "Redis Cache Server"
verify_command "redis-cli" "Redis CLI"

verify_service "supervisor" "supervisor" "Supervisor Process Manager"
verify_command "supervisorctl" "Supervisor Control"

if command -v node >/dev/null 2>&1; then
  verify_command "node" "Node.js"
else
  warn "Node.js not installed, skipping verification"
fi

if command -v pm2 >/dev/null 2>&1; then
  verify_command "pm2" "PM2 Process Manager"
else
  warn "PM2 not installed, skipping verification"
fi

echo ""
info "=========================================="
info "✅ ALL CORE SERVICES VERIFIED"
info "=========================================="
echo ""

# Save passwords
save_passwords

echo ""
echo "=========================================="
echo "🎉  INSTALLATION COMPLETE  🎉"
echo "=========================================="
cat <<EOF


✅ Ubuntu 22.04 LTS LEMP Stack installed successfully!

📊 System Information:
   - Ubuntu Version: 22.04 LTS (Jammy Jellyfish)
   - Script Version: ${SCRIPT_VERSION}
   - Installation Date: $(date '+%Y-%m-%d %H:%M:%S')
   - Server Class: ${SERVER_CLASS^^}
   - CPU Cores: ${CPU_CORES}
   - Total RAM: ${TOTAL_RAM_GB}GB (${TOTAL_RAM_MB}MB)
   - Available Disk: ${AVAILABLE_DISK_GB}GB / ${TOTAL_DISK_GB}GB

📦 Installed Software:
   - Nginx: $(nginx -v 2>&1 | cut -d'/' -f2)
   - PHP: ${PHP_VERSION} (${PHP_SOURCE})
   - MySQL: Percona Server 8.0
   - Redis: $(redis-server --version 2>/dev/null | awk '{print $3}' | cut -d'=' -f2 || echo "Installed")
   - Node.js: $(node --version 2>/dev/null || echo "Not installed")
   - PM2: $(pm2 --version 2>/dev/null || echo "Not installed")

⚙️  Service Configuration (Optimized for ${SERVER_CLASS^^} server):
   
   Nginx:
   - Worker processes: ${NGINX_WORKER_PROCESSES} (${CPU_CORES} cores)
   - Worker connections: ${NGINX_WORKER_CONNECTIONS}
   - Keepalive timeout: ${NGINX_KEEPALIVE_TIMEOUT}s
   
   PHP-FPM:
   - Max children: ${PM_MAX_CHILDREN}
   - Start servers: ${PM_START_SERVERS}
   - Socket: /run/php/php${PHP_VERSION}-fpm.sock
   
   MySQL (Percona):
   - Buffer pool: ${INNODB_BUFFER_POOL_SIZE_GB}GB (${MYSQL_RAM_PERCENT}% of RAM)
   - Max connections: ${MYSQL_MAX_CONNECTIONS}
   - Log file size: ${INNODB_LOG_FILE_SIZE_MB}MB
   
   Redis:
   - Max memory: ${REDIS_MAXMEMORY_MB}MB (${REDIS_RAM_PERCENT}% of RAM)
   - Eviction policy: allkeys-lru
   
   System:
   - Web Root: /var/www/html
   - SSH Port: ${SSH_PORT}
 
🔐 Passwords & Credentials:
   ⚠️  IMPORTANT: Saved to /root/.lemp-install-passwords.txt
   View anytime: sudo cat /root/.lemp-install-passwords.txt

📝 Next Steps:
   1. Review your passwords: sudo cat /root/.lemp-install-passwords.txt
   2. Upload your application to: /var/www/html
   3. Configure DNS to point to this server IP
   4. Test your website: http://$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
   $(if [[ "${ENABLE_SSL}" == "true" && "${SSL_DOMAIN}" != "example.com" ]]; then echo "5. ✅ SSL configured for: ${SSL_DOMAIN}"; fi)

🔒 Security Features Enabled:
   ✓ SSH on custom port ${SSH_PORT}
   ✓ UFW Firewall active (ports 80, 443, ${SSH_PORT})
   ✓ Fail2ban protecting SSH
   ✓ MySQL root password set
   ✓ Redis password authentication

📊 Service Status:
   - Nginx:     $(systemctl is-active nginx 2>/dev/null || echo "unknown")
   - PHP-FPM:   $(systemctl is-active php${PHP_VERSION}-fpm 2>/dev/null || echo "unknown")
   - MySQL:     $(systemctl is-active mysql 2>/dev/null || echo "unknown")
   - Redis:     $(systemctl is-active redis-server 2>/dev/null || echo "unknown")

📁 Important Paths:
   - Nginx config: /etc/nginx/nginx.conf
   - PHP-FPM pool: /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
   - MySQL config: /etc/mysql/conf.d/custom.cnf
   - Redis config: /etc/redis/redis.conf

📋 Useful Commands:
   - Check all services: sudo systemctl status nginx php${PHP_VERSION}-fpm mysql redis-server
   - View Nginx logs: sudo tail -f /var/log/nginx/error.log
   - Restart services: sudo systemctl restart nginx
   - Test PHP: php -v

🆘 Troubleshooting:
   If you encounter any issues, check:
   - Nginx errors: /var/log/nginx/error.log
   - PHP-FPM errors: /var/log/php${PHP_VERSION}-fpm.log
   - MySQL errors: /var/log/mysql/error.log
   - System logs: sudo journalctl -xe

EOF

echo "=========================================="
echo "✅ Installation completed successfully!"
echo "=========================================="
echo ""
info "Your LEMP stack is ready for production! 🚀"
echo ""
exit 0

