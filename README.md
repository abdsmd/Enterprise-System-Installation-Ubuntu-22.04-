# 🚀 Enterprise LEMP Stack Installer for Ubuntu 22.04 LTS

<div align="center">

![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Nginx](https://img.shields.io/badge/Nginx-Latest-009639?logo=nginx&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-8.3%2F8.2%2F8.1-777BB4?logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-Percona%208.0-4479A1?logo=mysql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Latest-DC382D?logo=redis&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**A production-ready, enterprise-grade LEMP stack installation script with intelligent auto-tuning, security hardening, and comprehensive management tools.**

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Troubleshooting](#-troubleshooting) • [Contributing](#-contributing)

</div>

---

## ⚠️ IMPORTANT COMPATIBILITY NOTICE

**This script is designed EXCLUSIVELY for Ubuntu 22.04 LTS (Jammy Jellyfish).**

- ✅ **Works on**: Ubuntu 22.04 LTS
- ❌ **Does NOT work on**: Ubuntu 24.04, 20.04, 18.04, Debian, CentOS, or any other distribution
- 🔒 **Version check**: The script will automatically verify and exit if not running on Ubuntu 22.04

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [What Gets Installed](#-what-gets-installed)
- [System Requirements](#-system-requirements)
- [Quick Start](#-quick-start)
- [Installation Guide](#-installation-guide)
  - [Interactive Configuration](#interactive-configuration)
  - [Installation Process](#installation-process)
- [Post-Installation](#-post-installation)
- [Feature Documentation](#-feature-documentation)
  - [Nginx Configuration](#nginx-configuration)
  - [PHP-FPM Optimization](#php-fpm-optimization)
  - [MySQL/Percona Tuning](#mysqlpercona-tuning)
  - [Redis Configuration](#redis-configuration)
  - [Security Features](#security-features)
  - [Backup System](#backup-system)
  - [SSL/TLS Setup](#ssltls-setup)
- [Management & Utilities](#-management--utilities)
- [Troubleshooting](#-troubleshooting)
- [Performance Tuning](#-performance-tuning)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

This automated installation script transforms a fresh Ubuntu 22.04 LTS server into a production-ready web hosting environment in 15-30 minutes. It intelligently detects your server's resources (CPU, RAM, disk) and automatically optimizes all services for maximum performance.

### Why Use This Script?

- **🚀 Production-Ready**: Optimized for high-traffic websites and applications
- **🧠 Intelligent**: Auto-detects and tunes based on your server's resources
- **🔒 Secure**: Enterprise-grade security with UFW, Fail2ban, and optional ModSecurity WAF
- **📦 Complete**: Everything you need in one script - no manual configuration required
- **🛠️ Maintainable**: Includes 20+ utility scripts for ongoing management
- **💾 Reliable**: Automated backups with FTP upload support
- **📊 Optimized**: Server classification (Small/Medium/Large) with tailored configurations

---

---

## 🆕 New Features Added

### 🚀 Performance Enhancements
- **BBR TCP Congestion Control** - Google's algorithm for 20-30% better network throughput
- **Kernel Optimization** - 1M file descriptors, 128MB network buffers, optimized connection tracking
- **Advanced Nginx Caching** - Static files (1yr), media (1mo), gzip compression (level 6)
- **System Tuning** - Comprehensive sysctl parameters for high-traffic servers

### 🔒 Enhanced Security
- **Rootkit Detection** - rkhunter + chkrootkit with daily automated scans
- **Security Auditing** - Lynis security scanner with custom audit script
- **Advanced Fail2ban** - 6 jails protecting Nginx (HTTP auth, bots, 404 floods) and MySQL
- **Service Watchdog** - Auto-restart failed services every 60 seconds

### 🖼️ Image Optimization
- **jpegoptim** - JPEG compression (max 85% quality)
- **optipng** + **pngquant** - PNG optimization (lossy + lossless)
- **gifsicle** - GIF optimization
- **webp** - WebP format support
- **Utility Script** - `/usr/local/bin/optimize-images.sh`

### 📊 Additional PHP Extensions
- **APCu** - User cache for better performance
- **igbinary** - Binary serializer (faster than PHP serialize)
- **msgpack** - MessagePack serializer
- **yaml** - YAML parser
- **mongodb** - MongoDB driver
- **swoole** - Async/coroutine support (optional)

### 💚 Monitoring & Health
- **Health Endpoints** - `/health` and `/health-detailed` for uptime monitoring
- **Service Watchdog** - Auto-restart with cooldown (60s) and max retries (10)
- **MySQL Tuner** - Automated optimization recommendations

---

## ✨ Features

### 🏗️ Core Stack

| Component | Version | Features |
|-----------|---------|----------|
| **Nginx** | Latest | FastCGI caching, auto-tuned workers, HTTP/2 ready |
| **PHP-FPM** | 8.3/8.2/8.1 | Dynamic pools, OPcache, 15+ extensions |
| **Percona MySQL** | 8.0 | InnoDB optimized, 40-60% RAM buffer pool |
| **Redis** | Latest | AOF persistence, LRU eviction, password auth |
| **Node.js** | LTS | With PM2 process manager |
| **Supervisor** | Latest | Web interface on port 9001 |

### 🔐 Security Features

- **UFW Firewall**: Automatic service port detection and configuration
- **Fail2ban**: SSH brute-force protection (3 attempts = 24-hour ban)
- **SSH Hardening**: Custom port with auto-detection of available ports
- **Password Security**: Auto-generated 32-character passwords for MySQL and Redis
- **ModSecurity WAF**: Optional Web Application Firewall with OWASP Core Rule Set
- **VPN Support**: IPv4 forwarding and NAT masquerading for VPN clients
- **SSL/TLS**: Let's Encrypt integration with automatic renewal

### ⚡ Performance Optimizations

#### Intelligent Resource Detection
The script automatically detects:
- CPU cores (for worker processes)
- Total RAM (for buffer pools and caches)
- Available disk space (for cache sizing)

#### Server Classification
Based on detected resources, servers are classified as:

| Class | RAM | CPU Cores | Optimizations |
|-------|-----|-----------|---------------|
| **Small** | < 8GB | < 4 | Conservative settings, 40% RAM allocation |
| **Medium** | 8-16GB | 4-8 | Balanced settings, 45-50% RAM allocation |
| **Large** | ≥ 16GB | ≥ 8 | Aggressive settings, 50-60% RAM allocation |

#### Service-Specific Tuning

**Nginx:**
- Worker processes: Matches CPU cores
- Worker connections: 8K-65K based on server class
- FastCGI cache: Automatic sizing (10% of available disk, max 10GB)
- Keepalive: Optimized timeouts (20-30s)

**PHP-FPM:**
- Dynamic process management
- Max children: 10-300 (calculated: RAM × allocation% / 40-60MB per child)
- Memory limit: 128M-512M based on server class
- OPcache: 128M-256M

**MySQL (Percona):**
- InnoDB buffer pool: 40-60% of total RAM
- Buffer pool instances: 1 per GB (max 8)
- Read/write threads: 8 each
- Max connections: 150-500 based on server class
- Binary logging: Disabled (saves disk space)

**Redis:**
- Max memory: 5-10% of total RAM
- Eviction policy: allkeys-lru
- AOF persistence: Every second
- Lazy freeing: Enabled

### 💾 Backup & Recovery

- **MySQL Backups**: Automated daily backups with compression
- **FTP Upload**: Optional remote backup to FTP server
- **Retention Policy**: Configurable (default: 14 days)
- **Backup Scripts**: Ready-to-use scripts for manual backups
- **Password Storage**: Secure file at `/root/.lemp-install-passwords.txt` (chmod 600)

### 🛠️ Developer Tools

- **Git**: Version control system
- **Composer**: PHP dependency manager (latest version)
- **Yarn**: Node.js package manager
- **PM2**: Process manager for Node.js applications
- **20+ Utility Scripts**: For cache management, database optimization, and maintenance

### 📊 Management & Maintenance

- **Cache Management**: Scripts for warming, purging, and viewing cache statistics
- **Database Tools**: Query optimization, migration helpers, read replica setup
- **Automated Cron Jobs**: Daily/weekly maintenance tasks
- **System Monitoring**: Performance tracking and resource monitoring

---

## 📦 What Gets Installed

<details>
<summary><b>Click to expand complete package list</b></summary>

### Web Server
- `nginx` - High-performance web server

### PHP & Extensions
- `php8.3-fpm` (or 8.2/8.1 fallback)
- `php-cli` - Command line interface
- `php-mysql` - MySQL database support
- `php-opcache` - Opcode cache
- `php-zip` - ZIP archive support
- `php-curl` - cURL support
- `php-gd` - Image processing
- `php-mbstring` - Multibyte string support
- `php-xml` - XML support
- `php-intl` - Internationalization
- `php-bcmath` - Arbitrary precision mathematics
- `php-pgsql` - PostgreSQL support
- `php-sqlite3` - SQLite support
- `php-imagick` - ImageMagick support
- `php-redis` - Redis support

### Database
- `percona-server-server` - Percona Server 8.0 (MySQL-compatible)
- `percona-server-client` - MySQL client

### Cache & Queue
- `redis-server` - In-memory data store
- `redis-tools` - Redis command-line tools

### Process Management
- `supervisor` - Process control system
- `pm2` - Node.js process manager (via npm)

### JavaScript Runtime
- `nodejs` - Node.js LTS version
- `npm` - Node package manager
- `yarn` - Alternative package manager

### Security
- `ufw` - Uncomplicated Firewall
- `fail2ban` - Intrusion prevention
- `certbot` - Let's Encrypt client
- `python3-certbot-nginx` - Nginx plugin for Certbot

### Development Tools
- `git` - Version control
- `composer` - PHP dependency manager
- `curl`, `wget` - Download tools
- `unzip` - Archive extraction
- `htop` - Process viewer
- `net-tools` - Network utilities
- `jq` - JSON processor

### Optional
- `libmodsecurity3` - ModSecurity WAF library
- `modsecurity-crs` - OWASP Core Rule Set

</details>

---

## 💻 System Requirements

### Minimum Requirements
- **OS**: Ubuntu 22.04 LTS (Jammy Jellyfish) - **REQUIRED**
- **RAM**: 2GB minimum (4GB recommended for production)
- **Disk**: 10GB free space minimum (20GB+ recommended)
- **CPU**: 1 core minimum (2+ cores recommended)
- **Network**: Stable internet connection
- **Access**: Root or sudo privileges

### Recommended Specifications

| Use Case | RAM | CPU | Disk | Server Class |
|----------|-----|-----|------|--------------|
| **Development** | 2-4GB | 1-2 cores | 20GB | Small |
| **Small Production** | 4-8GB | 2-4 cores | 40GB | Small-Medium |
| **Medium Production** | 8-16GB | 4-8 cores | 80GB | Medium |
| **Large Production** | 16GB+ | 8+ cores | 160GB+ | Large |

### Pre-Installation Checklist

- [ ] Fresh Ubuntu 22.04 LTS installation
- [ ] Root or sudo access available
- [ ] Server has internet connectivity
- [ ] At least 10GB free disk space (`df -h`)
- [ ] Verify Ubuntu version: `lsb_release -a` (must show 22.04)
- [ ] FTP credentials ready (if using remote backups)
- [ ] SMTP credentials ready (if using email alerts)
- [ ] Domain name configured (if using SSL)

---

## 🚀 Quick Start

### One-Command Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/Install-22.04.sh

# Make it executable
chmod +x Install-22.04.sh

# Run with sudo
sudo ./Install-22.04.sh
```

**Installation time**: 15-30 minutes depending on server speed and internet connection.

### What Happens During Installation

1. **Interactive prompts** for configuration (SSH port, passwords, backups, SSL, etc.)
2. **System validation** (Ubuntu version, resources, disk space)
3. **Automatic optimization** based on detected CPU/RAM
4. **Service installation** and configuration
5. **Security hardening** (firewall, Fail2ban, SSH)
6. **Final verification** of all services

---

## 📚 Installation Guide

### Interactive Configuration

The script uses **interactive prompts** to gather all necessary configuration. You'll be asked for:

#### 1. Security & Network Settings

```
SSH Port [default: 2222]: 
Admin IP CIDR (allowed SSH range) [default: 0.0.0.0/0]: 
Allow SSH from anywhere? [Y/n]: 
```

**Explanation:**
- **SSH Port**: Custom port for SSH (default 2222). Script auto-detects if port is in use.
- **Admin IP CIDR**: IP range allowed to connect via SSH (0.0.0.0/0 = anywhere)
- **Allow SSH from anywhere**: If 'n', only Admin IP CIDR can connect

#### 2. Database Configuration

```
MySQL Root Password [default: (auto-generate)]: 
MySQL Backup User Name [default: backup_user]: 
MySQL Backup User Password [default: (auto-generate)]: 
Redis Password [default: (auto-generate)]: 
```

**Explanation:**
- Leave passwords empty to auto-generate secure 32-character passwords
- Backup user is created for automated backup scripts
- All passwords are saved to `/root/.lemp-install-passwords.txt`

#### 3. Backup Configuration

```
Backup Retention Days [default: 14]: 
Enable FTP Backups? [y/N]: 
```

If FTP enabled, you'll be prompted for:
```
FTP Host [default: ftp.yourserver.com]: 
FTP Username [default: your_ftp_username]: 
FTP Password [default: (hidden)]: 
FTP Port [default: 21]: 
FTP Project Name [default: UptimeMatrix]: 
FTP Remote Path [default: /backups]: 
```

**Explanation:**
- Backups are stored locally in `/var/backups/`
- FTP upload is optional for offsite backups
- Retention policy auto-deletes old backups

#### 4. SSL/TLS Configuration

```
Enable SSL (Let's Encrypt)? [Y/n]: 
SSL Email [default: admin@uptimematrix.com]: 
SSL Domain (e.g., example.com) [default: (empty)]: 
Additional SSL Domains (comma-separated) [default: (empty)]: 
```

**Explanation:**
- Requires a valid domain pointing to your server
- Email is used for Let's Encrypt notifications
- Supports multiple domains (e.g., example.com,www.example.com)

#### 5. Email Notifications

```
Enable Email Alerts? [y/N]: 
```

If enabled:
```
Alert Email Address [default: admin@uptimematrix.com]: 
SMTP Host [default: smtp.gmail.com]: 
SMTP Port [default: 587]: 
SMTP Username [default: your-email@gmail.com]: 
SMTP Password [default: (hidden)]: 
SMTP From Address [default: noreply@uptimematrix.com]: 
```

**SMTP Examples:**

<details>
<summary><b>Gmail Configuration</b></summary>

```
SMTP Host: smtp.gmail.com
SMTP Port: 587
SMTP Username: your-email@gmail.com
SMTP Password: your-app-password
```

**Note**: Generate app password at https://myaccount.google.com/apppasswords

</details>

<details>
<summary><b>SendGrid Configuration</b></summary>

```
SMTP Host: smtp.sendgrid.net
SMTP Port: 587
SMTP Username: apikey
SMTP Password: your-sendgrid-api-key
```

</details>

#### 6. System Settings

```
Timezone [default: UTC]: 
Allow Unattended Reboot? [y/N]: 
```

**Common Timezones:**
- `UTC` - Coordinated Universal Time
- `America/New_York` - Eastern Time
- `America/Los_Angeles` - Pacific Time
- `Europe/London` - GMT/BST
- `Asia/Tokyo` - Japan Standard Time
- `Asia/Dhaka` - Bangladesh Standard Time

### Installation Process

The script performs 20 major steps:

<details>
<summary><b>Click to view detailed installation steps</b></summary>

1. **Interactive Configuration**
   - Collects all settings with defaults
   - Auto-generates passwords if not provided
   - Validates inputs

2. **System Validation**
   - Verifies Ubuntu 22.04 LTS
   - Detects CPU cores, RAM, disk space
   - Classifies server (Small/Medium/Large)
   - Checks minimum requirements

3. **Cleanup Previous Installations** (Optional)
   - Offers to remove existing LEMP components
   - Deletes old databases and configurations
   - **⚠️ DESTRUCTIVE** - Requires confirmation

4. **System Preparation**
   - Updates package lists (`apt update`)
   - Upgrades existing packages (`apt upgrade`)
   - Installs essential tools (curl, wget, git, etc.)
   - Sets timezone

5. **Swap Configuration**
   - Prompts for swap file creation
   - User specifies size (e.g., 2GB, 4GB)
   - Configures swappiness (1-10 based on RAM)
   - Makes persistent across reboots

6. **VPN Masquerading**
   - Enables IPv4 forwarding
   - Configures UFW for VPN clients
   - Sets up NAT masquerading rules

7. **Security Setup**
   - Configures SSH on custom port
   - Auto-detects available ports (tries up to 100)
   - Installs UFW firewall
   - Sets up Fail2ban for SSH protection
   - Configures SSH login email notifications (optional)

8. **Nginx Installation**
   - Installs Nginx web server
   - Optimizes worker processes (= CPU cores)
   - Configures worker connections (8K-65K)
   - Sets up FastCGI caching
   - Creates cache management scripts

9. **ModSecurity WAF** (Optional)
   - Prompts for installation
   - Downloads OWASP Core Rule Set
   - Configures SQL injection protection
   - Creates management scripts
   - **Disabled by default** - Enable manually

10. **PHP Installation**
    - Adds ondrej/php PPA repository
    - Installs PHP 8.3 (fallback to 8.2, then 8.1)
    - Installs 15+ extensions (Laravel-ready)
    - Configures PHP-FPM with dynamic pools
    - Optimizes memory limits (128M-512M)
    - Sets up OPcache

11. **MySQL Installation**
    - Installs Percona Server 8.0
    - Configures InnoDB buffer pool (40-60% RAM)
    - Sets root password with mysql_native_password
    - Creates backup user with permissions
    - Optimizes for SELECT operations
    - Disables binary logging (saves disk)

12. **Database Enhancements**
    - Creates query optimization scripts
    - Generates connection pooling documentation
    - Creates read replica setup tools
    - Adds database migration helpers

13. **Redis Installation**
    - Installs Redis server
    - Configures password authentication
    - Sets memory limits (5-10% RAM)
    - Enables AOF persistence
    - Configures LRU eviction policy

14. **Supervisor Installation**
    - Installs process control system
    - Configures web interface (port 9001)
    - Sets up password authentication
    - Enables auto-restart capabilities

15. **Node.js & PM2**
    - Installs Node.js LTS
    - Installs PM2 globally via npm
    - Configures PM2 startup scripts
    - Creates ecosystem configuration

16. **Composer Installation**
    - Downloads latest Composer
    - Installs globally to `/usr/local/bin/composer`
    - Verifies installation

17. **SSL/TLS Setup** (if enabled)
    - Installs Certbot and Nginx plugin
    - Obtains Let's Encrypt certificates
    - Configures Nginx for HTTPS
    - Sets up automatic renewal

18. **Backup System**
    - Creates MySQL backup scripts
    - Sets up FTP upload (if configured)
    - Configures retention policy
    - Schedules daily cron jobs

19. **Maintenance Scripts**
    - Database optimization automation
    - Log cleanup scripts
    - Temporary file cleanup
    - System update automation
    - Schedules weekly/monthly cron jobs

20. **Final Verification**
    - Verifies all services are running
    - Saves passwords to secure file
    - Displays installation summary
    - Shows next steps

</details>

---

## 🎉 Post-Installation

### 1. Verify Installation

```bash
# Check service status (adjust PHP version if different)
systemctl status nginx php8.3-fpm mysql redis-server fail2ban supervisor

# View installation summary and passwords
sudo cat /root/.lemp-install-passwords.txt
```

**Expected output**: All services should show `active (running)`

### 2. Test Web Server

```bash
# Test Nginx
curl http://localhost

# Test PHP
curl http://localhost/index.php

# Check PHP version
php -v
```

### 3. Access Supervisor Web Interface

```
URL: http://YOUR_SERVER_IP:9001
Username: admin
Password: (check /root/.lemp-install-passwords.txt)
```

**⚠️ Security Note**: Restrict access to port 9001 in production:
```bash
sudo ufw delete allow 9001/tcp
sudo ufw allow from YOUR_IP to any port 9001 proto tcp
```

### 4. Review Installed Utility Scripts

```bash
# List all utility scripts
ls -l /usr/local/bin/*.sh

# Common scripts:
# - nginx-cache-warm.sh       - Warm FastCGI cache
# - nginx-cache-purge.sh      - Purge cache entries
# - nginx-cache-stats.sh      - View cache statistics
# - mysql-query-optimize.sh   - Analyze slow queries
# - mysql-replica-setup.sh    - Configure read replicas
# - mysql-migrate.sh          - Run database migrations
# - modsecurity-manage.sh     - Manage WAF (if installed)
# - maintenance-*.sh          - Various maintenance tasks
```

### 5. Configure Your Application

```bash
# Navigate to web root
cd /var/www/html

# Remove default files
sudo rm index.html index.nginx-debian.html

# Upload your application files
# (via SFTP, git clone, etc.)
```

### 6. Set Up SSL (if configured)

If you enabled SSL during installation, verify:

```bash
# Check certificate status
sudo certbot certificates

# Test auto-renewal
sudo certbot renew --dry-run
```

### 7. Configure Firewall Rules

```bash
# View current rules
sudo ufw status numbered

# Allow additional ports if needed
sudo ufw allow 8080/tcp comment 'Custom App'

# Reload firewall
sudo ufw reload
```

---

## 📖 Feature Documentation

### Nginx Configuration

#### FastCGI Cache

The script configures Nginx with FastCGI caching for optimal PHP performance.

**Cache Location**: `/var/cache/nginx/fastcgi`  
**Cache Size**: Auto-calculated (10% of available disk, max 10GB)  
**Cache Duration**: 60 minutes for 200 responses, 10 minutes for 404

**Management Scripts:**

```bash
# Warm cache (pre-load pages)
sudo /usr/local/bin/nginx-cache-warm.sh

# Purge specific URL
sudo /usr/local/bin/nginx-cache-purge.sh /path/to/page

# Purge entire cache
sudo /usr/local/bin/nginx-cache-purge.sh all

# View cache statistics
sudo /usr/local/bin/nginx-cache-stats.sh
```

**Cache Bypass:**
The cache automatically bypasses for:
- Logged-in users (WordPress, Laravel sessions)
- POST requests
- Query strings (unless configured otherwise)

**Configuration File**: `/etc/nginx/conf.d/fastcgi-cache.conf`

#### Performance Settings

Based on your server class, Nginx is configured with:

| Setting | Small | Medium | Large |
|---------|-------|--------|-------|
| Worker Processes | = CPU cores | = CPU cores | = CPU cores |
| Worker Connections | 8,192 | 32,768 | 65,536 |
| Keepalive Timeout | 20s | 30s | 30s |
| Keepalive Requests | 100 | 500 | 1,000 |

**Configuration File**: `/etc/nginx/nginx.conf`

#### Custom Configuration

To add custom Nginx configurations:

```bash
# Create custom config
sudo nano /etc/nginx/conf.d/custom.conf

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

---

### PHP-FPM Optimization

#### Dynamic Process Management

PHP-FPM is configured with dynamic process management based on available RAM:

**Calculation Formula:**
```
Available RAM for PHP = Total RAM × Allocation% (40-60%)
Max Children = Available RAM / Average Child Size (40-60MB)
```

**Example Configurations:**

| Server RAM | Class | Max Children | Start Servers | Min Spare | Max Spare |
|------------|-------|--------------|---------------|-----------|-----------|
| 2GB | Small | 20 | 5 | 2 | 7 |
| 8GB | Medium | 90 | 23 | 9 | 30 |
| 16GB | Large | 200 | 50 | 20 | 67 |

**Configuration File**: `/etc/php/8.3/fpm/pool.d/www.conf`

#### PHP.ini Settings

Optimized settings based on server class:

| Setting | Small | Medium | Large |
|---------|-------|--------|-------|
| memory_limit | 128M | 256M | 512M |
| upload_max_filesize | 100M | 100M | 100M |
| post_max_size | 100M | 100M | 100M |
| max_execution_time | 300s | 300s | 300s |
| max_input_vars | 5000 | 5000 | 5000 |

**Configuration Files**:
- FPM: `/etc/php/8.3/fpm/php.ini`
- CLI: `/etc/php/8.3/cli/php.ini`

#### OPcache Configuration

OPcache is enabled and optimized for production:

```ini
opcache.enable=1
opcache.memory_consumption=128
opcache.interned_strings_buffer=8
opcache.max_accelerated_files=10000
opcache.revalidate_freq=2
opcache.fast_shutdown=1
```

#### Monitoring PHP-FPM

```bash
# Check PHP-FPM status
sudo systemctl status php8.3-fpm

# View PHP-FPM pool status (via Nginx)
curl http://localhost/fpm-status

# View slow log
sudo tail -f /var/log/php8.3-fpm-slow.log

# Restart PHP-FPM
sudo systemctl restart php8.3-fpm
```

---

### MySQL/Percona Tuning

#### InnoDB Buffer Pool

The most important MySQL setting, automatically configured:

**Allocation:**
- Small servers: 40% of RAM
- Medium servers: 50% of RAM
- Large servers: 60% of RAM

**Buffer Pool Instances:**
- 1 instance per GB of buffer pool
- Maximum 8 instances

**Example:**
- 16GB RAM server (Large class)
- Buffer pool: 16GB × 60% = 9.6GB
- Instances: 8 (max)

**Configuration File**: `/etc/mysql/conf.d/custom.cnf`

#### Connection Limits

| Server Class | Max Connections | Thread Cache |
|--------------|-----------------|--------------|
| Small | 150 | 20 |
| Medium | 300 | 50 |
| Large | 500 | 100 |

#### Performance Features

- **Binary Logging**: Disabled (saves disk space and I/O)
- **Read/Write Threads**: 8 each (optimized for SSDs)
- **Table Cache**: 2000 open tables
- **Slow Query Log**: Enabled (queries > 2 seconds)

#### Database Management

```bash
# Connect to MySQL
mysql -u root -p

# View buffer pool status
mysql -u root -p -e "SHOW ENGINE INNODB STATUS\G" | grep -A 10 "BUFFER POOL"

# Check slow queries
sudo /usr/local/bin/mysql-query-optimize.sh

# View connection status
mysql -u root -p -e "SHOW PROCESSLIST;"
```

#### Backup User

A dedicated backup user is created with minimal privileges:

```sql
-- Privileges
GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON *.* TO 'backup_user'@'localhost';
```

---

### Redis Configuration

#### Memory Management

Redis is configured with:
- **Max Memory**: 5-10% of total RAM (128MB minimum, 4GB maximum)
- **Eviction Policy**: allkeys-lru (removes least recently used keys)
- **Memory Samples**: 5 (for LRU algorithm)

**Example:**
- 8GB RAM server → Redis gets 640MB (8%)
- 32GB RAM server → Redis gets 4GB (max cap)

#### Persistence

**AOF (Append Only File)** is enabled for data durability:
- **Sync**: Every second (balance between performance and safety)
- **Auto-rewrite**: When AOF grows 100% and is at least 64MB
- **RDB**: Disabled (using AOF instead)

#### Configuration File

Location: `/etc/redis/redis.conf`

Key settings:
```conf
requirepass YOUR_PASSWORD
maxmemory 640mb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
```

#### Using Redis

```bash
# Connect to Redis
redis-cli -a YOUR_PASSWORD

# Test connection
redis-cli -a YOUR_PASSWORD ping
# Should return: PONG

# View memory usage
redis-cli -a YOUR_PASSWORD INFO memory

# Monitor commands in real-time
redis-cli -a YOUR_PASSWORD MONITOR
```

#### Redis with PHP

```php
<?php
// Connect to Redis
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth('YOUR_PASSWORD');

// Set a value
$redis->set('key', 'value');

// Get a value
$value = $redis->get('key');

// Set with expiration (60 seconds)
$redis->setex('key', 60, 'value');
?>
```

---

### Security Features

#### UFW Firewall

**Default Configuration:**
- Deny all incoming traffic
- Allow all outgoing traffic
- Allow SSH on custom port
- Allow HTTP (80) and HTTPS (443)
- Allow Supervisor web interface (9001)

**Management:**

```bash
# View firewall status
sudo ufw status numbered

# Allow a port
sudo ufw allow 8080/tcp comment 'My Application'

# Delete a rule (by number)
sudo ufw delete 5

# Reload firewall
sudo ufw reload

# Disable firewall (not recommended)
sudo ufw disable
```

#### Fail2ban

**SSH Protection:**
- **Max Retries**: 3 failed attempts
- **Ban Time**: 24 hours (86400 seconds)
- **Find Time**: 1 hour (3600 seconds)

**Configuration**: `/etc/fail2ban/jail.d/custom.conf`

**Management:**

```bash
# View banned IPs
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client set sshd unbanip 1.2.3.4

# Ban an IP manually
sudo fail2ban-client set sshd banip 1.2.3.4

# Restart Fail2ban
sudo systemctl restart fail2ban
```

#### SSH Hardening

**Applied Settings:**
- Custom port (default: 2222, auto-detected)
- Root login: Enabled (can be disabled post-installation)
- Password authentication: Enabled
- Login notifications: Email alerts (if SMTP configured)

**Post-Installation Hardening (Recommended):**

```bash
# Disable root login
sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Disable password authentication (use SSH keys only)
sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart ssh
```

#### ModSecurity WAF (Optional)

If installed, ModSecurity provides:
- SQL injection protection
- XSS (Cross-Site Scripting) protection
- Path traversal protection
- OWASP Core Rule Set

**Management:**

```bash
# Check status
sudo /usr/local/bin/modsecurity-manage.sh status

# Enable ModSecurity
sudo /usr/local/bin/modsecurity-manage.sh enable

# Disable ModSecurity
sudo /usr/local/bin/modsecurity-manage.sh disable

# View logs
sudo /usr/local/bin/modsecurity-manage.sh logs
```

**Configuration**: `/etc/nginx/modsec/main.conf`

---

### Backup System

#### MySQL Backups

**Schedule**: Daily (can be configured via cron)  
**Location**: `/var/backups/mysql/YYYY-MM-DD_HHMMSS/`  
**Retention**: 14 days (configurable)  
**Method**: mysqldump with compression

**Manual Backup:**

```bash
# Create backup
sudo mysqldump -u root -p --all-databases | gzip > /var/backups/mysql/manual-$(date +%Y%m%d_%H%M%S).sql.gz

# List backups
ls -lh /var/backups/mysql/
```

**Restore from Backup:**

```bash
# Extract and restore
gunzip < /var/backups/mysql/backup-20250119_020000.sql.gz | mysql -u root -p
```

#### FTP Upload

If configured, backups are automatically uploaded to FTP server:

**Structure:**
```
/backups/
  └── ProjectName/
      └── YYYY-MM-DD/
          ├── mysql-backup-YYYYMMDD_HHMMSS.tar.gz
          └── app-backup-YYYYMMDD_HHMMSS.tar.gz
```

**Test FTP Connection:**

```bash
# Install lftp if not present
sudo apt install lftp

# Test connection
lftp -u USERNAME,PASSWORD -p PORT HOSTNAME
```

#### Backup Verification

```bash
# Check backup directory size
du -sh /var/backups/

# List recent backups
find /var/backups/ -type f -mtime -7 -ls

# Verify backup integrity (for tar.gz files)
tar -tzf /var/backups/mysql/backup.tar.gz > /dev/null && echo "OK" || echo "CORRUPTED"
```

---

### SSL/TLS Setup

#### Let's Encrypt Integration

**Automatic Features:**
- Certificate issuance
- Nginx configuration
- Auto-renewal (twice daily via cron)

**Manual Certificate Request:**

```bash
# For single domain
sudo certbot --nginx -d example.com

# For multiple domains
sudo certbot --nginx -d example.com -d www.example.com

# Wildcard certificate (requires DNS challenge)
sudo certbot --nginx -d example.com -d *.example.com --preferred-challenges dns
```

#### Certificate Management

```bash
# List all certificates
sudo certbot certificates

# Renew all certificates
sudo certbot renew

# Test renewal (dry run)
sudo certbot renew --dry-run

# Revoke a certificate
sudo certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem
```

#### Nginx SSL Configuration

After SSL is enabled, Nginx is configured with:
- TLS 1.2 and 1.3
- Strong cipher suites
- HSTS (HTTP Strict Transport Security)
- OCSP stapling
- HTTP to HTTPS redirect

**Example Nginx SSL Block:**

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Your site configuration
}
```

---

## 🛠️ Management & Utilities

### Cache Management

#### Nginx FastCGI Cache

```bash
# Warm cache (pre-load important pages)
sudo /usr/local/bin/nginx-cache-warm.sh

# Warm specific domain
sudo /usr/local/bin/nginx-cache-warm.sh example.com

# Purge specific URL
sudo /usr/local/bin/nginx-cache-purge.sh /path/to/page example.com

# Purge entire cache
sudo /usr/local/bin/nginx-cache-purge.sh all

# View cache statistics
sudo /usr/local/bin/nginx-cache-stats.sh
```

### Database Tools

#### Query Optimization

```bash
# Analyze slow queries
sudo /usr/local/bin/mysql-query-optimize.sh

# View table statistics
mysql -u root -p -e "SELECT TABLE_SCHEMA, TABLE_NAME, 
    ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) AS 'Size (MB)',
    TABLE_ROWS
    FROM information_schema.TABLES 
    WHERE TABLE_SCHEMA NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')
    ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC 
    LIMIT 10;"
```

#### Database Migration

```bash
# Run migration
sudo /usr/local/bin/mysql-migrate.sh database_name /path/to/migration.sql

# This will:
# 1. Create a backup
# 2. Run the migration
# 3. Report success/failure
```

#### Read Replica Setup

```bash
# On replica server
sudo /usr/local/bin/mysql-replica-setup.sh

# Follow prompts for:
# - Master server IP
# - Replica user credentials
# - Master log file and position
```

### Maintenance Scripts

#### Database Optimization

```bash
# Optimize all databases
sudo /usr/local/bin/maintenance-db-optimize.sh

# This runs:
# - OPTIMIZE TABLE on all tables
# - ANALYZE TABLE for statistics
# - CHECK TABLE for errors
```

#### Log Cleanup

```bash
# Clean old logs
sudo /usr/local/bin/maintenance-log-cleanup.sh

# Removes:
# - Logs older than 30 days
# - Compressed logs older than 7 days
# - Rotates large log files
```

#### Temporary File Cleanup

```bash
# Clean temporary files
sudo /usr/local/bin/maintenance-temp-cleanup.sh

# Cleans:
# - /tmp files older than 7 days
# - PHP session files
# - Nginx temp files
```

#### System Updates

```bash
# Run system updates
sudo /usr/local/bin/maintenance-system-update.sh

# This performs:
# - apt update
# - apt upgrade (safe)
# - apt autoremove
# - Checks for reboot requirement
```

#### Run All Maintenance

```bash
# Execute all maintenance tasks
sudo /usr/local/bin/maintenance-all.sh
```

### Automated Cron Jobs

The script sets up the following cron jobs:

```bash
# View cron jobs
sudo crontab -l

# Typical schedule:
# - Database optimization: Weekly (Sunday 3 AM)
# - Log cleanup: Daily (2 AM)
# - Temp cleanup: Daily (4 AM)
# - System updates: Weekly (Monday 5 AM)
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Installation Fails with "Not Ubuntu 22.04"

**Problem**: Script exits with version error

**Solution**:
```bash
# Verify Ubuntu version
lsb_release -a

# Should show:
# Distributor ID: Ubuntu
# Description:    Ubuntu 22.04.X LTS
# Release:        22.04
# Codename:       jammy
```

If not 22.04, you must use Ubuntu 22.04 LTS. The script will NOT work on other versions.

---

#### 2. Services Not Starting

**Problem**: Nginx, PHP-FPM, or MySQL won't start

**Solution**:

```bash
# Check service status
sudo systemctl status nginx
sudo systemctl status php8.3-fpm
sudo systemctl status mysql

# View detailed logs
sudo journalctl -xeu nginx
sudo journalctl -xeu php8.3-fpm
sudo journalctl -xeu mysql

# Test configurations
sudo nginx -t
sudo php-fpm8.3 -t

# Check for port conflicts
sudo ss -tlnp | grep :80
sudo ss -tlnp | grep :3306
```

---

#### 3. MySQL Won't Start After Installation

**Problem**: MySQL service fails to start

**Possible Causes**:
- Insufficient memory for configured buffer pool
- Disk space issues
- Corrupted data directory

**Solution**:

```bash
# Check MySQL error log
sudo tail -50 /var/log/mysql/error.log

# Check available memory
free -h

# Check disk space
df -h /var/lib/mysql

# Try starting with minimal config
sudo systemctl stop mysql
sudo mv /etc/mysql/conf.d/custom.cnf /etc/mysql/conf.d/custom.cnf.bak
sudo systemctl start mysql

# If it starts, reduce buffer pool size in custom.cnf
sudo nano /etc/mysql/conf.d/custom.cnf
# Reduce innodb_buffer_pool_size
```

---

#### 4. PHP-FPM Runs Out of Memory

**Problem**: PHP-FPM processes consume too much RAM

**Solution**:

```bash
# Check current pool settings
sudo grep -E "pm.max_children|pm.start_servers" /etc/php/8.3/fpm/pool.d/www.conf

# Reduce max_children
sudo nano /etc/php/8.3/fpm/pool.d/www.conf

# Change:
pm.max_children = 50  # Reduce this number

# Restart PHP-FPM
sudo systemctl restart php8.3-fpm

# Monitor memory usage
watch -n 1 free -h
```

---

#### 5. Nginx 502 Bad Gateway

**Problem**: Nginx shows 502 error

**Possible Causes**:
- PHP-FPM not running
- PHP-FPM socket permission issues
- PHP-FPM pool exhausted

**Solution**:

```bash
# Check PHP-FPM status
sudo systemctl status php8.3-fpm

# Check PHP-FPM socket
ls -l /run/php/php8.3-fpm.sock

# Check Nginx error log
sudo tail -f /var/log/nginx/error.log

# Restart PHP-FPM
sudo systemctl restart php8.3-fpm

# Check PHP-FPM pool status
curl http://localhost/fpm-status
```

---

#### 6. SSL Certificate Not Renewing

**Problem**: Let's Encrypt certificate expired

**Solution**:

```bash
# Check certificate status
sudo certbot certificates

# Manual renewal
sudo certbot renew --force-renewal

# Check renewal timer
sudo systemctl status certbot.timer

# Enable timer if disabled
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

---

#### 7. FTP Backups Failing

**Problem**: Backups not uploading to FTP

**Solution**:

```bash
# Test FTP connection
sudo apt install lftp
lftp -u USERNAME,PASSWORD -p PORT HOSTNAME

# Check backup logs
sudo tail -f /var/log/backup_mysql.log

# Verify FTP credentials in script
sudo grep FTP_ /root/Install-22.04.sh

# Test backup manually
sudo /usr/local/bin/backup_mysql_to_ftp.sh
```

---

#### 8. High Disk Usage

**Problem**: Disk space filling up

**Solution**:

```bash
# Find large directories
sudo du -sh /* | sort -h

# Check log sizes
sudo du -sh /var/log/*

# Clean old logs
sudo find /var/log -name "*.log" -mtime +30 -delete
sudo find /var/log -name "*.gz" -mtime +7 -delete

# Clean old backups
sudo find /var/backups -mtime +14 -delete

# Clean package cache
sudo apt clean

# Clean Nginx cache
sudo rm -rf /var/cache/nginx/*
```

---

#### 9. Email Notifications Not Working

**Problem**: No email alerts received

**Solution**:

```bash
# Test SMTP connection
telnet smtp.gmail.com 587

# Check mail logs
sudo tail -f /var/log/mail.log

# Verify SMTP settings
sudo grep SMTP /root/Install-22.04.sh

# Test email manually (if mailutils installed)
echo "Test message" | mail -s "Test Subject" your-email@example.com
```

---

#### 10. Supervisor Web Interface Not Accessible

**Problem**: Cannot access http://SERVER_IP:9001

**Solution**:

```bash
# Check if Supervisor is running
sudo systemctl status supervisor

# Check if port 9001 is listening
sudo ss -tlnp | grep 9001

# Check firewall
sudo ufw status | grep 9001

# Allow port 9001
sudo ufw allow 9001/tcp

# Check Supervisor config
sudo nano /etc/supervisor/supervisord.conf

# Look for [inet_http_server] section
# Should have:
# port=*:9001
# username=admin
# password=YOUR_PASSWORD
```

---

### Service Restart Commands

```bash
# Restart all services
sudo systemctl restart nginx php8.3-fpm mysql redis-server supervisor

# Restart individual services
sudo systemctl restart nginx
sudo systemctl restart php8.3-fpm
sudo systemctl restart mysql
sudo systemctl restart redis-server
sudo systemctl restart supervisor
sudo systemctl restart fail2ban

# Reload configurations (no downtime)
sudo systemctl reload nginx
sudo systemctl reload php8.3-fpm
```

### Log File Locations

```bash
# Nginx
/var/log/nginx/access.log
/var/log/nginx/error.log

# PHP-FPM
/var/log/php8.3-fpm.log
/var/log/php8.3-fpm-slow.log

# MySQL
/var/log/mysql/error.log
/var/log/mysql/slow-query.log

# Redis
/var/log/redis/redis-server.log

# System
/var/log/syslog
/var/log/auth.log

# Fail2ban
/var/log/fail2ban.log
```

---

## ⚡ Performance Tuning

### Monitoring Performance

```bash
# CPU and memory usage
htop

# Disk I/O
sudo iotop

# Network connections
sudo ss -s

# MySQL performance
mysql -u root -p -e "SHOW GLOBAL STATUS LIKE '%Threads_connected%';"
mysql -u root -p -e "SHOW GLOBAL STATUS LIKE '%Slow_queries%';"

# PHP-FPM pool status
curl http://localhost/fpm-status?full

# Redis info
redis-cli -a YOUR_PASSWORD INFO stats
```

### Optimization Tips

#### For High-Traffic Websites

1. **Enable OPcache** (already enabled by default)
2. **Use Redis for sessions**:
   ```php
   // In php.ini
   session.save_handler = redis
   session.save_path = "tcp://127.0.0.1:6379?auth=YOUR_PASSWORD"
   ```

3. **Enable Nginx caching** for static files:
   ```nginx
   location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
       expires 1y;
       add_header Cache-Control "public, immutable";
   }
   ```

4. **Use HTTP/2**:
   ```nginx
   listen 443 ssl http2;
   ```

5. **Enable gzip compression** (already enabled by default)

#### For Database-Heavy Applications

1. **Use connection pooling** (see `/usr/local/share/mysql-connection-pooling.md`)

2. **Optimize queries**:
   ```bash
   sudo /usr/local/bin/mysql-query-optimize.sh
   ```

3. **Add indexes** to frequently queried columns

4. **Use read replicas** for read-heavy workloads:
   ```bash
   sudo /usr/local/bin/mysql-replica-setup.sh
   ```

5. **Cache query results** in Redis

#### For Memory-Constrained Servers

1. **Reduce PHP-FPM max_children**:
   ```bash
   sudo nano /etc/php/8.3/fpm/pool.d/www.conf
   # Reduce pm.max_children
   ```

2. **Reduce MySQL buffer pool**:
   ```bash
   sudo nano /etc/mysql/conf.d/custom.cnf
   # Reduce innodb_buffer_pool_size
   ```

3. **Reduce Redis max memory**:
   ```bash
   sudo nano /etc/redis/redis.conf
   # Reduce maxmemory
   ```

4. **Enable swap** (if not already):
   ```bash
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

---

## ❓ FAQ

<details>
<summary><b>Q: Can I run this script on Ubuntu 20.04 or 24.04?</b></summary>

**A:** No. This script is specifically designed for Ubuntu 22.04 LTS only. It will not work on other versions due to:
- Different package versions
- Different repository structures
- Different default configurations

You must use Ubuntu 22.04 LTS.

</details>

<details>
<summary><b>Q: Can I run this script multiple times?</b></summary>

**A:** Yes, the script is idempotent and includes checks for existing installations. However:
- It will offer to clean up previous installations (destructive)
- Some settings may be overwritten
- Passwords will be regenerated if you choose cleanup

It's safe to re-run for updates or fixes.

</details>

<details>
<summary><b>Q: How do I change the SSH port after installation?</b></summary>

**A:**
```bash
# Edit SSH config
sudo nano /etc/ssh/sshd_config

# Change the Port line
Port 2222  # Change to your desired port

# Update firewall
sudo ufw allow NEW_PORT/tcp
sudo ufw delete allow OLD_PORT/tcp

# Restart SSH
sudo systemctl restart ssh
```

**Important**: Test the new port before closing your current session!

</details>

<details>
<summary><b>Q: Where are all my passwords stored?</b></summary>

**A:** All passwords are saved in `/root/.lemp-install-passwords.txt` with chmod 600 (root only).

```bash
# View passwords
sudo cat /root/.lemp-install-passwords.txt
```

**Backup this file** to a secure location!

</details>

<details>
<summary><b>Q: How do I add a new website/domain?</b></summary>

**A:**
```bash
# Create document root
sudo mkdir -p /var/www/example.com/public_html

# Create Nginx server block
sudo nano /etc/nginx/sites-available/example.com

# Add configuration (see example below)

# Enable site
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx

# Set up SSL
sudo certbot --nginx -d example.com -d www.example.com
```

Example Nginx configuration:
```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    root /var/www/example.com/public_html;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

</details>

<details>
<summary><b>Q: How do I upgrade PHP version?</b></summary>

**A:** The script installs the latest available PHP version from ondrej/php PPA. To upgrade:

```bash
# Update package lists
sudo apt update

# Check available PHP versions
apt-cache search php8

# Install new PHP version
sudo apt install php8.4-fpm php8.4-cli php8.4-mysql # etc.

# Update Nginx configuration
sudo nano /etc/nginx/sites-available/default
# Change php8.3-fpm.sock to php8.4-fpm.sock

# Restart services
sudo systemctl restart php8.4-fpm nginx
```

</details>

<details>
<summary><b>Q: How much disk space do backups use?</b></summary>

**A:** Backup size depends on your database and application size:
- MySQL backups: Compressed, typically 10-30% of database size
- Retention: 14 days by default
- Example: 1GB database = ~300MB compressed × 14 days = ~4.2GB

Monitor with:
```bash
du -sh /var/backups/
```

</details>

<details>
<summary><b>Q: Can I use this for production?</b></summary>

**A:** Yes! This script is designed for production use. However:
- **Test first** on a staging server
- **Review security settings** for your specific needs
- **Backup regularly** (script includes automated backups)
- **Monitor performance** and adjust as needed
- **Keep system updated** with security patches

</details>

<details>
<summary><b>Q: How do I uninstall everything?</b></summary>

**A:** The script includes a cleanup function. To manually remove:

```bash
# Stop services
sudo systemctl stop nginx php8.3-fpm mysql redis-server supervisor

# Remove packages
sudo apt purge nginx php* percona-server-* redis-server supervisor nodejs

# Remove data
sudo rm -rf /var/lib/mysql /var/lib/redis /var/www /etc/nginx /etc/php

# Remove backups
sudo rm -rf /var/backups/mysql

# Clean up
sudo apt autoremove
sudo apt autoclean
```

**Warning**: This will delete all data!

</details>

<details>
<summary><b>Q: Does this work with Docker?</b></summary>

**A:** This script is designed for bare metal or VM installations, not Docker containers. For Docker, consider using official images:
- nginx:alpine
- php:8.3-fpm-alpine
- percona:8.0
- redis:alpine

</details>

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Reporting Issues

1. Check if the issue already exists
2. Provide detailed information:
   - Ubuntu version (`lsb_release -a`)
   - Error messages
   - Steps to reproduce
   - Expected vs actual behavior

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the feature and use case
3. Explain why it would be useful

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly on Ubuntu 22.04
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your fork (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- **Test on Ubuntu 22.04 LTS only**
- **Maintain idempotency** (safe to run multiple times)
- **Add error handling** for all operations
- **Document new features** in README
- **Follow existing code style**
- **Add comments** for complex logic

---

## 📄 License

This project is licensed under the MIT License - see below for details:

```
MIT License

Copyright (c) 2024 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

- **Ondřej Surý** - For maintaining the PHP PPA
- **Percona** - For the excellent MySQL distribution
- **Nginx Team** - For the high-performance web server
- **Let's Encrypt** - For free SSL certificates
- **Ubuntu Community** - For the solid foundation

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/YOUR_USERNAME/YOUR_REPO/issues)
- **Discussions**: [GitHub Discussions](https://github.com/YOUR_USERNAME/YOUR_REPO/discussions)
- **Documentation**: This README and inline script comments

---

## 🔗 Useful Links

- [Ubuntu 22.04 LTS Documentation](https://help.ubuntu.com/22.04/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [PHP Documentation](https://www.php.net/docs.php)
- [Percona Server Documentation](https://docs.percona.com/percona-server/8.0/)
- [Redis Documentation](https://redis.io/documentation)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

---

## ⭐ Star History

If you find this project useful, please consider giving it a star on GitHub!

---

<div align="center">

**Made with ❤️ for the Ubuntu community**

[⬆ Back to Top](#-enterprise-lemp-stack-installer-for-ubuntu-2204-lts)

</div>
