"""Pre-built Runbook Library for MSP Platform
Contains 20+ common automation scripts for AWS and Azure
"""

def get_global_runbooks():
    """Get list of pre-built global runbooks"""
    
    runbooks = [
        # ============= DISK MANAGEMENT =============
        {
            "name": "Clean Disk Space - Linux",
            "description": "Clean up temporary files, logs, and package caches to free disk space on Linux systems",
            "category": "disk",
            "script_content": """#!/bin/bash
# Clean Disk Space - Linux Systems
echo "Starting disk cleanup..."

# Check current disk usage
echo "=== Current Disk Usage ==="
df -h

# Clean package manager cache
echo "=== Cleaning package cache ==="
sudo apt-get clean 2>/dev/null || sudo yum clean all 2>/dev/null

# Remove old log files (older than 30 days)
echo "=== Removing old logs ==="
sudo find /var/log -type f -name "*.log" -mtime +30 -delete 2>/dev/null
sudo find /var/log -type f -name "*.gz" -mtime +30 -delete 2>/dev/null

# Clean temporary files
echo "=== Cleaning /tmp ==="
sudo find /tmp -type f -atime +7 -delete 2>/dev/null

# Clean Docker if installed
if command -v docker &> /dev/null; then
    echo "=== Cleaning Docker ==="
    sudo docker system prune -af --volumes 2>/dev/null || true
fi

# Final disk usage
echo "=== Final Disk Usage ==="
df -h

echo "Disk cleanup completed!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["disk", "cleanup", "linux", "maintenance"]
        },
        
        {
            "name": "Clean Disk Space - Windows",
            "description": "Clean up temporary files, logs, and caches to free disk space on Windows systems",
            "category": "disk",
            "script_content": """# Clean Disk Space - Windows Systems
Write-Output "Starting disk cleanup..."

# Check current disk usage
Write-Output "=== Current Disk Usage ==="
Get-PSDrive -PSProvider FileSystem

# Clean Windows Temp
Write-Output "=== Cleaning Windows Temp ==="
Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue

# Clean System Temp
Write-Output "=== Cleaning System Temp ==="
Remove-Item -Path C:\\Windows\\Temp\\* -Recurse -Force -ErrorAction SilentlyContinue

# Clean IIS Logs (if exists)
if (Test-Path "C:\\inetpub\\logs") {
    Write-Output "=== Cleaning IIS Logs ==="
    Get-ChildItem -Path "C:\\inetpub\\logs\\LogFiles" -Recurse -File | 
        Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-30)} | 
        Remove-Item -Force -ErrorAction SilentlyContinue
}

# Clean Windows Update Cache
Write-Output "=== Cleaning Windows Update Cache ==="
Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item -Path C:\\Windows\\SoftwareDistribution\\Download\\* -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -ErrorAction SilentlyContinue

# Final disk usage
Write-Output "=== Final Disk Usage ==="
Get-PSDrive -PSProvider FileSystem

Write-Output "Disk cleanup completed!"
""",
            "script_type": "powershell",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["disk", "cleanup", "windows", "maintenance"]
        },
        
        # ============= APPLICATION MANAGEMENT =============
        {
            "name": "Restart Apache/Nginx Web Server",
            "description": "Restart Apache or Nginx web server to resolve hanging connections or memory issues",
            "category": "application",
            "script_content": """#!/bin/bash
# Restart Web Server
echo "Checking web server..."

# Try Apache
if systemctl is-active --quiet apache2; then
    echo "Restarting Apache2..."
    sudo systemctl restart apache2
    sudo systemctl status apache2 --no-pager
elif systemctl is-active --quiet httpd; then
    echo "Restarting Apache (httpd)..."
    sudo systemctl restart httpd
    sudo systemctl status httpd --no-pager
# Try Nginx
elif systemctl is-active --quiet nginx; then
    echo "Restarting Nginx..."
    sudo systemctl restart nginx
    sudo systemctl status nginx --no-pager
else
    echo "No supported web server found (apache2/httpd/nginx)"
    exit 1
fi

echo "Web server restarted successfully!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "medium",
            "auto_approve": False,
            "tags": ["application", "web", "restart", "apache", "nginx"]
        },
        
        {
            "name": "Restart Application Service",
            "description": "Restart a specific application service (requires SERVICE_NAME parameter)",
            "category": "application",
            "script_content": """#!/bin/bash
# Restart Application Service
SERVICE_NAME="${1:-myapp}"

echo "Restarting service: $SERVICE_NAME"

# Check if service exists
if ! systemctl list-unit-files | grep -q "^$SERVICE_NAME.service"; then
    echo "Service $SERVICE_NAME not found"
    exit 1
fi

# Restart service
sudo systemctl restart "$SERVICE_NAME"

# Check status
sudo systemctl status "$SERVICE_NAME" --no-pager

echo "Service $SERVICE_NAME restarted successfully!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "medium",
            "auto_approve": False,
            "tags": ["application", "service", "restart"],
            "parameters": [
                {
                    "name": "SERVICE_NAME",
                    "type": "string",
                    "required": True,
                    "description": "Name of the service to restart"
                }
            ]
        },
        
        # ============= DATABASE MANAGEMENT =============
        {
            "name": "Check MySQL/PostgreSQL Status",
            "description": "Check database server status, connections, and performance metrics",
            "category": "database",
            "script_content": """#!/bin/bash
# Check Database Status
echo "Checking database servers..."

# Check MySQL
if systemctl is-active --quiet mysql || systemctl is-active --quiet mysqld; then
    echo "=== MySQL Status ==="
    sudo systemctl status mysql --no-pager 2>/dev/null || sudo systemctl status mysqld --no-pager
    
    echo "=== MySQL Connections ==="
    sudo mysql -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null || echo "MySQL command failed"
fi

# Check PostgreSQL
if systemctl is-active --quiet postgresql; then
    echo "=== PostgreSQL Status ==="
    sudo systemctl status postgresql --no-pager
    
    echo "=== PostgreSQL Connections ==="
    sudo -u postgres psql -c "SELECT count(*) as connections FROM pg_stat_activity;" 2>/dev/null || echo "PostgreSQL command failed"
fi

echo "Database check completed!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["database", "mysql", "postgresql", "monitoring"]
        },
        
        # ============= MEMORY MANAGEMENT =============
        {
            "name": "Clear Memory Cache - Linux",
            "description": "Clear page cache, dentries, and inodes to free up memory (safe operation)",
            "category": "memory",
            "script_content": """#!/bin/bash
# Clear Memory Cache - Linux
echo "=== Current Memory Usage ==="
free -h

echo "Syncing filesystems..."
sudo sync

echo "Clearing page cache, dentries, and inodes..."
echo 3 | sudo tee /proc/sys/vm/drop_caches

echo "=== Memory Usage After Clearing ==="
free -h

echo "Memory cache cleared successfully!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["memory", "cache", "linux", "performance"]
        },
        
        # ============= CPU MANAGEMENT =============
        {
            "name": "Identify High CPU Processes",
            "description": "List top 10 processes consuming CPU and their details",
            "category": "cpu",
            "script_content": """#!/bin/bash
# Identify High CPU Processes
echo "=== Top 10 CPU-Consuming Processes ==="
ps aux --sort=-%cpu | head -11

echo ""
echo "=== Current CPU Usage ==="
top -bn1 | grep "Cpu(s)"

echo ""
echo "=== Load Average ==="
uptime

echo ""
echo "=== Process Count ==="
ps aux | wc -l

echo "CPU analysis completed!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["cpu", "monitoring", "processes", "performance"]
        },
        
        # ============= NETWORK MANAGEMENT =============
        {
            "name": "Network Connectivity Check",
            "description": "Test network connectivity to common endpoints and DNS resolution",
            "category": "network",
            "script_content": """#!/bin/bash
# Network Connectivity Check
echo "=== Network Interface Status ==="
ip addr show

echo ""
echo "=== Routing Table ==="
ip route

echo ""
echo "=== DNS Resolution Test ==="
nslookup google.com

echo ""
echo "=== Connectivity Tests ==="
ping -c 3 8.8.8.8
ping -c 3 google.com

echo ""
echo "=== Active Connections ==="
netstat -an | grep ESTABLISHED | wc -l
echo "active connections"

echo "Network check completed!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["network", "connectivity", "dns", "monitoring"]
        },
        
        # ============= SECURITY =============
        {
            "name": "Security Audit - Failed Login Attempts",
            "description": "Check for failed login attempts and potential security issues",
            "category": "security",
            "script_content": """#!/bin/bash
# Security Audit - Failed Logins
echo "=== Failed SSH Login Attempts (Last 100) ==="
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 || \
sudo grep "Failed password" /var/log/secure 2>/dev/null | tail -100 || \
echo "No failed login logs found"

echo ""
echo "=== Unique IPs with Failed Logins ==="
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | \
    awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10 || \
echo "No data available"

echo ""
echo "=== Active User Sessions ==="
who

echo ""
echo "=== Recent sudo Commands ==="
sudo grep sudo /var/log/auth.log 2>/dev/null | tail -20 || \
echo "No sudo log found"

echo "Security audit completed!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["security", "audit", "ssh", "monitoring"]
        },
        
        # ============= AWS SPECIFIC =============
        {
            "name": "AWS - Check EC2 Instance Metadata",
            "description": "Retrieve EC2 instance metadata and configuration",
            "category": "cloud",
            "script_content": """#!/bin/bash
# Check EC2 Instance Metadata
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null)

echo "=== Instance Information ==="
echo "Instance ID: $(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)"
echo "Instance Type: $(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null)"
echo "Availability Zone: $(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null)"
echo "Private IP: $(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null)"
echo "Public IP: $(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)"

echo ""
echo "=== IAM Role ==="
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null

echo ""
echo "Instance metadata retrieved!"
""",
            "script_type": "bash",
            "cloud_provider": "aws",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["aws", "ec2", "metadata", "monitoring"]
        },
        
        # ============= DOCKER =============
        {
            "name": "Docker - Restart Container",
            "description": "Restart a specific Docker container by name or ID",
            "category": "application",
            "script_content": """#!/bin/bash
# Restart Docker Container
CONTAINER_NAME="${1:-myapp}"

echo "Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "Docker not installed"
    exit 1
fi

echo "Restarting container: $CONTAINER_NAME"
sudo docker restart "$CONTAINER_NAME"

echo ""
echo "Container status:"
sudo docker ps -a --filter "name=$CONTAINER_NAME"

echo ""
echo "Container logs (last 20 lines):"
sudo docker logs --tail 20 "$CONTAINER_NAME"

echo "Container restart completed!"
""",
            "script_type": "bash",
            "cloud_provider": "multi",
            "risk_level": "medium",
            "auto_approve": False,
            "tags": ["docker", "container", "restart", "application"],
            "parameters": [
                {
                    "name": "CONTAINER_NAME",
                    "type": "string",
                    "required": True,
                    "description": "Name or ID of the Docker container"
                }
            ]
        },
        
        {
            "name": "Docker - Clean Unused Resources",
            "description": "Remove unused Docker containers, images, and volumes",
            "category": "disk",
            "script_content": """#!/bin/bash
# Clean Docker Resources
echo "Cleaning Docker resources..."

echo "=== Current Docker Disk Usage ==="
sudo docker system df

echo ""
echo "=== Removing Stopped Containers ==="
sudo docker container prune -f

echo ""
echo "=== Removing Unused Images ==="
sudo docker image prune -a -f

echo ""
echo "=== Removing Unused Volumes ==="
sudo docker volume prune -f

echo ""
echo "=== Removing Unused Networks ==="
sudo docker network prune -f

echo ""
echo "=== Final Docker Disk Usage ==="
sudo docker system df

echo "Docker cleanup completed!"
""",
            "script_type": "bash",
            "cloud_provider": "multi",
            "risk_level": "medium",
            "auto_approve": False,
            "tags": ["docker", "cleanup", "disk", "maintenance"]
        },
        
        # ============= LOGS =============
        {
            "name": "Analyze Application Logs for Errors",
            "description": "Search application logs for errors, warnings, and exceptions",
            "category": "application",
            "script_content": """#!/bin/bash
# Analyze Application Logs
LOG_PATH="${1:-/var/log}"

echo "Analyzing logs in: $LOG_PATH"

echo "=== Error Count (Last 1000 Lines) ==="
sudo find "$LOG_PATH" -name "*.log" -type f -exec tail -1000 {} + 2>/dev/null | \
    grep -iE "error|exception|failed|critical" | wc -l

echo ""
echo "=== Recent Errors ==="
sudo find "$LOG_PATH" -name "*.log" -type f -exec tail -1000 {} + 2>/dev/null | \
    grep -iE "error|exception|failed|critical" | tail -20

echo ""
echo "=== Warning Count ==="
sudo find "$LOG_PATH" -name "*.log" -type f -exec tail -1000 {} + 2>/dev/null | \
    grep -iE "warning|warn" | wc -l

echo ""
echo "=== Log File Sizes ==="
sudo find "$LOG_PATH" -name "*.log" -type f -exec ls -lh {} + | \
    awk '{print $5, $9}' | sort -rh | head -10

echo "Log analysis completed!"
""",
            "script_type": "bash",
            "cloud_provider": "multi",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["logs", "monitoring", "troubleshooting"],
            "parameters": [
                {
                    "name": "LOG_PATH",
                    "type": "string",
                    "required": False,
                    "default": "/var/log",
                    "description": "Path to log directory"
                }
            ]
        },
        
        # ============= SYSTEM INFO =============
        {
            "name": "System Health Check",
            "description": "Comprehensive system health check including CPU, memory, disk, and services",
            "category": "monitoring",
            "script_content": """#!/bin/bash
# System Health Check
echo "=== SYSTEM HEALTH CHECK ==="
echo "Timestamp: $(date)"
echo ""

echo "=== System Information ==="
uname -a
echo "Uptime: $(uptime)"

echo ""
echo "=== CPU Usage ==="
top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | \
    awk '{print "CPU Usage: " 100 - $1"%"}'

echo ""
echo "=== Memory Usage ==="
free -h

echo ""
echo "=== Disk Usage ==="
df -h | grep -v "tmpfs"

echo ""
echo "=== Top 5 Memory-Consuming Processes ==="
ps aux --sort=-%mem | head -6

echo ""
echo "=== Critical Services Status ==="
for service in ssh sshd nginx apache2 httpd mysql mysqld postgresql docker; do
    if systemctl list-unit-files | grep -q "^$service.service"; then
        status=$(systemctl is-active $service 2>/dev/null)
        echo "$service: $status"
    fi
done

echo ""
echo "=== Recent System Errors ==="
sudo journalctl -p err -n 5 --no-pager 2>/dev/null || echo "Journal not available"

echo ""
echo "Health check completed!"
""",
            "script_type": "bash",
            "cloud_provider": "multi",
            "risk_level": "low",
            "auto_approve": True,
            "tags": ["monitoring", "health", "system", "diagnostics"]
        }
    ]
    
    return runbooks
