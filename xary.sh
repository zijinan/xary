#!/bin/bash

# =============================================================================
# Xray REALITY with 'steal oneself' 一键安装脚本
# 基于：https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html
# 功能：自动安装和配置 Xray REALITY + Nginx
# 兼容：Ubuntu/Debian 系统
# =============================================================================

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
DOMAIN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""

# 日志函数
log_info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[步骤]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 检查系统兼容性
check_system() {
    log_step "检查系统兼容性..."
    
    if [[ -f /etc/debian_version ]]; then
        log_info "检测到 Debian/Ubuntu 系统"
        # 更新包管理器
        log_info "更新软件包列表..."
        apt update > /dev/null 2>&1
    else
        log_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
}

# 获取域名信息
get_domain() {
    log_step "配置域名信息..."
    
    while true; do
        read -p "请输入您的域名 (例如: chika.example.com): " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            log_warn "域名不能为空，请重新输入"
            continue
        fi
        
        # 简单验证域名格式
        if [[ $DOMAIN =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            log_info "域名格式正确: $DOMAIN"
            break
        else
            log_warn "域名格式不正确，请重新输入"
        fi
    done
    
    # 测试域名解析
    log_info "测试域名解析..."
    if ping -c 1 "$DOMAIN" &> /dev/null; then
        SERVER_IP=$(ping -c 1 "$DOMAIN" | grep -oP '(?<=\().*?(?=\))' | head -1)
        log_info "域名解析成功，指向IP: $SERVER_IP"
    else
        log_warn "域名解析失败，请确保域名已正确解析到此服务器"
        read -p "是否继续安装？(y/N): " continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    fi
}

# 开放防火墙端口
setup_firewall() {
    log_step "配置防火墙端口..."
    
    # 检查是否安装了ufw
    if command -v ufw &> /dev/null; then
        log_info "开放端口 80 和 443..."
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        log_info "防火墙端口配置完成"
    else
        log_warn "未检测到UFW防火墙，请手动确保端口80和443已开放"
    fi
}

# 安装必要的依赖
install_dependencies() {
    log_step "安装必要的依赖包..."
    
    log_info "安装 socat, gnupg2, ca-certificates 等..."
    apt install -y socat gnupg2 ca-certificates lsb-release ubuntu-keyring curl > /dev/null 2>&1
    
    log_info "依赖包安装完成"
}

# 安装ACME脚本
install_acme() {
    log_step "安装ACME证书管理脚本..."
    
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log_info "下载并安装ACME脚本..."
        curl -s https://get.acme.sh | sh > /dev/null 2>&1
    else
        log_info "ACME脚本已存在"
    fi
    
    # 设置别名
    alias acme.sh=~/.acme.sh/acme.sh
    
    # 设置自动更新
    log_info "配置ACME自动更新..."
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade > /dev/null 2>&1
    
    # 设置默认CA为Let's Encrypt
    log_info "设置默认证书颁发机构为Let's Encrypt..."
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt > /dev/null 2>&1
    
    log_info "ACME脚本配置完成"
}

# 申请SSL证书
get_ssl_certificate() {
    log_step "申请SSL证书..."
    
    # 检查端口80是否被占用
    if netstat -tlnp | grep :80 > /dev/null 2>&1; then
        log_warn "端口80被占用，正在尝试停止相关服务..."
        systemctl stop nginx > /dev/null 2>&1 || true
        systemctl stop apache2 > /dev/null 2>&1 || true
        sleep 2
    fi
    
    log_info "申请 $DOMAIN 的ECC证书..."
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 || {
        log_error "证书申请失败"
        exit 1
    }
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    # 安装证书
    log_info "安装证书到 /etc/ssl/private..."
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file /etc/ssl/private/fullchain.cer \
        --key-file /etc/ssl/private/private.key || {
        log_error "证书安装失败"
        exit 1
    }
    
    # 设置证书文件权限
    chown -R nobody:nogroup /etc/ssl/private
    
    log_info "SSL证书配置完成"
}

# 安装Xray
install_xray() {
    log_step "安装Xray..."
    
    log_info "下载并安装最新版本的Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta > /dev/null 2>&1
    
    log_info "Xray安装完成"
}

# 安装Nginx
install_nginx() {
    log_step "安装Nginx..."
    
    # 添加Nginx官方源
    log_info "添加Nginx官方仓库..."
    curl -s https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
    
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx
    
    # 更新并安装Nginx
    apt update > /dev/null 2>&1
    apt install -y nginx > /dev/null 2>&1
    
    # 配置systemd服务
    mkdir -p /etc/systemd/system/nginx.service.d
    echo -e "[Service]\nExecStartPost=/bin/sleep 0.1" > /etc/systemd/system/nginx.service.d/override.conf
    systemctl daemon-reload
    
    log_info "Nginx安装完成"
}

# 生成UUID和密钥
generate_keys() {
    log_step "生成UUID和密钥..."
    
    # 生成UUID
    UUID=$(xray uuid)
    log_info "生成的UUID: $UUID"
    
    # 生成X25519密钥对
    KEY_PAIR=$(xray x25519)
    PRIVATE_KEY=$(echo "$KEY_PAIR" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEY_PAIR" | grep "Public key:" | awk '{print $3}')
    
    log_info "生成的私钥: $PRIVATE_KEY"
    log_info "生成的公钥: $PUBLIC_KEY"
}

# 配置Xray
configure_xray() {
    log_step "配置Xray..."
    
    log_info "创建Xray配置文件..."
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:cn"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "127.0.0.1:8080",
          "xver": 1,
          "serverNames": [
            "$DOMAIN"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "",
            "0123456789abcdef"
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF
    
    log_info "Xray配置文件创建完成"
}

# 配置Nginx
configure_nginx() {
    log_step "配置Nginx..."
    
    log_info "创建Nginx配置文件..."
    cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    gzip on;
    
    server {
        listen 8080;
        server_name $DOMAIN;
        
        ssl_certificate /etc/ssl/private/fullchain.cer;
        ssl_certificate_key /etc/ssl/private/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        
        location / {
            root /usr/share/nginx/html;
            index index.html index.htm;
        }
        
        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root /usr/share/nginx/html;
        }
    }
}
EOF
    
    log_info "Nginx配置文件创建完成"
}

# 启动服务
start_services() {
    log_step "启动服务..."
    
    # 启动并启用Xray
    log_info "启动Xray服务..."
    systemctl enable xray > /dev/null 2>&1
    systemctl restart xray
    
    if systemctl is-active --quiet xray; then
        log_info "Xray服务启动成功"
    else
        log_error "Xray服务启动失败"
        systemctl status xray
        exit 1
    fi
    
    # 启动并启用Nginx
    log_info "启动Nginx服务..."
    systemctl enable nginx > /dev/null 2>&1
    systemctl restart nginx
    
    if systemctl is-active --quiet nginx; then
        log_info "Nginx服务启动成功"
    else
        log_error "Nginx服务启动失败"
        systemctl status nginx
        exit 1
    fi
}

# 显示配置信息
show_config() {
    log_step "显示配置信息..."
    
    echo
    echo "==============================================="
    log_info "Xray REALITY 安装完成！"
    echo "==============================================="
    echo
    
    log_info "服务器配置信息:"
    echo "  域名: $DOMAIN"
    echo "  UUID: $UUID"
    echo "  私钥: $PRIVATE_KEY"
    echo "  公钥: $PUBLIC_KEY"
    echo
    
    log_info "客户端配置参数:"
    echo "  协议: VLESS"
    echo "  地址: $DOMAIN"
    echo "  端口: 443"
    echo "  UUID: $UUID"
    echo "  Flow: xtls-rprx-vision"
    echo "  传输协议: TCP"
    echo "  传输层安全: Reality"
    echo "  SNI: $DOMAIN"
    echo "  Fingerprint: chrome"
    echo "  PublicKey: $PUBLIC_KEY"
    echo "  ShortId: 留空或使用 0123456789abcdef"
    echo "  SpiderX: /"
    echo
    
    log_info "管理命令:"
    echo "  查看Xray状态: systemctl status xray"
    echo "  查看Nginx状态: systemctl status nginx"
    echo "  重启Xray: systemctl restart xray"
    echo "  重启Nginx: systemctl restart nginx"
    echo "  查看Xray日志: journalctl -u xray -f"
    echo "  查看Nginx日志: tail -f /var/log/nginx/error.log"
    echo
    
    log_warn "重要提醒:"
    echo "  1. 请保存好UUID和密钥信息"
    echo "  2. 证书将在90天后自动续期"
    echo "  3. 请根据上述参数配置客户端"
    echo
}

# 主函数
main() {
    echo "==============================================="
    echo "       Xray REALITY 一键安装脚本"
    echo "==============================================="
    echo
    
    # 检查运行权限和系统兼容性
    check_root
    check_system
    
    # 显示安装信息
    log_warn "此脚本将安装和配置："
    echo "  • Xray-core (最新版本)"
    echo "  • Nginx (官方最新版本)"
    echo "  • Let's Encrypt SSL证书"
    echo "  • REALITY协议配置"
    echo
    
    read -p "确认开始安装? (y/N): " confirm_start
    if [[ ! $confirm_start =~ ^[Yy]$ ]]; then
        log_info "安装已取消"
        exit 0
    fi
    
    echo
    
    # 执行安装步骤
    get_domain
    setup_firewall
    install_dependencies
    install_acme
    get_ssl_certificate
    install_xray
    install_nginx
    generate_keys
    configure_xray
    configure_nginx
    start_services
    
    # 显示配置信息
    show_config
    
    log_info "安装完成！请使用上述配置信息设置客户端。"
}

# 执行主函数
main "$@"
