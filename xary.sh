#!/bin/bash

# =============================================================================
# Xray REALITY with 'steal oneself' 修复版一键安装脚本
# 基于：https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html
# 功能：自动安装和配置 Xray REALITY + Nginx
# 兼容：Ubuntu/Debian 系统
# =============================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 全局变量
DOMAIN=""
UUID=""
PRIVATE_KEY=""
PUBLIC_KEY=""
SERVER_IP=""

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

# 错误处理函数
handle_error() {
    local line_no=$1
    local error_code=$2
    log_error "脚本在第 $line_no 行出错，错误代码: $error_code"
    log_error "安装失败，请检查错误信息"
    exit $error_code
}

# 设置错误处理
trap 'handle_error $LINENO $?' ERR

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
        apt update || {
            log_error "更新软件包列表失败"
            exit 1
        }
    else
        log_error "此脚本仅支持 Debian/Ubuntu 系统"
        exit 1
    fi
}

# 获取域名信息
get_domain() {
    log_step "配置域名信息..."
    
    while true; do
        read -p "请输入您的域名 (例如: example.com): " DOMAIN
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
        SERVER_IP=$(dig +short "$DOMAIN" | head -1)
        if [[ -n "$SERVER_IP" ]]; then
            log_info "域名解析成功，指向IP: $SERVER_IP"
        else
            log_warn "无法获取域名解析结果"
        fi
    else
        log_warn "域名解析失败，请确保域名已正确解析到此服务器"
        read -p "是否继续安装？(y/N): " continue_install
        if [[ ! $continue_install =~ ^[Yy]$ ]]; then
            log_info "安装已取消"
            exit 0
        fi
    fi
}

# 停止可能冲突的服务
stop_conflicting_services() {
    log_step "停止可能冲突的服务..."
    
    # 停止Apache2
    if systemctl is-active --quiet apache2; then
        log_info "停止Apache2服务..."
        systemctl stop apache2
    fi
    
    # 停止旧的Nginx
    if systemctl is-active --quiet nginx; then
        log_info "停止Nginx服务..."
        systemctl stop nginx
    fi
    
    # 停止旧的Xray
    if systemctl is-active --quiet xray; then
        log_info "停止Xray服务..."
        systemctl stop xray
    fi
}

# 开放防火墙端口
setup_firewall() {
    log_step "配置防火墙端口..."
    
    # 检查UFW
    if command -v ufw &> /dev/null; then
        log_info "配置UFW防火墙..."
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 22/tcp
        echo "y" | ufw enable || true
        log_info "UFW防火墙配置完成"
    fi
    
    # 检查iptables
    if command -v iptables &> /dev/null; then
        log_info "配置iptables规则..."
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT || true
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT || true
        iptables -I INPUT -p tcp --dport 22 -j ACCEPT || true
        # 保存规则
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        log_info "iptables规则配置完成"
    fi
}

# 安装必要的依赖
install_dependencies() {
    log_step "安装必要的依赖包..."
    
    log_info "安装基础依赖..."
    DEBIAN_FRONTEND=noninteractive apt install -y \
        curl \
        wget \
        socat \
        gnupg2 \
        ca-certificates \
        lsb-release \
        apt-transport-https \
        software-properties-common \
        dnsutils \
        net-tools || {
        log_error "依赖包安装失败"
        exit 1
    }
    
    log_info "依赖包安装完成"
}

# 安装ACME脚本
install_acme() {
    log_step "安装ACME证书管理脚本..."
    
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log_info "下载并安装ACME脚本..."
        curl -s https://get.acme.sh | sh || {
            log_error "ACME脚本安装失败"
            exit 1
        }
    else
        log_info "ACME脚本已存在"
    fi
    
    # 设置环境变量
    export PATH="$HOME/.acme.sh:$PATH"
    
    # 设置自动更新
    log_info "配置ACME自动更新..."
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade || {
        log_error "ACME自动更新配置失败"
        exit 1
    }
    
    # 设置默认CA为Let's Encrypt
    log_info "设置默认证书颁发机构为Let's Encrypt..."
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt || {
        log_error "设置默认CA失败"
        exit 1
    }
    
    log_info "ACME脚本配置完成"
}

# 申请SSL证书
get_ssl_certificate() {
    log_step "申请SSL证书..."
    
    # 确保端口80空闲
    log_info "检查端口80状态..."
    if netstat -tlnp | grep :80 > /dev/null 2>&1; then
        log_info "端口80被占用，正在释放..."
        fuser -k 80/tcp 2>/dev/null || true
        sleep 2
    fi
    
    # 创建证书目录
    mkdir -p /etc/ssl/private
    
    log_info "申请 $DOMAIN 的SSL证书..."
    ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --keylength ec-256 --force || {
        log_error "证书申请失败"
        log_error "请检查："
        log_error "1. 域名是否正确解析到此服务器"
        log_error "2. 端口80是否可以从外部访问"
        log_error "3. 防火墙是否正确配置"
        exit 1
    }
    
    # 安装证书
    log_info "安装证书到 /etc/ssl/private..."
    ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
        --fullchain-file /etc/ssl/private/fullchain.pem \
        --key-file /etc/ssl/private/private.key || {
        log_error "证书安装失败"
        exit 1
    }
    
    # 设置证书文件权限
    chmod 600 /etc/ssl/private/private.key
    chmod 644 /etc/ssl/private/fullchain.pem
    
    # 验证证书文件
    if [[ ! -f /etc/ssl/private/fullchain.pem ]] || [[ ! -f /etc/ssl/private/private.key ]]; then
        log_error "证书文件不存在"
        exit 1
    fi
    
    log_info "SSL证书配置完成"
}

# 安装Xray
install_xray() {
    log_step "安装Xray..."
    
    log_info "下载并安装最新版本的Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || {
        log_error "Xray安装失败"
        exit 1
    }
    
    # 验证安装
    if [[ ! -f /usr/local/bin/xray ]]; then
        log_error "Xray可执行文件不存在"
        exit 1
    fi
    
    log_info "Xray安装完成，版本信息："
    /usr/local/bin/xray version
}

# 安装Nginx
install_nginx() {
    log_step "安装Nginx..."
    
    # 移除旧版本
    apt remove -y nginx nginx-common nginx-core nginx-full 2>/dev/null || true
    
    # 添加Nginx官方源
    log_info "添加Nginx官方仓库..."
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
    
    # 设置优先级
    echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" > /etc/apt/preferences.d/99nginx
    
    # 更新并安装Nginx
    apt update || {
        log_error "更新软件包列表失败"
        exit 1
    }
    
    DEBIAN_FRONTEND=noninteractive apt install -y nginx || {
        log_error "Nginx安装失败"
        exit 1
    }
    
    # 验证安装
    if [[ ! -f /usr/sbin/nginx ]]; then
        log_error "Nginx可执行文件不存在"
        exit 1
    fi
    
    log_info "Nginx安装完成，版本信息："
    nginx -v
}

# 生成UUID和密钥
generate_keys() {
    log_step "生成UUID和密钥..."
    
    # 生成UUID
    UUID=$(/usr/local/bin/xray uuid)
    if [[ -z "$UUID" ]]; then
        log_error "UUID生成失败"
        exit 1
    fi
    log_info "生成的UUID: $UUID"
    
    # 生成X25519密钥对
    KEY_PAIR=$(/usr/local/bin/xray x25519)
    if [[ -z "$KEY_PAIR" ]]; then
        log_error "密钥对生成失败"
        exit 1
    fi
    
    PRIVATE_KEY=$(echo "$KEY_PAIR" | grep "Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEY_PAIR" | grep "Public key:" | awk '{print $3}')
    
    if [[ -z "$PRIVATE_KEY" ]] || [[ -z "$PUBLIC_KEY" ]]; then
        log_error "密钥解析失败"
        exit 1
    fi
    
    log_info "生成的私钥: $PRIVATE_KEY"
    log_info "生成的公钥: $PUBLIC_KEY"
}

# 配置Xray
configure_xray() {
    log_step "配置Xray..."
    
    # 确保配置目录存在
    mkdir -p /usr/local/etc/xray
    
    log_info "创建Xray配置文件..."
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
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
    
    # 创建日志目录
    mkdir -p /var/log/xray
    chown nobody:nogroup /var/log/xray
    
    # 验证配置文件
    if ! /usr/local/bin/xray -test -c /usr/local/etc/xray/config.json; then
        log_error "Xray配置文件验证失败"
        exit 1
    fi
    
    log_info "Xray配置文件创建完成"
}

# 配置Nginx
configure_nginx() {
    log_step "配置Nginx..."
    
    # 备份原配置
    if [[ -f /etc/nginx/nginx.conf ]]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
    fi
    
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
    
    # 重要：移除default server配置，避免冲突
    server {
        listen 8080;
        server_name $DOMAIN;
        
        # 使用正确的SSL证书路径
        ssl_certificate /etc/ssl/private/fullchain.pem;
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
    
    # 测试Nginx配置
    if ! nginx -t; then
        log_error "Nginx配置文件验证失败"
        exit 1
    fi
    
    log_info "Nginx配置文件创建完成"
}

# 启动服务
start_services() {
    log_step "启动服务..."
    
    # 启动Xray
    log_info "启动Xray服务..."
    systemctl enable xray
    systemctl restart xray
    
    # 等待服务启动
    sleep 3
    
    if systemctl is-active --quiet xray; then
        log_info "Xray服务启动成功"
    else
        log_error "Xray服务启动失败"
        systemctl status xray
        journalctl -u xray -n 20
        exit 1
    fi
    
    # 启动Nginx
    log_info "启动Nginx服务..."
    systemctl enable nginx
    systemctl restart nginx
    
    # 等待服务启动
    sleep 3
    
    if systemctl is-active --quiet nginx; then
        log_info "Nginx服务启动成功"
    else
        log_error "Nginx服务启动失败"
        systemctl status nginx
        journalctl -u nginx -n 20
        exit 1
    fi
    
    # 检查端口监听
    log_info "检查端口监听状态..."
    if netstat -tlnp | grep :443 > /dev/null; then
        log_info "端口443监听正常"
    else
        log_error "端口443未监听"
        exit 1
    fi
    
    if netstat -tlnp | grep :8080 > /dev/null; then
        log_info "端口8080监听正常"
    else
        log_error "端口8080未监听"
        exit 1
    fi
}

# 测试连接
test_connection() {
    log_step "测试连接..."
    
    log_info "测试HTTPS连接..."
    if curl -k -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" | grep -q "200\|301\|302"; then
        log_info "HTTPS连接测试成功"
    else
        log_warn "HTTPS连接测试失败，但这可能是正常的"
    fi
    
    log_info "测试端口443连接..."
    if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$DOMAIN/443"; then
        log_info "端口443连接测试成功"
    else
        log_warn "端口443连接测试失败"
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
    echo "  端口: 443"
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
    echo "  查看服务状态: systemctl status xray nginx"
    echo "  重启服务: systemctl restart xray nginx"
    echo "  查看日志: journalctl -u xray -f"
    echo "  查看端口: netstat -tlnp | grep -E ':(443|8080)'"
    echo
    
    log_info "客户端配置JSON (v2rayN):"
    echo "{"
    echo "  \"add\": \"$DOMAIN\","
    echo "  \"aid\": 0,"
    echo "  \"host\": \"$DOMAIN\","
    echo "  \"id\": \"$UUID\","
    echo "  \"net\": \"tcp\","
    echo "  \"path\": \"/\","
    echo "  \"port\": 443,"
    echo "  \"ps\": \"Xray-Reality\","
    echo "  \"scy\": \"none\","
    echo "  \"sni\": \"$DOMAIN\","
    echo "  \"tls\": \"reality\","
    echo "  \"type\": \"none\","
    echo "  \"v\": 2,"
    echo "  \"flow\": \"xtls-rprx-vision\","
    echo "  \"reality\": {"
    echo "    \"publicKey\": \"$PUBLIC_KEY\","
    echo "    \"shortId\": \"\","
    echo "    \"spiderX\": \"/\""
    echo "  }"
    echo "}"
    echo
    
    log_warn "重要提醒:"
    echo "  1. 请保存好UUID和密钥信息"
    echo "  2. 证书将在90天后自动续期"
    echo "  3. 请根据上述参数配置客户端"
    echo "  4. 如果连接失败，请检查防火墙和域名解析"
    echo
}

# 主函数
main() {
    clear
    echo "==============================================="
    echo "    Xray REALITY 修复版一键安装脚本"
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
    
    log_warn "安装前请确保："
    echo "  • 域名已正确解析到此服务器"
    echo "  • 防火墙已开放80和443端口"
    echo "  • 系统时间正确"
    echo
    
    read -p "确认开始安装? (y/N): " confirm_start
    if [[ ! $confirm_start =~ ^[Yy]$ ]]; then
        log_info "安装已取消"
        exit 0
    fi
    
    echo
    
    # 执行安装步骤
    get_domain
    stop_conflicting_services
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
    test_connection
    
    # 显示配置信息
    show_config
    
    log_info "安装完成！请使用上述配置信息设置客户端。"
    log_info "如有问题，请检查日志：journalctl -u xray -f"
}

# 执行主函数
main "$@"
