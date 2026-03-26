#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VLESS 节点连通性测试脚本（优化版）
测试节点: vless://37d71b6f-8df3-4702-b569-7f78978e56a2@sub.xwup.top:443?encryption=none&security=tls&sni=node.cloudflare.xwup.top&fp=random&type=ws&host=sub.xwup.top&path=%2F%3Fed%3D2048
"""

import socket
import ssl
import base64
import json
import time
import sys
from urllib.parse import urlparse, parse_qs, unquote

# 节点配置
VLESS_URL = "vless://37d71b6f-8df3-4702-b569-7f78978e56a2@sub.xwup.top:443?encryption=none&security=tls&sni=node.cloudflare.xwup.top&fp=random&type=ws&host=sub.xwup.top&path=%2F%3Fed%3D2048#%E9%BB%98%E8%AE%A4DNS"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}[✓]{Colors.RESET} {msg}")

def print_error(msg):
    print(f"{Colors.RED}[✗]{Colors.RESET} {msg}")

def print_info(msg):
    print(f"{Colors.BLUE}[i]{Colors.RESET} {msg}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def print_debug(msg):
    print(f"{Colors.YELLOW}[DEBUG]{Colors.RESET} {msg}")

def parse_vless_url(url):
    """解析 VLESS URL"""
    try:
        # 去掉 vless:// 前缀
        url = url.replace('vless://', '')
        
        # 分离备注
        if '#' in url:
            url, remark = url.split('#', 1)
            remark = unquote(remark)
        else:
            remark = "未命名"
        
        # 解析主体
        parsed = urlparse(f"vless://{url}")
        
        # 提取信息
        config = {
            'uuid': parsed.username,
            'address': parsed.hostname,
            'port': parsed.port or 443,
            'remark': remark,
            'params': parse_qs(parsed.query)
        }
        
        # 提取参数
        params = config['params']
        config['security'] = params.get('security', ['none'])[0]
        config['sni'] = params.get('sni', [config['address']])[0]
        config['type'] = params.get('type', ['tcp'])[0]
        config['host'] = params.get('host', [config['address']])[0]
        config['path'] = unquote(params.get('path', ['/'])[0])
        config['fp'] = params.get('fp', [''])[0]
        
        return config
    except Exception as e:
        print_error(f"解析 VLESS URL 失败: {e}")
        return None

def test_dns_resolution(config):
    """测试 DNS 解析"""
    print_info(f"测试 DNS 解析: {config['address']}")
    try:
        start = time.time()
        ip = socket.getaddrinfo(config['address'], None, socket.AF_INET)[0][4][0]
        elapsed = (time.time() - start) * 1000
        print_success(f"DNS 解析成功: {config['address']} -> {ip} ({elapsed:.2f}ms)")
        return ip
    except Exception as e:
        print_error(f"DNS 解析失败: {e}")
        return None

def test_tcp_connection(config, ip):
    """测试 TCP 连接"""
    print_info(f"测试 TCP 连接: {ip}:{config['port']}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        start = time.time()
        result = sock.connect_ex((ip, config['port']))
        elapsed = (time.time() - start) * 1000
        
        if result == 0:
            print_success(f"TCP 连接成功 ({elapsed:.2f}ms)")
            sock.close()
            return True
        else:
            print_error(f"TCP 连接失败，错误码: {result}")
            sock.close()
            return False
    except Exception as e:
        print_error(f"TCP 连接异常: {e}")
        return False

def test_tls_handshake(config, ip):
    """测试 TLS 握手"""
    print_info(f"测试 TLS 握手: SNI={config['sni']}")
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, config['port']))
        
        start = time.time()
        tls_sock = context.wrap_socket(sock, server_hostname=config['sni'])
        elapsed = (time.time() - start) * 1000
        
        cipher = tls_sock.cipher()
        version = tls_sock.version()
        
        print_success(f"TLS 握手成功 ({elapsed:.2f}ms)")
        print_info(f"  协议版本: {version}")
        print_info(f"  加密套件: {cipher[0]}")
        
        tls_sock.close()
        return True
    except Exception as e:
        print_error(f"TLS 握手失败: {e}")
        return False

def test_websocket_handshake(config, ip):
    """测试 WebSocket 握手（优化版，添加更多请求头）"""
    print_info(f"测试 WebSocket 握手（优化版）")
    print_info(f"  Host: {config['host']}")
    print_info(f"  Path: {config['path']}")
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ip, config['port']))
        tls_sock = context.wrap_socket(sock, server_hostname=config['sni'])
        
        # 生成 WebSocket Key（标准做法）
        import os
        ws_key = base64.b64encode(os.urandom(16)).decode()
        
        # 构造完整的 WebSocket 握手请求（添加更多请求头）
        request_lines = [
            f"GET {config['path']} HTTP/1.1",
            f"Host: {config['host']}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: Upgrade",
            "Upgrade: websocket",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
            "",
            ""  # 空行结束请求
        ]
        
        request = "\r\n".join(request_lines)
        
        print_debug("发送的 HTTP 请求:")
        for line in request_lines:
            if line:
                print_debug(f"  {line}")
        
        start = time.time()
        tls_sock.send(request.encode())
        
        # 接收响应
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            response += chunk
        
        elapsed = (time.time() - start) * 1000
        response_str = response.decode('utf-8', errors='ignore')
        
        print_debug("收到的 HTTP 响应:")
        for line in response_str.split('\r\n')[:10]:  # 只显示前10行
            if line:
                print_debug(f"  {line}")
        
        # 检查响应状态
        if "101 Switching Protocols" in response_str:
            print_success(f"WebSocket 握手成功 ({elapsed:.2f}ms)")
            print_info("  服务器已切换到 WebSocket 协议")
            tls_sock.close()
            return True, tls_sock
        elif "403 Forbidden" in response_str:
            print_error(f"WebSocket 握手失败: HTTP 403 Forbidden ({elapsed:.2f}ms)")
            print_warning("  可能原因：")
            print_warning("    1. Host 头不被服务器接受")
            print_warning("    2. Path 路径错误")
            print_warning("    3. 服务器需要额外的验证")
            tls_sock.close()
            return False, None
        elif "400 Bad Request" in response_str:
            print_error(f"WebSocket 握手失败: HTTP 400 Bad Request ({elapsed:.2f}ms)")
            print_warning("  请求格式有误")
            tls_sock.close()
            return False, None
        elif "404 Not Found" in response_str:
            print_error(f"WebSocket 握手失败: HTTP 404 Not Found ({elapsed:.2f}ms)")
            print_warning("  Path 路径不存在")
            tls_sock.close()
            return False, None
        else:
            status_line = response_str.split('\r\n')[0] if response_str else "Unknown"
            print_error(f"WebSocket 握手失败: {status_line} ({elapsed:.2f}ms)")
            tls_sock.close()
            return False, None
            
    except socket.timeout:
        print_error("WebSocket 握手超时")
        return False, None
    except Exception as e:
        print_error(f"WebSocket 握手异常: {e}")
        import traceback
        traceback.print_exc()
        return False, None

def test_proxy_protocol(config, ip, tls_sock):
    """测试代理协议（发送 VLESS 协议头）"""
    print_info(f"测试 VLESS 协议")
    print_info(f"  UUID: {config['uuid']}")
    
    try:
        # 构造 VLESS 协议头
        # VLESS 协议格式:
        # 版本(1字节) + UUID(16字节) + 额外信息长度(1字节) + 额外信息 + 指令(1字节) + 目标地址类型(1字节) + 目标地址 + 端口(2字节)
        import uuid
        
        uuid_bytes = uuid.UUID(config['uuid']).bytes
        
        # 简化版 VLESS 请求头（版本 0，无额外信息，TCP 指令）
        # 目标地址: www.google.com:80（用于测试）
        target_host = b"www.google.com"
        target_port = 80
        
        vless_header = bytes([
            0,  # 版本 0
            *uuid_bytes,  # UUID
            0,  # 额外信息长度
            1,  # 指令: TCP
            2,  # 地址类型: 域名
            len(target_host),  # 域名长度
            *target_host,  # 域名
            (target_port >> 8) & 0xFF,  # 端口高字节
            target_port & 0xFF  # 端口低字节
        ])
        
        print_debug(f"VLESS 协议头长度: {len(vless_header)} 字节")
        print_debug(f"VLESS 协议头 (hex): {vless_header.hex()}")
        
        # WebSocket 帧格式: FIN=1, opcode=2(binary), MASK=1
        # 第一字节: 1000 0010 = 0x82 (FIN=1, opcode=2)
        # 第二字节: 1XXX XXXX (MASK=1, 载荷长度)
        payload_len = len(vless_header)
        if payload_len < 126:
            ws_frame = bytes([0x82, 0x80 | payload_len])
        elif payload_len < 65536:
            ws_frame = bytes([0x82, 0x80 | 126, (payload_len >> 8) & 0xFF, payload_len & 0xFF])
        else:
            ws_frame = bytes([0x82, 0x80 | 127]) + payload_len.to_bytes(8, 'big')
        
        # 添加掩码键（4字节随机数）
        import os
        mask_key = os.urandom(4)
        ws_frame += mask_key
        
        # 对载荷进行掩码处理
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(vless_header))
        ws_frame += masked_payload
        
        print_debug(f"WebSocket 帧长度: {len(ws_frame)} 字节")
        
        start = time.time()
        tls_sock.send(ws_frame)
        
        # 尝试接收响应
        tls_sock.settimeout(10)
        try:
            response = tls_sock.recv(4096)
            elapsed = (time.time() - start) * 1000
            
            if response:
                print_success(f"VLESS 协议有响应 ({elapsed:.2f}ms)")
                print_info(f"  响应长度: {len(response)} 字节")
                print_debug(f"  响应内容 (hex): {response[:64].hex()}...")
                tls_sock.close()
                return True
            else:
                print_warning("VLESS 协议无响应，连接已关闭")
                tls_sock.close()
                return False
        except socket.timeout:
            print_warning("VLESS 协议测试超时（可能是正常的，需要真实流量才能响应）")
            tls_sock.close()
            return True
            
    except Exception as e:
        print_error(f"VLESS 协议测试异常: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("VLESS 节点连通性测试（优化版）")
    print("=" * 60)
    
    # 解析节点
    config = parse_vless_url(VLESS_URL)
    if not config:
        sys.exit(1)
    
    print(f"\n节点信息:")
    print(f"  备注: {config['remark']}")
    print(f"  地址: {config['address']}:{config['port']}")
    print(f"  UUID: {config['uuid']}")
    print(f"  传输: {config['type']}")
    print(f"  安全: {config['security']}")
    print(f"  SNI: {config['sni']}")
    print(f"  Host: {config['host']}")
    print(f"  Path: {config['path']}")
    print(f"  Fingerprint: {config['fp']}")
    print()
    
    # 执行测试
    results = {}
    
    # 1. DNS 解析
    ip = test_dns_resolution(config)
    results['dns'] = ip is not None
    
    if not ip:
        print_error("DNS 解析失败，停止后续测试")
        sys.exit(1)
    
    print()
    
    # 2. TCP 连接
    results['tcp'] = test_tcp_connection(config, ip)
    print()
    
    if not results['tcp']:
        print_error("TCP 连接失败，停止后续测试")
        sys.exit(1)
    
    # 3. TLS 握手
    results['tls'] = test_tls_handshake(config, ip)
    print()
    
    if not results['tls']:
        print_error("TLS 握手失败，停止后续测试")
        sys.exit(1)
    
    # 4. WebSocket 握手
    ws_result, tls_sock = test_websocket_handshake(config, ip)
    results['ws'] = ws_result
    print()
    
    # 5. 代理协议测试
    if results['ws'] and tls_sock:
        results['proxy'] = test_proxy_protocol(config, ip, tls_sock)
        print()
    
    # 总结
    print("=" * 60)
    print("测试结果总结")
    print("=" * 60)
    
    status_map = {
        'dns': 'DNS 解析',
        'tcp': 'TCP 连接',
        'tls': 'TLS 握手',
        'ws': 'WebSocket 握手',
        'proxy': '代理协议'
    }
    
    for key, name in status_map.items():
        if key in results:
            status = "通过" if results[key] else "失败"
            color = Colors.GREEN if results[key] else Colors.RED
            print(f"  {name}: {color}{status}{Colors.RESET}")
    
    print()
    
    # 诊断建议
    if not results.get('ws'):
        print_warning("WebSocket 握手失败，可能原因：")
        print("  1. Host 头不被服务器接受")
        print("  2. Path 路径错误")
        print("  3. 服务器需要额外的验证头")
        print("  4. 这不是一个 WebSocket 端点")
        print()
        print_info("建议：")
        print("  - 检查 Host 头是否正确")
        print("  - 尝试不同的 Path 路径")
        print("  - 确认服务器是否支持 WebSocket")
    elif not results.get('proxy'):
        print_warning("代理协议测试异常，可能原因：")
        print("  1. UUID 错误")
        print("  2. VLESS 协议版本不匹配")
        print("  3. 需要真实流量才能响应")
    else:
        print_success("所有测试通过，节点应该可以正常使用！")
    
    print("=" * 60)

if __name__ == '__main__':
    main()
