from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
import json
import hashlib
import uuid
from datetime import datetime
import requests
from icecream import ic
from urllib.parse import unquote

app = Flask(__name__)
# 生产环境请使用强密钥，建议从环境变量读取
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-here-change-in-production')
# 简化会话配置，确保开发环境正常工作
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1小时会话
# 开发环境禁用安全cookie设置
app.config['SESSION_COOKIE_SECURE'] = False  # 开发环境禁用HTTPS要求
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JavaScript访问cookie
app.config['SESSION_COOKIE_SAMESITE'] = True  


# 认证API配置（安全增强版）
AUTH_API_BASE = "http://127.0.0.1:2005"

# 数据存储路径
DATA_DIR = "blog_data"
FILES_ROOT_DIR = os.path.join(DATA_DIR, "files")  # 统一文件根目录
PERMISSIONS_FILE = os.path.join(DATA_DIR, "permissions.json")

def to_web_path(path: str) -> str:
    """将系统路径转换为 Web 安全的正斜杠路径"""
    return path.replace("\\", "/").replace("//", "/")

def is_safe_path(path: str) -> bool:
    """检查路径是否安全，防止路径遍历攻击"""
    if not path:
        return True
    
    # 检查常见的路径遍历模式
    unsafe_patterns = [
        '..', '../', '..\\', '....', '..../', '....\\',
        '%2e%2e', '%2e%2e/', '%2e%2e%2f',  # URL编码的..
        '\\..', '/..', '..%2f', '..%5c'  # 各种分隔符
    ]
    
    for pattern in unsafe_patterns:
        if pattern in path:
            return False
    
    # 检查绝对路径
    if os.path.isabs(path):
        return False
    
    # 检查路径组件是否包含特殊字符
    path_components = path.replace('\\', '/').split('/')
    for component in path_components:
        if component in ('', '.', '..'):
            return False
        # 检查组件是否包含危险字符
        if any(char in component for char in ['<', '>', ':', '"', '|', '?', '*']):
            return False
    
    return True

def init_directories():
    """初始化必要的目录"""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(FILES_ROOT_DIR, exist_ok=True)  # 创建统一文件根目录
    
    # 初始化权限文件
    if not os.path.exists(PERMISSIONS_FILE):
        with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump({}, f)

def verify_token(token):
    """验证令牌"""
    if not token:
        return {"code": 401, "message": "令牌为空"}
    
    try:
        response = requests.post(f"{AUTH_API_BASE}/chk", json={"token": token})
        result = response.json()
        
        # 根据新的API规范处理响应
        if result.get('code') == 200:
            return {"code": 200, "message": "令牌有效", "data": result.get('data', {})}
        else:
            return {"code": 401, "message": result.get('message', '令牌无效或已过期')}
    except Exception as e:
        return {"code": 500, "message": "认证服务不可用"}

def get_current_user():
    """获取当前用户信息"""
    # 首先检查是否有有效的用户ID在session中
    user_id = session.get('user_id')
    if user_id:
        return user_id
    
    # 开发便利：如果设置了 dev_user，会优先返回该用户（仅用于本地开发调试）
    dev_user = session.get('dev_user')
    if dev_user:
        return dev_user

    token = session.get('token')
    if not token:
        return None
    
    result = verify_token(token)
    if result.get('code') == 200:
        return result.get('data', {}).get('user_id')
    return None

def load_permissions():
    """加载权限配置"""
    try:
        with open(PERMISSIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}


def map_virtual_to_disk(resource_path):
    """将请求中的 resource_path 映射为磁盘上实际的相对路径。
    
    在新的单根目录结构中，直接返回原始路径，因为所有文件都在同一个根目录下。
    """
    return resource_path

def save_permissions(permissions):
    """保存权限配置"""
    with open(PERMISSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(permissions, f, ensure_ascii=False, indent=2)


def ensure_permission_entry(resource_type, resource_path, owner):
    """确保资源在 permissions.json 中存在一个默认条目（首次创建时使用）。"""
    try:
        permissions = load_permissions()
        resource_key = f"{resource_type}:{to_web_path(resource_path)}"
        if resource_key not in permissions:
            if resource_type == 'file':
                owner_perms = ['read_file', 'edit_file', 'delete_file', 'change_permission']
            else:
                owner_perms = ['list_contents', 'create_file', 'create_folder', 'delete_folder', 'change_permission']

            permissions[resource_key] = {
                'users': {
                    owner: owner_perms
                }
            }
            save_permissions(permissions)
    except Exception:
        # 不要阻塞主流程，权限写入失败仅影响展示/权限管理
        pass

def get_user_files_path(user_id):
    """获取用户文件存储路径（在新结构中返回根目录）"""
    return FILES_ROOT_DIR

def check_permission(resource_type, resource_path, user_id, permission):
    resource_path=to_web_path(resource_path)
    """检查用户对资源的权限"""
    permissions = load_permissions()
    
    # 资源键
    resource_key = f"{resource_type}:{to_web_path(resource_path)}"

    # 检查权限配置
    if resource_key in permissions:
        resource_perms = permissions[resource_key]
        
        # 检查用户权限
        if user_id in resource_perms.get('users', {}):
            user_perms = resource_perms['users'][user_id]
            if permission in user_perms:
                return True
        if "*" in resource_perms.get('users', {}):
            user_perms = resource_perms['users']["*"]
            if permission in user_perms:
                return True
    
    # 在新结构中，没有默认权限，必须显式配置权限
    return False

def update_permission(resource_type, resource_path, target_user, permission, allow):
    """更新权限"""
    permissions = load_permissions()
    resource_key = f"{resource_type}:{to_web_path(resource_path)}"
    
    if resource_key not in permissions:
        permissions[resource_key] = {
            'owner': get_current_user(),
            'users': {}
        }
    
    if target_user not in permissions[resource_key]['users']:
        permissions[resource_key]['users'][target_user] = []
    
    user_perms = permissions[resource_key]['users'][target_user]
    
    if allow:
        if permission not in user_perms:
            user_perms.append(permission)
    else:
        if permission in user_perms:
            user_perms.remove(permission)
    
    save_permissions(permissions)
    return True

# 路由定义
@app.route('/')
def index():
    """首页"""
    user_id = get_current_user()
    if not user_id:
        return redirect(url_for('login'))
    
    return render_template('index.html', user_id=user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        
        # 登录输入验证
        if not user_id or not password:
            return render_template('login.html', error='用户名和密码不能为空')
        
        if len(user_id) > 50 or len(password) > 128:
            return render_template('login.html', error='用户名或密码格式无效')
        
        # 用户名格式验证（只能包含字母、数字和下划线）
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', user_id):
            return render_template('login.html', error='用户名只能包含字母、数字和下划线')
        
        # 固定设置为7天（168小时）
        keep_hours = 168
        
        try:
            response = requests.post(f"{AUTH_API_BASE}/log", json={
                "user_id": user_id,
                "password": password,
                "keep_hours": keep_hours
            }, timeout=5)
            
            result = response.json()
            if result.get('code') == 200:
                session['token'] = result['data']['token']
                session['user_id'] = user_id  # 存储用户名到session
                session.permanent = True
                # 根据keep_hours设置会话过期时间
                app.config['PERMANENT_SESSION_LIFETIME'] = keep_hours * 3600
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error=result.get('message', '登录失败'))
        except requests.exceptions.ConnectionError:
            # 开发模式：仅在调试模式下允许绕过认证
            if app.debug:
                session['token'] = f"dev_token_{user_id}"
                session['user_id'] = user_id
                session.permanent = True
                app.config['PERMANENT_SESSION_LIFETIME'] = keep_hours * 3600
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='认证服务不可用')
        except Exception as e:
            return render_template('login.html', error='认证服务异常')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """注册页面"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # 客户端验证
        if not user_id or not password:
            return render_template('register.html', error='用户名和密码不能为空')
        
        if len(user_id) < 3 or len(user_id) > 30:
            return render_template('register.html', error='用户名长度必须在3-30个字符之间')
        
        if len(password) < 8 or len(password) > 128:
            return render_template('register.html', error='密码长度必须在8-128个字符之间')
        
        if password != confirm_password:
            return render_template('register.html', error='密码不一致')
        
        # 用户名格式验证（只能包含字母、数字和下划线）
        import re
        if not re.match(r'^[a-zA-Z0-9_]+$', user_id):
            return render_template('register.html', error='用户名只能包含字母、数字和下划线')
        
        try:
            response = requests.post(f"{AUTH_API_BASE}/reg", json={
                "user_id": user_id,
                "password": password
            })
            
            result = response.json()
            if result.get('code') == 200:
                return render_template('register.html', success='注册成功，请登录')
            else:
                return render_template('register.html', error=result.get('message', '注册失败'))
        except Exception as e:
            return render_template('register.html', error='认证服务不可用')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """登出"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/files')
def list_files():
    """列出用户可访问的文件和文件夹"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    path = unquote(request.args.get('path', ''))
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(path):
        return jsonify({"error": "非法路径"}), 400
    
    # 构建完整的磁盘路径
    if path:
        base_path = os.path.join(FILES_ROOT_DIR, path)
    else:
        base_path = FILES_ROOT_DIR

    if not os.path.exists(base_path):
        return jsonify({"files": [], "folders": [], "current_path": path})
    
    files = []
    folders = []

    if check_permission('folder', path, user_id, 'list_contents'):
        for item in os.listdir(base_path):
            item_path = os.path.join(base_path, item)
            full_path = os.path.join(path, item) if path else item
            
            if os.path.isdir(item_path):
                # 检查文件夹列表权限
                folders.append({
                    'name': item,
                    'path': to_web_path(full_path),
                    'type': 'folder'
                })
            else:
                # 检查文件读取权限
                files.append({
                    'name': item,
                    'path': to_web_path(full_path),
                    'type': 'file',
                    'size': os.path.getsize(item_path)
                })
    else:
        return jsonify({"error": "无读取权限"}), 403
    
    return jsonify({
        "files": files,
        "folders": folders,
        "current_path": path
    })

@app.route('/api/file/<path:file_path>')
def get_file(file_path):
    file_path=unquote(file_path)
    file_path=os.path.join(*file_path.split("/"))
    """获取文件内容"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(file_path):
        return jsonify({"error": "非法路径"}), 400
    
    if not check_permission('file', file_path, user_id, 'read_file'):
        return jsonify({"error": "无读取权限"}), 403
    
    file_full_path = os.path.join(FILES_ROOT_DIR, file_path)
    
    try:
        with open(file_full_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({"content": content})
    except Exception as e:
        # print(e)
        return jsonify({"error": "文件读取失败"}), 500

@app.route('/api/file/<path:file_path>', methods=['POST'])
def save_file(file_path):
    file_path=unquote(file_path)

    file_path=os.path.join(*file_path.split("/"))
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(file_path):
        return jsonify({"error": "非法路径"}), 400
    
    file_full_path = os.path.join(FILES_ROOT_DIR, file_path)
    content = request.json.get('content', '')

    # 文件内容验证：防止过大文件
    if len(content) > 10 * 1024 * 1024:  # 10MB限制
        return jsonify({"error": "文件内容过大"}), 400

    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    if  os.path.exists(file_full_path):
        """保存文件内容"""
        if not check_permission('file', file_path, user_id, 'edit_file'):
            return jsonify({"error": "无编辑权限"}), 403
        if not content:
            return jsonify({"error": "文件已经存在"}), 500
    else:
        file_full_path_dir = os.path.dirname(file_full_path)
        if not check_permission('folder', os.path.dirname(file_path), user_id, 'create_file'):
            return jsonify({"error": "无创建文件权限"}), 403
    try:
        with open(file_full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        # 创建文件后，确保为该文件写入默认权限
        try:
            ensure_permission_entry('file', file_path, user_id)
        except Exception:
            pass
        return jsonify({"message": "保存成功"})
    except Exception as e:
        return jsonify({"error": "文件保存失败"}), 500

@app.route('/api/folder/<path:folder_path>', methods=['POST'])
def create_folder(folder_path):
    folder_path=unquote(folder_path)
    folder_path=os.path.join(*folder_path.split("/"))
    """创建文件夹"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(folder_path):
        return jsonify({"error": "非法路径"}), 400
    
    parent_path = os.path.dirname(folder_path)

    if not check_permission('folder', parent_path, user_id, 'create_folder'):
        return jsonify({"error": "无创建文件夹权限"}), 403

    folder_full_path = os.path.join(FILES_ROOT_DIR, folder_path)

    try:
        os.makedirs(folder_full_path, exist_ok=True)
        # 为新建文件夹写入默认权限条目
        try:
            ensure_permission_entry('folder', folder_path, user_id)
        except Exception:
            pass
        return jsonify({"message": "文件夹创建成功"})
    except Exception as e:
        return jsonify({"error": "文件夹创建失败"}), 500

@app.route('/api/delete/<path:resource_path>', methods=['POST'])
def delete_resource(resource_path):
    resource_path=unquote(resource_path)
    resource_path=os.path.join(*resource_path.split("/"))
    """删除文件或文件夹"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(resource_path):
        return jsonify({"error": "非法路径"}), 400
    
    resource_full_path = os.path.join(FILES_ROOT_DIR, resource_path)

    if os.path.isdir(resource_full_path):
        # 删除文件夹
        if not check_permission('folder', resource_path, user_id, 'delete_folder'):
            return jsonify({"error": "无删除文件夹权限"}), 403
    else:
        # 删除文件
        if not check_permission('file', resource_path, user_id, 'delete_file'):
            return jsonify({"error": "无删除文件权限"}), 403
    
    try:
        if os.path.isdir(resource_full_path):
            import shutil
            shutil.rmtree(resource_full_path)
        else:
            os.remove(resource_full_path)
        return jsonify({"message": "删除成功"})
    except Exception as e:
        return jsonify({"error": "删除失败"}), 500

@app.route('/api/search')
def search_files():
    """搜索文件"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    query = request.args.get('q', '')
    query=unquote(query)
    if not query:
        return jsonify({"results": []})
    
    # 搜索查询验证：防止恶意查询
    if len(query) > 100:
        return jsonify({"error": "搜索查询过长"}), 400
    
    # 检查查询是否包含危险字符
    dangerous_chars = ['<', '>', '&', '"', "'", ';', '|', '`', '$', '(', ')', '{', '}', '[', ']']
    if any(char in query for char in dangerous_chars):
        return jsonify({"error": "搜索查询包含非法字符"}), 400
    
    results = []
    
    def search_in_directory(directory, base_path=""):
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                relative_path = os.path.join(base_path, item) if base_path else item
                
                if os.path.isdir(item_path):
                    if check_permission('folder', relative_path, user_id, 'list_contents'):
                        search_in_directory(item_path, relative_path)
                else:
                    if (check_permission('file', relative_path, user_id, 'read_file') and 
                        item.endswith('.md')):
                        # 在文件名中搜索
                        if query.lower() in item.lower():
                            results.append({
                                'name': item,
                                'path': to_web_path(relative_path),
                                'type': 'file',
                                'match_type': 'filename'
                            })
                        else:
                            # 在文件内容中搜索
                            try:
                                with open(item_path, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    if query.lower() in content.lower():
                                        results.append({
                                            'name': item,
                                            'path': to_web_path(relative_path),
                                            'type': 'file',
                                            'match_type': 'content',
                                            'preview': content[:100] + '...' if len(content) > 100 else content
                                        })
                            except:
                                pass
        except:
            pass
    
    search_in_directory(FILES_ROOT_DIR)
    return jsonify({"results": results})

@app.route('/api/permissions/<path:resource_path>')
def get_permissions(resource_path):
    resource_path=unquote(resource_path)
    resource_path=os.path.join(*resource_path.split("/"))
    """获取资源权限"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(resource_path):
        return jsonify({"error": "非法路径"}), 400
    
    # 根据实际路径判断资源类型
    resource_full_path = os.path.join(FILES_ROOT_DIR, resource_path)
    resource_type = 'folder' if os.path.isdir(resource_full_path) else 'file'

    if not check_permission(resource_type, resource_path, user_id, 'change_permission'):
        return jsonify({"error": "无权限管理权限"}), 403

    permissions = load_permissions()
    resource_key = f"{resource_type}:{to_web_path(resource_path)}"

    # 返回请求路径对应的权限
    perm_entry = permissions.get(resource_key, {})

    return jsonify({
        "permissions": perm_entry,
        "resource_type": resource_type,
        "resource_path": resource_path
    })

@app.route('/editor')
def editor():
    """Markdown编辑器页面"""
    user_id = get_current_user()
    if not user_id:
        return redirect(url_for('login'))
    
    return render_template('editor.html')

@app.route('/api/permissions/<path:resource_path>', methods=['POST'])
def update_permissions(resource_path):
    resource_path=unquote(resource_path)
    resource_path=os.path.join(*resource_path.split("/"))
    """更新资源权限"""
    user_id = get_current_user()
    if not user_id:
        return jsonify({"error": "未登录"}), 401
    
    # 增强安全检查：防止路径遍历
    if not is_safe_path(resource_path):
        return jsonify({"error": "非法路径"}), 400
    
    disk_resource_path = map_virtual_to_disk(resource_path)
    resource_type = 'folder' if os.path.isdir(os.path.join(FILES_ROOT_DIR, disk_resource_path)) else 'file'

    if not check_permission(resource_type, resource_path, user_id, 'change_permission'):
        return jsonify({"error": "无权限管理权限"}), 403

    data = request.json
    target_user = data.get('target_user')
    permission = data.get('permission')
    allow = data.get('allow', True)

    # 权限更新参数验证
    if not target_user or not isinstance(target_user, str):
        return jsonify({"error": "目标用户参数无效"}), 400
    
    if not permission or not isinstance(permission, str):
        return jsonify({"error": "权限参数无效"}), 400
    
    # 验证权限类型
    valid_permissions = ['read_file', 'edit_file', 'delete_file', 'list_contents', 'create_file', 
                        'create_folder', 'delete_folder', 'change_permission']
    if permission not in valid_permissions:
        return jsonify({"error": "无效的权限类型"}), 400
    
    # 验证用户名格式
    if len(target_user) > 50 or any(char in target_user for char in ['<', '>', '&', '"', "'", ';', '|', '`', '$']):
        return jsonify({"error": "目标用户名格式无效"}), 400

    # 将更新写入以磁盘路径为键的权限条目，保证与实际目录一致
    if update_permission(resource_type, disk_resource_path, target_user, permission, allow):
        return jsonify({"message": "权限更新成功"})
    else:
        return jsonify({"error": "权限更新失败"}), 500
@app.route('/_debug/whoami')
def _debug_whoami():
    """开发用调试接口：返回后端当前识别的用户名（不包含 token 值）。仅用于本地调试。"""
    # 仅在调试模式下可用
    if not app.debug:
        return jsonify({'error': '调试接口仅在调试模式下可用'}), 403
    
    try:
        user = get_current_user()
        return jsonify({
            'session_has_token': bool(session.get('token')),
            'current_user': user
        })
    except Exception:
        return jsonify({'error': 'debug failed'}), 500


@app.route('/_debug/login_as')
def _debug_login_as():
        """开发用：模拟登录某个用户（在 session 中设置 dev_user）。

        用法（本地开发专用）:
            /_debug/login_as?user=Iron_Grey

        这不会修改真实认证服务，仅用于本地调试界面和权限显示。
        """
        # 仅在调试模式下可用
        if not app.debug:
            return jsonify({'error': '调试接口仅在调试模式下可用'}), 403
        
        user = request.args.get('user')
        if not user:
                return jsonify({'error': 'missing user param'}), 400
        session['dev_user'] = user
        session.permanent = True
        return jsonify({'message': f'logged in as {user}', 'current_user': user})


if __name__ == '__main__':
    init_directories()
    app.run(host='0.0.0.0', port=2006, debug=False)