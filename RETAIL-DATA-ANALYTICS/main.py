
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import plotly.express as px
import pandas as pd
from flask import Response
import bcrypt
import secrets
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# Security Functions
def hash_password(password):
    """Hash a password for storing in the database"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

def is_session_expired():
    """Check if current session has expired"""
    if 'last_activity' in request.cookies:
        try:
            last_activity = datetime.fromisoformat(request.cookies.get('last_activity'))
            if datetime.now() - last_activity > timedelta(hours=2):
                return True
        except:
            return True
    return False

# Data Tables - Maximum 100 users, 250 products per shop owner
USERS_TABLE = {
    1: {'id': 1, 'username': 'admin', 'password': hash_password('Z@mbezi@1958'), 'is_admin': True, 'email': 'admin@example.com', 'created_date': datetime.now(), 'account_status': 'active', 'last_payment_date': datetime.now(), 'monthly_fee': 0, 'pending_deletion': False, 'deletion_scheduled': None},
    2: {'id': 2, 'username': 'hawa', 'password': hash_password('martin123'), 'is_admin': False, 'email': 'hawa@example.com', 'created_date': datetime.now(), 'account_status': 'active', 'last_payment_date': datetime.now(), 'monthly_fee': 25.00, 'pending_deletion': False, 'deletion_scheduled': None},
    3: {'id': 3, 'username': 'mauswa', 'password': hash_password('martin123'), 'is_admin': False, 'email': 'mauswa@example.com', 'created_date': datetime.now(), 'account_status': 'active', 'last_payment_date': datetime.now(), 'monthly_fee': 25.00, 'pending_deletion': False, 'deletion_scheduled': None},
    4: {'id': 4, 'username': 'john', 'password': hash_password('password123'), 'is_admin': False, 'email': 'john@example.com', 'created_date': datetime.now(), 'account_status': 'active', 'last_payment_date': datetime.now(), 'monthly_fee': 25.00, 'pending_deletion': False, 'deletion_scheduled': None}
}

STORES_TABLE = {
    1: {'id': 1, 'name': 'Main Store', 'user_id': 2, 'address': 'Main Street 123', 'phone': '+255123456789', 'created_date': datetime.now()},
    2: {'id': 2, 'name': 'Branch Store', 'user_id': 3, 'address': 'Branch Avenue 456', 'phone': '+255987654321', 'created_date': datetime.now()},
    3: {'id': 3, 'name': 'Downtown Store', 'user_id': 4, 'address': 'Downtown Plaza 789', 'phone': '+255555666777', 'created_date': datetime.now()}
}

PRODUCTS_TABLE = {
    1: {'id': 1, 'name': 'Rice 5kg', 'store_id': 1, 'quantity': 50, 'price': 25.00, 'buffer_stock': 10, 'category': 'Grains', 'barcode': '1234567890123', 'created_date': datetime.now()},
    2: {'id': 2, 'name': 'Sugar 2kg', 'store_id': 1, 'quantity': 30, 'price': 8.00, 'buffer_stock': 5, 'category': 'Sweeteners', 'barcode': '2345678901234', 'created_date': datetime.now()},
    3: {'id': 3, 'name': 'Cooking Oil 1L', 'store_id': 1, 'quantity': 8, 'price': 5.00, 'buffer_stock': 10, 'category': 'Oils', 'barcode': '3456789012345', 'created_date': datetime.now()},
    4: {'id': 4, 'name': 'Milk 1L', 'store_id': 2, 'quantity': 25, 'price': 3.00, 'buffer_stock': 5, 'category': 'Dairy', 'barcode': '4567890123456', 'created_date': datetime.now()},
    5: {'id': 5, 'name': 'Bread', 'store_id': 2, 'quantity': 15, 'price': 2.00, 'buffer_stock': 8, 'category': 'Bakery', 'barcode': '5678901234567', 'created_date': datetime.now()},
    6: {'id': 6, 'name': 'Eggs (dozen)', 'store_id': 3, 'quantity': 20, 'price': 7.00, 'buffer_stock': 5, 'category': 'Dairy', 'barcode': '6789012345678', 'created_date': datetime.now()}
}

SALES_TABLE = []

# News and Messages Tables
NEWS_TABLE = {}
MESSAGES_TABLE = {}

# Credit Management Tables
CREDITS_TABLE = []
BAD_DEBTS_TABLE = []

# Accounting Data
ACCOUNTING_DATA = {
    'expenses': [],  # rent, electricity, etc.
    'costs': [],     # product costs
    'projections': []
}

# Forensic Audit Log Table
AUDIT_LOG = []

# Caching system for frequently accessed data
CACHE = {
    'user_stores': {},  # user_id -> stores list
    'store_products': {},  # store_id -> products list
    'daily_sales': {},  # store_id -> date -> sales data
    'analytics': {},  # store_id -> analytics data
    'cache_timestamps': {}  # track when cache was last updated
}

# Indexes for faster lookups
INDEXES = {
    'username_to_id': {},  # username -> user_id
    'store_by_user': {},  # user_id -> [store_ids]
    'products_by_store': {},  # store_id -> [product_ids]
    'sales_by_date': {},  # date -> [sale_ids]
    'audit_by_user': {}  # user_id -> [audit_ids]
}

def rebuild_indexes():
    """Rebuild all indexes for faster data access"""
    global INDEXES
    INDEXES = {
        'username_to_id': {},
        'store_by_user': {},
        'products_by_store': {},
        'sales_by_date': {},
        'audit_by_user': {}
    }
    
    # Build username index
    for user_id, user in USERS_TABLE.items():
        INDEXES['username_to_id'][user['username']] = user_id
    
    # Build store indexes
    for store_id, store in STORES_TABLE.items():
        user_id = store['user_id']
        if user_id not in INDEXES['store_by_user']:
            INDEXES['store_by_user'][user_id] = []
        INDEXES['store_by_user'][user_id].append(store_id)
    
    # Build product indexes
    for product_id, product in PRODUCTS_TABLE.items():
        store_id = product['store_id']
        if store_id not in INDEXES['products_by_store']:
            INDEXES['products_by_store'][store_id] = []
        INDEXES['products_by_store'][store_id].append(product_id)
    
    # Build sales indexes
    for i, sale in enumerate(SALES_TABLE):
        date_key = sale['sale_date'].date().isoformat()
        if date_key not in INDEXES['sales_by_date']:
            INDEXES['sales_by_date'][date_key] = []
        INDEXES['sales_by_date'][date_key].append(i)
    
    # Build audit indexes
    for i, audit in enumerate(AUDIT_LOG):
        user_id = audit['user_id']
        if user_id not in INDEXES['audit_by_user']:
            INDEXES['audit_by_user'][user_id] = []
        INDEXES['audit_by_user'][user_id].append(i)

def clear_cache(cache_type=None, key=None):
    """Clear cache for better memory management"""
    if cache_type and key:
        if cache_type in CACHE and key in CACHE[cache_type]:
            del CACHE[cache_type][key]
            if key in CACHE['cache_timestamps'].get(cache_type, {}):
                del CACHE['cache_timestamps'][cache_type][key]
    elif cache_type:
        if cache_type in CACHE:
            CACHE[cache_type] = {}
            CACHE['cache_timestamps'][cache_type] = {}
    else:
        for key in CACHE:
            if key != 'cache_timestamps':
                CACHE[key] = {}
        CACHE['cache_timestamps'] = {}

def is_cache_valid(cache_type, key, max_age_minutes=10):
    """Check if cached data is still valid"""
    if cache_type not in CACHE['cache_timestamps']:
        return False
    if key not in CACHE['cache_timestamps'][cache_type]:
        return False
    
    timestamp = CACHE['cache_timestamps'][cache_type][key]
    return datetime.now() - timestamp < timedelta(minutes=max_age_minutes)

# Auto-increment IDs
next_user_id = max(USERS_TABLE.keys()) + 1 if USERS_TABLE else 1
next_store_id = max(STORES_TABLE.keys()) + 1 if STORES_TABLE else 1
next_product_id = max(PRODUCTS_TABLE.keys()) + 1 if PRODUCTS_TABLE else 1
next_sale_id = 1
next_news_id = 1
next_message_id = 1
next_audit_id = 1

# Table Management Functions
def add_user(username, password, email, is_admin=False):
    global next_user_id
    if len(USERS_TABLE) >= 100:
        return False, "Maximum user limit reached (100 users)"
    
    # Check if username already exists
    for user in USERS_TABLE.values():
        if user['username'] == username:
            return False, "Username already exists"
    
    # Validate password strength
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    new_user = {
        'id': next_user_id,
        'username': username,
        'password': hash_password(password),
        'email': email,
        'is_admin': is_admin,
        'created_date': datetime.now(),
        'account_status': 'active',
        'last_payment_date': datetime.now(),
        'monthly_fee': 0 if is_admin else 25.00,
        'pending_deletion': False,
        'deletion_scheduled': None
    }
    USERS_TABLE[next_user_id] = new_user
    next_user_id += 1
    return True, "User added successfully"

def add_store(name, user_id, address="", phone=""):
    global next_store_id
    new_store = {
        'id': next_store_id,
        'name': name,
        'user_id': user_id,
        'address': address,
        'phone': phone,
        'created_date': datetime.now()
    }
    STORES_TABLE[next_store_id] = new_store
    next_store_id += 1
    return True, "Store added successfully"

def add_product_to_store(name, store_id, quantity, price, buffer_stock, category="", barcode=""):
    global next_product_id
    
    # Check if store has reached product limit
    store_products = [p for p in PRODUCTS_TABLE.values() if p['store_id'] == store_id]
    if len(store_products) >= 250:
        return False, "Maximum product limit reached for this store (250 products)"
    
    new_product = {
        'id': next_product_id,
        'name': name,
        'store_id': store_id,
        'quantity': quantity,
        'price': price,
        'buffer_stock': buffer_stock,
        'category': category,
        'barcode': barcode,
        'created_date': datetime.now()
    }
    PRODUCTS_TABLE[next_product_id] = new_product
    next_product_id += 1
    return True, "Product added successfully"

def get_user_stores(user_id):
    # Check cache first
    cache_key = str(user_id)
    if is_cache_valid('user_stores', cache_key):
        return CACHE['user_stores'][cache_key]
    
    # Use index for faster lookup
    if user_id in INDEXES['store_by_user']:
        stores = [STORES_TABLE[store_id] for store_id in INDEXES['store_by_user'][user_id] if store_id in STORES_TABLE]
    else:
        stores = [store for store in STORES_TABLE.values() if store['user_id'] == user_id]
    
    # Cache the result
    if 'user_stores' not in CACHE['cache_timestamps']:
        CACHE['cache_timestamps']['user_stores'] = {}
    CACHE['user_stores'][cache_key] = stores
    CACHE['cache_timestamps']['user_stores'][cache_key] = datetime.now()
    
    return stores

def get_store_products(store_id):
    # Check cache first
    cache_key = str(store_id)
    if is_cache_valid('store_products', cache_key):
        return CACHE['store_products'][cache_key]
    
    # Use index for faster lookup
    if store_id in INDEXES['products_by_store']:
        products = [PRODUCTS_TABLE[product_id] for product_id in INDEXES['products_by_store'][store_id] if product_id in PRODUCTS_TABLE]
    else:
        products = [product for product in PRODUCTS_TABLE.values() if product['store_id'] == store_id]
    
    # Cache the result
    if 'store_products' not in CACHE['cache_timestamps']:
        CACHE['cache_timestamps']['store_products'] = {}
    CACHE['store_products'][cache_key] = products
    CACHE['cache_timestamps']['store_products'][cache_key] = datetime.now()
    
    return products

def get_all_users():
    return list(USERS_TABLE.values())

def mark_user_for_deletion(user_id):
    if user_id in USERS_TABLE:
        USERS_TABLE[user_id]['pending_deletion'] = True
        USERS_TABLE[user_id]['deletion_scheduled'] = datetime.now()
        USERS_TABLE[user_id]['account_status'] = 'pending_deletion'
        return True, "User marked for deletion - will be permanently deleted in 24 hours"
    return False, "User not found"

def cancel_user_deletion(user_id):
    if user_id in USERS_TABLE and USERS_TABLE[user_id].get('pending_deletion'):
        USERS_TABLE[user_id]['pending_deletion'] = False
        USERS_TABLE[user_id]['deletion_scheduled'] = None
        USERS_TABLE[user_id]['account_status'] = 'active'
        return True, "User deletion cancelled successfully"
    return False, "User not found or not scheduled for deletion"

def process_pending_deletions():
    from datetime import timedelta
    current_time = datetime.now()
    users_to_delete = []
    
    for user_id, user in USERS_TABLE.items():
        if user.get('pending_deletion') and user.get('deletion_scheduled'):
            deletion_time = user['deletion_scheduled'] + timedelta(hours=24)
            if current_time >= deletion_time:
                users_to_delete.append(user_id)
    
    for user_id in users_to_delete:
        # Delete user's stores and products
        user_stores = get_user_stores(user_id)
        for store in user_stores:
            delete_store(store['id'])
        del USERS_TABLE[user_id]
    
    return len(users_to_delete)

def delete_user(user_id):
    if user_id in USERS_TABLE:
        # Also delete user's stores and products
        user_stores = get_user_stores(user_id)
        for store in user_stores:
            delete_store(store['id'])
        deleted_user = USERS_TABLE[user_id]
        del USERS_TABLE[user_id]
        # Log the deletion
        if 'current_user' in globals() and hasattr(current_user, 'id'):
            log_audit_event(current_user.id, 'user_deleted', 'user', user_id, 
                           f"Deleted user: {deleted_user['username']}")
        return True, "User deleted successfully"
    return False, "User not found"

def delete_store(store_id):
    if store_id in STORES_TABLE:
        # Delete all products in this store
        store_products = get_store_products(store_id)
        for product in store_products:
            del PRODUCTS_TABLE[product['id']]
        del STORES_TABLE[store_id]
        return True, "Store deleted successfully"
    return False, "Store not found"

def delete_product(product_id):
    if product_id in PRODUCTS_TABLE:
        del PRODUCTS_TABLE[product_id]
        return True, "Product deleted successfully"
    return False, "Product not found"

def freeze_user_account(user_id):
    if user_id in USERS_TABLE:
        USERS_TABLE[user_id]['account_status'] = 'frozen'
        return True, "Account frozen successfully"
    return False, "User not found"

def unfreeze_user_account(user_id):
    if user_id in USERS_TABLE:
        USERS_TABLE[user_id]['account_status'] = 'active'
        return True, "Account unfrozen successfully"
    return False, "User not found"

def reset_user_password(user_id, new_password):
    if user_id in USERS_TABLE:
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters long"
        USERS_TABLE[user_id]['password'] = hash_password(new_password)
        return True, "Password reset successfully"
    return False, "User not found"

def record_payment(user_id):
    if user_id in USERS_TABLE:
        USERS_TABLE[user_id]['last_payment_date'] = datetime.now()
        if USERS_TABLE[user_id]['account_status'] == 'frozen':
            USERS_TABLE[user_id]['account_status'] = 'active'
        return True, "Payment recorded successfully"
    return False, "User not found"

def get_payment_status():
    from datetime import timedelta
    current_date = datetime.now()
    payment_alerts = []
    
    for user in USERS_TABLE.values():
        if not user['is_admin'] and user['monthly_fee'] > 0:
            last_payment = user['last_payment_date']
            days_since_payment = (current_date - last_payment).days
            next_payment_due = last_payment + timedelta(days=30)
            days_until_due = (next_payment_due - current_date).days
            
            if days_since_payment > 30:
                # Payment overdue - account should be frozen
                user['account_status'] = 'frozen'
                payment_alerts.append({
                    'user': user,
                    'status': 'overdue',
                    'days_overdue': days_since_payment - 30,
                    'message': f"Payment overdue by {days_since_payment - 30} days - Account frozen"
                })
            elif days_until_due <= 7:
                # Payment due within 7 days
                payment_alerts.append({
                    'user': user,
                    'status': 'due_soon',
                    'days_until_due': days_until_due,
                    'message': f"Payment due in {days_until_due} days"
                })
    
    return payment_alerts

def add_news(title, content, author_id, priority='normal'):
    global next_news_id
    new_news = {
        'id': next_news_id,
        'title': title,
        'content': content,
        'author_id': author_id,
        'priority': priority,  # 'high', 'normal', 'low'
        'created_date': datetime.now(),
        'is_active': True
    }
    NEWS_TABLE[next_news_id] = new_news
    next_news_id += 1
    return True, "News published successfully"

def get_active_news():
    return [news for news in NEWS_TABLE.values() if news['is_active']]

def deactivate_news(news_id):
    if news_id in NEWS_TABLE:
        NEWS_TABLE[news_id]['is_active'] = False
        return True, "News deactivated successfully"
    return False, "News not found"

def send_message(sender_id, recipient_id, subject, content):
    global next_message_id
    new_message = {
        'id': next_message_id,
        'sender_id': sender_id,
        'recipient_id': recipient_id,
        'subject': subject,
        'content': content,
        'sent_date': datetime.now(),
        'is_read': False
    }
    MESSAGES_TABLE[next_message_id] = new_message
    next_message_id += 1
    return True, "Message sent successfully"

def get_user_messages(user_id, unread_only=False):
    messages = [msg for msg in MESSAGES_TABLE.values() if msg['recipient_id'] == user_id]
    if unread_only:
        messages = [msg for msg in messages if not msg['is_read']]
    return sorted(messages, key=lambda x: x['sent_date'], reverse=True)

def mark_message_read(message_id):
    if message_id in MESSAGES_TABLE:
        MESSAGES_TABLE[message_id]['is_read'] = True
        return True, "Message marked as read"
    return False, "Message not found"

def get_unread_message_count(user_id):
    return len([msg for msg in MESSAGES_TABLE.values() if msg['recipient_id'] == user_id and not msg['is_read']])

def log_audit_event(user_id, action, target_type, target_id, details="", ip_address=""):
    global next_audit_id
    
    # Safely get request context information
    session_info = 'N/A'
    try:
        from flask import has_request_context
        if has_request_context():
            session_info = request.remote_addr
        else:
            session_info = 'System/Startup'
    except:
        session_info = 'N/A'
    
    audit_entry = {
        'id': next_audit_id,
        'user_id': user_id,
        'username': USERS_TABLE.get(user_id, {}).get('username', 'Unknown'),
        'action': action,
        'target_type': target_type,  # 'user', 'store', 'product', 'sale', 'login', 'system'
        'target_id': target_id,
        'details': details,
        'ip_address': ip_address,
        'timestamp': datetime.now(),
        'session_info': session_info
    }
    AUDIT_LOG.append(audit_entry)
    next_audit_id += 1
    return audit_entry

def get_audit_logs(limit=100, user_id=None, action_type=None, date_range=None):
    logs = AUDIT_LOG.copy()
    
    # Filter by user if specified
    if user_id:
        logs = [log for log in logs if log['user_id'] == user_id]
    
    # Filter by action type if specified
    if action_type:
        logs = [log for log in logs if log['action'] == action_type]
    
    # Filter by date range if specified
    if date_range:
        start_date, end_date = date_range
        logs = [log for log in logs if start_date <= log['timestamp'].date() <= end_date]
    
    # Sort by most recent first and limit
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return logs[:limit]

# Backup and Disaster Recovery System
import json
import gzip
import threading
import time

BACKUP_INTERVAL = 18000  # Backup every 5 hours (18000 seconds)
BACKUP_RETENTION_DAYS = 30  # Keep backups for 30 days
BACKUP_DIRECTORY = "backups"
BUSINESS_HOURS_START = 5  # 5 AM
BUSINESS_HOURS_END = 22   # 10 PM

def create_backup():
    """Create a compressed backup of all system data"""
    try:
        # Ensure backup directory exists
        if not os.path.exists(BACKUP_DIRECTORY):
            os.makedirs(BACKUP_DIRECTORY)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"retail_backup_{timestamp}.json.gz"
        backup_path = os.path.join(BACKUP_DIRECTORY, backup_filename)
        
        # Prepare backup data
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0',
            'users': USERS_TABLE,
            'stores': STORES_TABLE,
            'products': PRODUCTS_TABLE,
            'sales': [dict(sale, sale_date=sale['sale_date'].isoformat()) for sale in SALES_TABLE],
            'news': NEWS_TABLE,
            'messages': MESSAGES_TABLE,
            'audit_log': [dict(audit, timestamp=audit['timestamp'].isoformat()) for audit in AUDIT_LOG],
            'indexes': INDEXES,
            'counters': {
                'next_user_id': next_user_id,
                'next_store_id': next_store_id,
                'next_product_id': next_product_id,
                'next_sale_id': next_sale_id,
                'next_news_id': next_news_id,
                'next_message_id': next_message_id,
                'next_audit_id': next_audit_id
            }
        }
        
        # Write compressed backup
        with gzip.open(backup_path, 'wt', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        # Clean up old backups
        cleanup_old_backups()
        
        log_audit_event(0, 'backup_created', 'system', 0, f'Backup created: {backup_filename}')
        return True, backup_filename
        
    except Exception as e:
        log_audit_event(0, 'backup_failed', 'system', 0, f'Backup failed: {str(e)}')
        return False, str(e)

def restore_from_backup(backup_filename):
    """Restore system data from a backup file"""
    try:
        backup_path = os.path.join(BACKUP_DIRECTORY, backup_filename)
        
        if not os.path.exists(backup_path):
            return False, "Backup file not found"
        
        # Read backup data
        with gzip.open(backup_path, 'rt', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        # Restore global variables
        global USERS_TABLE, STORES_TABLE, PRODUCTS_TABLE, SALES_TABLE
        global NEWS_TABLE, MESSAGES_TABLE, AUDIT_LOG, INDEXES
        global next_user_id, next_store_id, next_product_id, next_sale_id
        global next_news_id, next_message_id, next_audit_id
        
        USERS_TABLE = backup_data['users']
        STORES_TABLE = backup_data['stores']
        PRODUCTS_TABLE = backup_data['products']
        NEWS_TABLE = backup_data['news']
        MESSAGES_TABLE = backup_data['messages']
        INDEXES = backup_data.get('indexes', {})
        
        # Restore sales with datetime conversion
        SALES_TABLE = []
        for sale in backup_data['sales']:
            sale['sale_date'] = datetime.fromisoformat(sale['sale_date'])
            SALES_TABLE.append(sale)
        
        # Restore audit log with datetime conversion
        AUDIT_LOG = []
        for audit in backup_data['audit_log']:
            audit['timestamp'] = datetime.fromisoformat(audit['timestamp'])
            AUDIT_LOG.append(audit)
        
        # Restore counters
        counters = backup_data.get('counters', {})
        next_user_id = counters.get('next_user_id', 1)
        next_store_id = counters.get('next_store_id', 1)
        next_product_id = counters.get('next_product_id', 1)
        next_sale_id = counters.get('next_sale_id', 1)
        next_news_id = counters.get('next_news_id', 1)
        next_message_id = counters.get('next_message_id', 1)
        next_audit_id = counters.get('next_audit_id', 1)
        
        # Rebuild indexes and clear cache
        rebuild_indexes()
        clear_cache()
        
        log_audit_event(0, 'backup_restored', 'system', 0, f'System restored from: {backup_filename}')
        return True, "System successfully restored from backup"
        
    except Exception as e:
        log_audit_event(0, 'restore_failed', 'system', 0, f'Restore failed: {str(e)}')
        return False, f"Restore failed: {str(e)}"

def cleanup_old_backups():
    """Remove backups older than BACKUP_RETENTION_DAYS"""
    try:
        if not os.path.exists(BACKUP_DIRECTORY):
            return
        
        cutoff_date = datetime.now() - timedelta(days=BACKUP_RETENTION_DAYS)
        
        for filename in os.listdir(BACKUP_DIRECTORY):
            if filename.startswith('retail_backup_') and filename.endswith('.json.gz'):
                filepath = os.path.join(BACKUP_DIRECTORY, filename)
                file_date = datetime.fromtimestamp(os.path.getctime(filepath))
                
                if file_date < cutoff_date:
                    os.remove(filepath)
                    log_audit_event(0, 'backup_cleaned', 'system', 0, f'Removed old backup: {filename}')
    
    except Exception as e:
        log_audit_event(0, 'cleanup_failed', 'system', 0, f'Backup cleanup failed: {str(e)}')

def get_available_backups():
    """Get list of available backup files"""
    try:
        if not os.path.exists(BACKUP_DIRECTORY):
            return []
        
        backups = []
        for filename in os.listdir(BACKUP_DIRECTORY):
            if filename.startswith('retail_backup_') and filename.endswith('.json.gz'):
                filepath = os.path.join(BACKUP_DIRECTORY, filename)
                stat = os.stat(filepath)
                backups.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'modified': datetime.fromtimestamp(stat.st_mtime)
                })
        
        return sorted(backups, key=lambda x: x['created'], reverse=True)
    
    except Exception as e:
        log_audit_event(0, 'backup_list_failed', 'system', 0, f'Failed to list backups: {str(e)}')
        return []

def automated_backup_worker():
    """Background worker for automated backups during business hours"""
    while True:
        try:
            current_hour = datetime.now().hour
            
            # Only backup during business hours (5 AM to 10 PM)
            if BUSINESS_HOURS_START <= current_hour <= BUSINESS_HOURS_END:
                create_backup()
                log_audit_event(0, 'scheduled_backup', 'system', 0, f'Business hours backup completed at {datetime.now().strftime("%H:%M")}')
                time.sleep(BACKUP_INTERVAL)  # Wait 5 hours
            else:
                # If outside business hours, wait until next business hour
                if current_hour < BUSINESS_HOURS_START:
                    # Wait until 5 AM
                    wait_seconds = (BUSINESS_HOURS_START - current_hour) * 3600
                else:
                    # Wait until 5 AM next day
                    wait_seconds = (24 - current_hour + BUSINESS_HOURS_START) * 3600
                
                log_audit_event(0, 'backup_scheduled', 'system', 0, f'Next backup scheduled in {wait_seconds//3600} hours (business hours only)')
                time.sleep(wait_seconds)
                
        except Exception as e:
            log_audit_event(0, 'auto_backup_failed', 'system', 0, f'Automated backup failed: {str(e)}')
            time.sleep(3600)  # Wait 1 hour before retrying

# Start backup worker thread
backup_thread = threading.Thread(target=automated_backup_worker, daemon=True)
backup_thread.start()

# Initialize indexes on startup
rebuild_indexes()

def get_daily_sales_summary(store_id, date=None):
    if date is None:
        date = datetime.now().date()
    
    daily_sales = []
    total_amount = 0
    total_quantity = 0
    
    for sale in SALES_TABLE:
        if sale['sale_date'].date() == date:
            product = PRODUCTS_TABLE.get(sale['product_id'])
            if product and product['store_id'] == store_id:
                daily_sales.append(sale)
                total_amount += sale['total_amount']
                total_quantity += sale['quantity']
    
    return {
        'date': date,
        'total_sales': len(daily_sales),
        'total_amount': total_amount,
        'total_quantity': total_quantity,
        'sales': daily_sales
    }

class User(UserMixin):
    def __init__(self, user_data):
        self.username = user_data['username']
        self.id = user_data['id']
        self.is_admin = user_data['is_admin']
        self.email = user_data['email']

@login_manager.user_loader
def load_user(user_id):
    user_data = USERS_TABLE.get(int(user_id))
    if user_data:
        return User(user_data)
    return None

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        success, message = add_user(username, password, email)
        if success:
            flash(message, 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    
    return render_template('register.html')

# Rate limiting storage
LOGIN_ATTEMPTS = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client_ip = request.remote_addr
        
        # Rate limiting - max 5 attempts per IP per 15 minutes
        current_time = datetime.now()
        if client_ip in LOGIN_ATTEMPTS:
            attempts = LOGIN_ATTEMPTS[client_ip]
            # Remove old attempts (older than 15 minutes)
            attempts = [attempt for attempt in attempts if current_time - attempt < timedelta(minutes=15)]
            LOGIN_ATTEMPTS[client_ip] = attempts
            
            if len(attempts) >= 5:
                log_audit_event(0, 'login_rate_limited', 'system', 0, f'Rate limited IP: {client_ip}', client_ip)
                flash('Too many login attempts. Please try again in 15 minutes.', 'error')
                return render_template('login.html')
        else:
            LOGIN_ATTEMPTS[client_ip] = []
        
        user_data = None
        for user in USERS_TABLE.values():
            if user['username'] == username and verify_password(password, user['password']):
                user_data = user
                break
        
        if user_data:
            # Check if account is frozen (except for admins)
            if not user_data['is_admin'] and user_data.get('account_status') == 'frozen':
                log_audit_event(user_data['id'], 'login_failed', 'user', user_data['id'], 
                              'Account frozen - login denied', request.remote_addr)
                flash('Your account has been frozen due to non-payment. Please contact administrator.', 'error')
                return render_template('login.html')
            
            user = User(user_data)
            login_user(user)
            log_audit_event(user_data['id'], 'login_success', 'user', user_data['id'], 
                          f"Login successful - {'Admin' if user.is_admin else 'User'}", request.remote_addr)
            if user.is_admin:
                flash(f'Welcome Admin {username}!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('dashboard'))
        else:
            # Record failed login attempt
            LOGIN_ATTEMPTS[client_ip].append(current_time)
            log_audit_event(0, 'login_failed', 'system', 0, f'Failed login attempt for username: {username}', request.remote_addr)
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    user_stores = get_user_stores(current_user.id)
    
    # Get products and daily sales for user's stores
    daily_sales_data = {}
    for store in user_stores:
        products = get_store_products(store['id'])
        store['products'] = products  # Keep as dict objects for template compatibility
        daily_sales_data[store['id']] = get_daily_sales_summary(store['id'])
    
    # Get news and messages for shop owners
    active_news = get_active_news()
    user_messages = get_user_messages(current_user.id)
    unread_count = get_unread_message_count(current_user.id)
    
    return render_template('dashboard.html', 
                         stores=user_stores, 
                         daily_sales=daily_sales_data,
                         generate_analytics=generate_analytics, 
                         datetime=datetime,
                         news=active_news,
                         messages=user_messages,
                         unread_count=unread_count)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        log_audit_event(current_user.id, 'unauthorized_access', 'system', 0, 
                       'Attempted access to admin dashboard', request.remote_addr)
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    # Process any pending deletions that are due
    deleted_count = process_pending_deletions()
    if deleted_count > 0:
        flash(f'Automatically deleted {deleted_count} user(s) after 24-hour period', 'info')
    
    all_stores = list(STORES_TABLE.values())
    for store in all_stores:
        products = get_store_products(store['id'])
        store['products'] = products  # Keep as dict objects for JSON serialization
    
    all_users = get_all_users()
    payment_alerts = get_payment_status()
    active_news = get_active_news()
    recent_audit_logs = get_audit_logs(50)  # Get last 50 audit entries
    
    return render_template('admin_dashboard.html', 
                         stores=all_stores, 
                         users=all_users, 
                         payment_alerts=payment_alerts, 
                         generate_analytics=generate_analytics, 
                         datetime=datetime,
                         timedelta=timedelta,
                         news=active_news,
                         audit_logs=recent_audit_logs)

@app.route('/forensic_audit')
@login_required
def forensic_audit():
    if not current_user.is_admin:
        log_audit_event(current_user.id, 'unauthorized_access', 'system', 0, 
                       'Attempted access to forensic audit', request.remote_addr)
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get filter parameters
    user_filter = request.args.get('user_id', type=int)
    action_filter = request.args.get('action')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    limit = request.args.get('limit', 500, type=int)
    
    # Parse date range
    date_range = None
    if date_from and date_to:
        try:
            start_date = datetime.strptime(date_from, '%Y-%m-%d').date()
            end_date = datetime.strptime(date_to, '%Y-%m-%d').date()
            date_range = (start_date, end_date)
        except ValueError:
            flash('Invalid date format. Use YYYY-MM-DD', 'error')
    
    audit_logs = get_audit_logs(limit, user_filter, action_filter, date_range)
    all_users = get_all_users()
    
    # Log the audit access
    log_audit_event(current_user.id, 'audit_access', 'system', 0, 
                   f'Accessed forensic audit logs with filters: user={user_filter}, action={action_filter}', 
                   request.remote_addr)
    
    return render_template('forensic_audit.html', 
                         audit_logs=audit_logs,
                         users=all_users,
                         current_filters={
                             'user_id': user_filter,
                             'action': action_filter,
                             'date_from': date_from,
                             'date_to': date_to,
                             'limit': limit
                         },
                         datetime=datetime)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    is_admin = 'is_admin' in request.form
    
    success, message = add_user(username, password, email, is_admin)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_store', methods=['POST'])
@login_required
def add_store_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    name = request.form['name']
    user_id = int(request.form['user_id'])
    address = request.form.get('address', '')
    phone = request.form.get('phone', '')
    
    success, message = add_store(name, user_id, address, phone)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    store_id = int(request.form['store_id'])
    
    # Check if user owns this store or is admin
    if not current_user.is_admin:
        store = STORES_TABLE.get(store_id)
        if not store or store['user_id'] != current_user.id:
            flash('Unauthorized access.', 'error')
            return redirect(url_for('dashboard'))
    
    name = request.form['name']
    quantity = int(request.form['quantity'])
    price = float(request.form['price'])
    buffer_stock = int(request.form['buffer_stock'])
    category = request.form.get('category', '')
    barcode = request.form.get('barcode', '')
    
    success, message = add_product_to_store(name, store_id, quantity, price, buffer_stock, category, barcode)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('Cannot delete your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    success, message = mark_user_for_deletion(user_id)
    flash(message, 'warning' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/cancel_deletion/<int:user_id>', methods=['POST'])
@login_required
def cancel_deletion_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    success, message = cancel_user_deletion(user_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product_route(product_id):
    product = PRODUCTS_TABLE.get(product_id)
    if product:
        store = STORES_TABLE.get(product['store_id'])
        if current_user.is_admin or (store and store['user_id'] == current_user.id):
            success, message = delete_product(product_id)
            flash(message, 'success' if success else 'error')
        else:
            flash('Unauthorized access.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/update_price/<int:product_id>', methods=['POST'])
@login_required
def update_price(product_id):
    product = PRODUCTS_TABLE.get(product_id)
    if product:
        store = STORES_TABLE.get(product['store_id'])
        if current_user.is_admin or (store and store['user_id'] == current_user.id):
            product['price'] = float(request.form['price'])
            flash(f'Price updated for {product["name"]}', 'success')
        else:
            flash('Unauthorized access.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/record_sale', methods=['POST'])
@login_required
def record_sale():
    global next_sale_id
    
    product_id = int(request.form['product_id'])
    quantity = int(request.form['quantity'])
    
    product = PRODUCTS_TABLE.get(product_id)
    if product:
        store = STORES_TABLE.get(product['store_id'])
        if current_user.is_admin or (store and store['user_id'] == current_user.id):
            if product['quantity'] >= quantity:
                sale = {
                    'id': next_sale_id,
                    'product_id': product_id,
                    'quantity': quantity,
                    'sale_date': datetime.now(),
                    'total_amount': quantity * product['price'],
                    'user_id': current_user.id
                }
                SALES_TABLE.append(sale)
                next_sale_id += 1
                
                product['quantity'] -= quantity
                
                # Log the sale for audit
                log_audit_event(current_user.id, 'sale_recorded', 'sale', sale['id'], 
                               f"Sale: {quantity}x {product['name']} = ${sale['total_amount']:.2f}", 
                               request.remote_addr)
                
                if product['quantity'] <= product['buffer_stock']:
                    flash(f"Restock {product['name']}! Quantity is {product['quantity']}, buffer is {product['buffer_stock']}", 'warning')
                
                flash(f'Sale recorded: {quantity} x {product["name"]}', 'success')
            else:
                flash(f'Insufficient stock. Available: {product["quantity"]}', 'error')
        else:
            flash('Unauthorized access.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/daily_sales_report/<int:store_id>')
@login_required
def daily_sales_report(store_id):
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        return "Unauthorized", 403
    
    today = datetime.now().date()
    daily_sales = []
    
    for sale in SALES_TABLE:
        if sale['sale_date'].date() == today:
            product = PRODUCTS_TABLE.get(sale['product_id'])
            if product and product['store_id'] == store_id:
                daily_sales.append({
                    'Sale ID': sale['id'],
                    'Product Name': product['name'],
                    'Category': product.get('category', 'N/A'),
                    'Barcode': product.get('barcode', 'N/A'),
                    'Quantity Sold': sale['quantity'],
                    'Unit Price ($)': f"{product['price']:.2f}",
                    'Total Amount ($)': f"{sale['total_amount']:.2f}",
                    'Sale Time': sale['sale_date'].strftime('%H:%M:%S'),
                    'Sale Date': sale['sale_date'].strftime('%Y-%m-%d'),
                    'Cashier': current_user.username
                })
    
    df = pd.DataFrame(daily_sales)
    
    if len(df) > 0:
        # Calculate totals
        total_qty = sum([sale['quantity'] for sale in SALES_TABLE if PRODUCTS_TABLE.get(sale['product_id'], {}).get('store_id') == store_id and sale['sale_date'].date() == today])
        total_amount = sum([sale['total_amount'] for sale in SALES_TABLE if PRODUCTS_TABLE.get(sale['product_id'], {}).get('store_id') == store_id and sale['sale_date'].date() == today])
        
        # Add summary rows
        summary_rows = pd.DataFrame([
            {'Sale ID': '', 'Product Name': '', 'Category': '', 'Barcode': '', 'Quantity Sold': '', 'Unit Price ($)': '', 'Total Amount ($)': '', 'Sale Time': '', 'Sale Date': '', 'Cashier': ''},
            {'Sale ID': 'SUMMARY', 'Product Name': f'{len(daily_sales)} transactions', 'Category': '', 'Barcode': '', 'Quantity Sold': total_qty, 'Unit Price ($)': 'TOTAL:', 'Total Amount ($)': f"{total_amount:.2f}", 'Sale Time': '', 'Sale Date': today.strftime('%Y-%m-%d'), 'Cashier': ''},
            {'Sale ID': 'STORE', 'Product Name': store['name'], 'Category': '', 'Barcode': '', 'Quantity Sold': '', 'Unit Price ($)': 'ADDRESS:', 'Total Amount ($)': store.get('address', 'N/A'), 'Sale Time': '', 'Sale Date': '', 'Cashier': ''}
        ])
        df = pd.concat([df, summary_rows], ignore_index=True)
    
    csv_data = df.to_csv(index=False)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=daily_sales_report_{store['name'].replace(' ', '_')}_{today}.csv"}
    )

def generate_analytics(store_id):
    store_sales = []
    for sale in SALES_TABLE:
        product = PRODUCTS_TABLE.get(sale['product_id'])
        if product and product['store_id'] == store_id:
            store_sales.append({
                'product': product['name'],
                'category': product.get('category', 'Uncategorized'),
                'quantity': sale['quantity'],
                'amount': sale['total_amount'],
                'date': sale['sale_date'],
                'hour': sale['sale_date'].hour
            })
    
    if not store_sales:
        return None
    
    df = pd.DataFrame(store_sales)
    
    # Sales by product
    fig1 = px.bar(df, x='product', y='amount', title='Sales by Product')
    
    # Daily sales trend
    daily_sales = df.groupby(df['date'].dt.date)['amount'].sum().reset_index()
    fig2 = px.line(daily_sales, x='date', y='amount', title='Daily Sales Trend')
    
    # Peak hours analysis
    hourly_sales = df.groupby('hour')['amount'].sum().reset_index()
    fig3 = px.bar(hourly_sales, x='hour', y='amount', title='Sales by Hour')
    
    # Category performance
    if 'category' in df.columns:
        category_sales = df.groupby('category')['amount'].sum().reset_index()
        fig4 = px.pie(category_sales, values='amount', names='category', title='Sales by Category')
    else:
        fig4 = px.scatter(df.groupby('product').agg({'amount': 'sum', 'quantity': 'sum'}).reset_index(), 
                         x='quantity', y='amount', text='product', title='Product Performance')
    
    return {
        'sales_by_product': fig1.to_html(),
        'daily_trend': fig2.to_html(),
        'peak_hours': fig3.to_html(),
        'category_performance': fig4.to_html()
    }

@app.route('/export_csv/<int:store_id>')
@login_required
def export_csv(store_id):
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        return "Unauthorized", 403
    
    store_sales = []
    for sale in SALES_TABLE:
        product = PRODUCTS_TABLE.get(sale['product_id'])
        if product and product['store_id'] == store_id:
            store_sales.append({
                'product': product['name'],
                'category': product.get('category', ''),
                'quantity': sale['quantity'],
                'amount': sale['total_amount'],
                'date': sale['sale_date']
            })
    
    df = pd.DataFrame(store_sales)
    csv_data = df.to_csv(index=False)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={store['name']}_sales.csv"}
    )

@app.route('/pos_system/<int:store_id>')
@login_required
def pos_system(store_id):
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    products = get_store_products(store_id)
    
    # Calculate today's sales total
    today = datetime.now().date()
    daily_sales_total = 0
    for sale in SALES_TABLE:
        if sale['sale_date'].date() == today:
            product = PRODUCTS_TABLE.get(sale['product_id'])
            if product and product['store_id'] == store_id:
                daily_sales_total += sale['total_amount']
    
    return render_template('pos_system.html', store=store, products=products, daily_sales_total=daily_sales_total)

@app.route('/process_sale', methods=['POST'])
@login_required
def process_sale():
    global next_sale_id
    
    data = request.get_json()
    sales = data.get('sales', [])
    store_id = data.get('store_id')
    
    # Verify store ownership
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        return jsonify({'success': False, 'message': 'Unauthorized access'})
    
    total_sale_amount = 0
    processed_sales = []
    
    # Process each item in the sale
    for sale_item in sales:
        product_id = sale_item['product_id']
        quantity = sale_item['quantity']
        
        product = PRODUCTS_TABLE.get(product_id)
        if not product or product['store_id'] != store_id:
            return jsonify({'success': False, 'message': f'Product {product_id} not found or unauthorized'})
        
        if product['quantity'] < quantity:
            return jsonify({'success': False, 'message': f'Insufficient stock for {product["name"]}. Available: {product["quantity"]}'})
        
        # Create sale record
        sale_record = {
            'id': next_sale_id,
            'product_id': product_id,
            'quantity': quantity,
            'sale_date': datetime.now(),
            'total_amount': quantity * product['price'],
            'user_id': current_user.id
        }
        
        SALES_TABLE.append(sale_record)
        processed_sales.append(sale_record)
        next_sale_id += 1
        
        # Update product quantity
        product['quantity'] -= quantity
        total_sale_amount += sale_record['total_amount']
    
    # Return updated product information
    updated_products = []
    for sale_item in sales:
        product_id = sale_item['product_id']
        product = PRODUCTS_TABLE.get(product_id)
        if product and product['store_id'] == store_id:
            updated_products.append({
                'id': product['id'],
                'quantity': product['quantity']
            })
    
    return jsonify({
        'success': True, 
        'total': total_sale_amount,
        'sales_count': len(processed_sales),
        'updated_products': updated_products,
        'message': f'Sale completed successfully. {len(processed_sales)} items sold.'
    })

@app.route('/freeze_account/<int:user_id>', methods=['POST'])
@login_required
def freeze_account_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    if user_id == current_user.id:
        flash('Cannot freeze your own account.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    success, message = freeze_user_account(user_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/unfreeze_account/<int:user_id>', methods=['POST'])
@login_required
def unfreeze_account_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    success, message = unfreeze_user_account(user_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    new_password = request.form['new_password']
    success, message = reset_user_password(user_id, new_password)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/record_payment/<int:user_id>', methods=['POST'])
@login_required
def record_payment_route(user_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    success, message = record_payment(user_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/add_news', methods=['POST'])
@login_required
def add_news_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    title = request.form['title']
    content = request.form['content']
    priority = request.form.get('priority', 'normal')
    
    success, message = add_news(title, content, current_user.id, priority)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/deactivate_news/<int:news_id>', methods=['POST'])
@login_required
def deactivate_news_route(news_id):
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    success, message = deactivate_news(news_id)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    recipient_id = int(request.form['recipient_id'])
    subject = request.form['subject']
    content = request.form['content']
    
    success, message = send_message(current_user.id, recipient_id, subject, content)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/mark_message_read/<int:message_id>', methods=['POST'])
@login_required
def mark_message_read_route(message_id):
    message = MESSAGES_TABLE.get(message_id)
    if message and message['recipient_id'] == current_user.id:
        success, msg = mark_message_read(message_id)
        flash(msg, 'success' if success else 'error')
    else:
        flash('Unauthorized access.', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api/table_stats')
@login_required
def table_stats():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    stats = {
        'users': {
            'count': len(USERS_TABLE),
            'max': 100,
            'remaining': 100 - len(USERS_TABLE)
        },
        'stores': {
            'count': len(STORES_TABLE),
            'by_user': {}
        },
        'products': {
            'count': len(PRODUCTS_TABLE),
            'by_store': {}
        }
    }
    
    # Products by store
    for store_id, store in STORES_TABLE.items():
        products_count = len(get_store_products(store_id))
        stats['products']['by_store'][store['name']] = {
            'count': products_count,
            'max': 250,
            'remaining': 250 - products_count
        }
    
    return jsonify(stats)

@app.route('/admin/create_backup', methods=['POST'])
@login_required
def create_backup_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    success, message = create_backup()
    flash(f'Backup {"created" if success else "failed"}: {message}', 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/business_backup_status')
@login_required
def business_backup_status():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    current_hour = datetime.now().hour
    is_business_time = BUSINESS_HOURS_START <= current_hour <= BUSINESS_HOURS_END
    
    # Calculate next backup time
    if is_business_time:
        next_backup_hour = current_hour + 5
        if next_backup_hour > BUSINESS_HOURS_END:
            next_backup_hour = BUSINESS_HOURS_START  # Next day
        status = "Active (Business Hours)"
    else:
        next_backup_hour = BUSINESS_HOURS_START
        status = "Waiting (Outside Business Hours)"
    
    return jsonify({
        'current_time': datetime.now().strftime('%H:%M'),
        'business_hours': f"{BUSINESS_HOURS_START:02d}:00 - {BUSINESS_HOURS_END:02d}:00",
        'is_business_hours': is_business_time,
        'status': status,
        'next_backup': f"{next_backup_hour:02d}:00",
        'backup_interval': f"{BACKUP_INTERVAL // 3600} hours"
    })

@app.route('/admin/restore_backup', methods=['POST'])
@login_required
def restore_backup_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    backup_filename = request.form.get('backup_filename')
    if not backup_filename:
        flash('No backup file selected.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    success, message = restore_from_backup(backup_filename)
    flash(message, 'success' if success else 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/list_backups')
@login_required
def list_backups():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    backups = get_available_backups()
    return jsonify({
        'backups': [
            {
                'filename': backup['filename'],
                'size_mb': round(backup['size'] / 1024 / 1024, 2),
                'created': backup['created'].strftime('%Y-%m-%d %H:%M:%S'),
                'age_hours': round((datetime.now() - backup['created']).total_seconds() / 3600, 1)
            }
            for backup in backups
        ]
    })

@app.route('/admin/rebuild_indexes', methods=['POST'])
@login_required
def rebuild_indexes_route():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    rebuild_indexes()
    clear_cache()
    flash('Database indexes rebuilt and cache cleared successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/credit_management')
@login_required
def credit_management():
    if current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user_stores = get_user_stores(current_user.id)
    
    # Get credits for user's stores
    active_credits = []
    overdue_credits = []
    bad_debts = []
    total_credit_amount = 0
    
    from datetime import date, timedelta
    current_date = datetime.now()
    
    for credit in CREDITS_TABLE:
        # Check if credit belongs to user's stores
        store = STORES_TABLE.get(credit['store_id'])
        if store and store['user_id'] == current_user.id:
            days_outstanding = (current_date - credit['created_date']).days
            credit['days_outstanding'] = days_outstanding
            credit['store_name'] = store['name']
            
            if credit['status'] == 'active':
                active_credits.append(credit)
                total_credit_amount += credit['amount']
                
                if days_outstanding > 14:
                    overdue_credits.append(credit)
    
    # Get bad debts
    for debt in BAD_DEBTS_TABLE:
        store = STORES_TABLE.get(debt['store_id'])
        if store and store['user_id'] == current_user.id:
            debt['store_name'] = store['name']
            bad_debts.append(debt)
    
    return render_template('credit_management.html',
                         stores=user_stores,
                         active_credits=active_credits,
                         overdue_credits=overdue_credits,
                         bad_debts=bad_debts,
                         total_credit_amount=total_credit_amount,
                         datetime=datetime)

@app.route('/add_credit_sale', methods=['POST'])
@login_required
def add_credit_sale():
    global next_sale_id
    
    client_name = request.form['client_name']
    client_phone = request.form['client_phone']
    amount = float(request.form['amount'])
    store_id = int(request.form['store_id'])
    description = request.form.get('description', '')
    
    # Verify store ownership
    store = STORES_TABLE.get(store_id)
    if not store or store['user_id'] != current_user.id:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('credit_management'))
    
    # Check if client is blacklisted
    for debt in BAD_DEBTS_TABLE:
        if debt['client_phone'] == client_phone:
            flash(f'Client {client_name} is blacklisted for bad debt!', 'error')
            return redirect(url_for('credit_management'))
    
    new_credit = {
        'id': next_sale_id,
        'client_name': client_name,
        'client_phone': client_phone,
        'amount': amount,
        'store_id': store_id,
        'description': description,
        'created_date': datetime.now(),
        'status': 'active',
        'user_id': current_user.id
    }
    
    CREDITS_TABLE.append(new_credit)
    next_sale_id += 1
    
    flash(f'Credit sale recorded for {client_name}: ${amount:.2f}', 'success')
    return redirect(url_for('credit_management'))

@app.route('/repay_credit/<int:credit_id>', methods=['POST'])
@login_required
def repay_credit(credit_id):
    for credit in CREDITS_TABLE:
        if credit['id'] == credit_id:
            store = STORES_TABLE.get(credit['store_id'])
            if store and store['user_id'] == current_user.id:
                credit['status'] = 'paid'
                credit['paid_date'] = datetime.now()
                flash(f'Credit repayment recorded for {credit["client_name"]}', 'success')
                break
    
    return redirect(url_for('credit_management'))

@app.route('/remove_bad_debt/<int:debt_id>', methods=['POST'])
@login_required
def remove_bad_debt(debt_id):
    global BAD_DEBTS_TABLE
    BAD_DEBTS_TABLE = [debt for debt in BAD_DEBTS_TABLE if debt['id'] != debt_id]
    flash('Client removed from blacklist', 'success')
    return redirect(url_for('credit_management'))

@app.route('/accounting_data')
@login_required
def accounting_data():
    if current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    user_stores = get_user_stores(current_user.id)
    
    # Calculate accounting metrics
    total_revenue = 0
    total_costs = 0
    total_inventory_value = 0
    
    for store in user_stores:
        # Revenue from sales
        for sale in SALES_TABLE:
            product = PRODUCTS_TABLE.get(sale['product_id'])
            if product and product['store_id'] == store['id']:
                total_revenue += sale['total_amount']
        
        # Inventory value
        for product in get_store_products(store['id']):
            total_inventory_value += product['quantity'] * product['price']
    
    # Get expenses from accounting data
    monthly_expenses = sum(expense['amount'] for expense in ACCOUNTING_DATA['expenses'] 
                          if expense.get('user_id') == current_user.id)
    
    profit = total_revenue - total_costs - monthly_expenses
    profit_margin = (profit / total_revenue * 100) if total_revenue > 0 else 0
    
    # Generate projections based on last 30 days
    from datetime import timedelta
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_sales = [sale for sale in SALES_TABLE 
                   if sale['sale_date'] >= thirty_days_ago]
    
    if recent_sales:
        daily_avg = sum(sale['total_amount'] for sale in recent_sales) / 30
        monthly_projection = daily_avg * 30
        yearly_projection = daily_avg * 365
    else:
        monthly_projection = yearly_projection = 0
    
    html_content = f"""
    <div class="accounting-dashboard">
        <div class="kpi-grid">
            <div class="kpi-card">
                <h3>Total Revenue</h3>
                <div class="kpi-value">${total_revenue:,.2f}</div>
            </div>
            <div class="kpi-card">
                <h3>Monthly Expenses</h3>
                <div class="kpi-value">${monthly_expenses:,.2f}</div>
            </div>
            <div class="kpi-card">
                <h3>Net Profit</h3>
                <div class="kpi-value">${profit:,.2f}</div>
            </div>
            <div class="kpi-card">
                <h3>Profit Margin</h3>
                <div class="kpi-value">{profit_margin:.1f}%</div>
            </div>
        </div>
        
        <div class="projection-section">
            <h3>📈 Sales Projections</h3>
            <p>Monthly Projection: <strong>${monthly_projection:,.2f}</strong></p>
            <p>Yearly Projection: <strong>${yearly_projection:,.2f}</strong></p>
        </div>
        
        <div class="expenses-section">
            <h3>💰 Manage Expenses</h3>
            <form onsubmit="addExpense(event)">
                <input type="text" id="expenseDescription" placeholder="Description (e.g., Rent, Electricity)" required>
                <input type="number" step="0.01" id="expenseAmount" placeholder="Amount" required>
                <button type="submit">Add Expense</button>
            </form>
            
            <div class="expenses-list">
                <h4>Current Expenses:</h4>
                <ul>
                    {''.join([f"<li>{exp['description']}: ${exp['amount']:,.2f}</li>" 
                             for exp in ACCOUNTING_DATA['expenses'] 
                             if exp.get('user_id') == current_user.id])}
                </ul>
            </div>
        </div>
        
        <button onclick="downloadReport()" class="export-btn">📊 Download Report</button>
    </div>
    """
    
    return jsonify({'html': html_content})

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    data = request.get_json()
    
    new_expense = {
        'id': len(ACCOUNTING_DATA['expenses']) + 1,
        'description': data['description'],
        'amount': float(data['amount']),
        'user_id': current_user.id,
        'created_date': datetime.now()
    }
    
    ACCOUNTING_DATA['expenses'].append(new_expense)
    return jsonify({'success': True})

# Background task to check for overdue credits and convert to bad debt
def check_overdue_credits():
    current_time = datetime.now()
    for credit in CREDITS_TABLE:
        if credit['status'] == 'active':
            days_outstanding = (current_time - credit['created_date']).days
            if days_outstanding >= 14:  # 2 weeks
                # Convert to bad debt
                bad_debt = credit.copy()
                bad_debt['blacklisted_date'] = current_time
                BAD_DEBTS_TABLE.append(bad_debt)
                credit['status'] = 'bad_debt'
                
                # Log the event
                log_audit_event(credit['user_id'], 'bad_debt_created', 'credit', credit['id'],
                               f"Credit converted to bad debt: {credit['client_name']} - ${credit['amount']:.2f}")

# Run credit check every hour
import threading
import time

def credit_check_worker():
    while True:
        try:
            check_overdue_credits()
            time.sleep(3600)  # Check every hour
        except Exception as e:
            log_audit_event(0, 'credit_check_failed', 'system', 0, f'Credit check failed: {str(e)}')
            time.sleep(3600)

# Start credit check worker thread
credit_thread = threading.Thread(target=credit_check_worker, daemon=True)
credit_thread.start()

@app.route('/update_accounting_settings', methods=['POST'])
@login_required
def update_accounting_settings():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    # This would update accounting password and permissions
    flash('Accounting settings updated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/accounting_view')
@login_required
def admin_accounting_view():
    if not current_user.is_admin:
        flash('Unauthorized access.', 'error')
        return redirect(url_for('dashboard'))
    
    # Generate comprehensive accounting view for admin
    return render_template('admin_accounting.html')

@app.route('/admin/download_system_report')
@login_required
def download_system_report():
    if not current_user.is_admin:
        return "Unauthorized", 403
    
    # Generate and return system-wide financial report
    import io
    from flask import make_response
    
    report_data = "System Financial Report\n"
    report_data += "=" * 50 + "\n\n"
    
    # Add comprehensive financial data here
    total_revenue = sum(sale['total_amount'] for sale in SALES_TABLE)
    total_inventory = sum(product['quantity'] * product['price'] 
                         for product in PRODUCTS_TABLE.values())
    
    report_data += f"Total System Revenue: ${total_revenue:,.2f}\n"
    report_data += f"Total Inventory Value: ${total_inventory:,.2f}\n"
    report_data += f"Total Active Credits: {len([c for c in CREDITS_TABLE if c['status'] == 'active'])}\n"
    report_data += f"Total Bad Debts: {len(BAD_DEBTS_TABLE)}\n"
    
    response = make_response(report_data)
    response.headers['Content-Type'] = 'text/plain'
    response.headers['Content-Disposition'] = f'attachment; filename=system_report_{datetime.now().strftime("%Y%m%d")}.txt'
    
    return response

@app.route('/update_analytics', methods=['POST'])
@login_required
def update_analytics():
    data = request.get_json()
    store_id = data.get('store_id')
    date_filter = int(data.get('date_filter', 30))
    category_filter = data.get('category_filter', '')
    
    # Filter sales data based on criteria
    from datetime import timedelta
    cutoff_date = datetime.now() - timedelta(days=date_filter)
    
    filtered_sales = []
    for sale in SALES_TABLE:
        if sale['sale_date'] >= cutoff_date:
            product = PRODUCTS_TABLE.get(sale['product_id'])
            if product and product['store_id'] == store_id:
                if not category_filter or product.get('category') == category_filter:
                    filtered_sales.append(sale)
    
    # Generate updated analytics HTML
    # This would use the same analytics generation logic but with filtered data
    return jsonify({'success': True, 'html': '<div>Updated analytics would go here</div>'})

@app.route('/export_analytics/<int:store_id>')
@login_required
def export_analytics(store_id):
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        return "Unauthorized", 403
    
    # Generate analytics export
    analytics_data = "Store Analytics Export\n"
    analytics_data += f"Store: {store['name']}\n"
    analytics_data += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    analytics_data += "=" * 50 + "\n\n"
    
    # Add analytics data here
    store_sales = [sale for sale in SALES_TABLE 
                  if PRODUCTS_TABLE.get(sale['product_id'], {}).get('store_id') == store_id]
    
    analytics_data += f"Total Sales: {len(store_sales)}\n"
    analytics_data += f"Total Revenue: ${sum(sale['total_amount'] for sale in store_sales):,.2f}\n"
    
    response = Response(
        analytics_data,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename=analytics_{store['name'].replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.txt"}
    )
    
    return response

@app.route('/api/clear_analytics_cache', methods=['POST'])
@login_required
def clear_analytics_cache():
    data = request.get_json()
    store_id = data.get('store_id')
    
    # Verify store ownership
    store = STORES_TABLE.get(store_id)
    if not store or (not current_user.is_admin and store['user_id'] != current_user.id):
        return jsonify({'success': False, 'message': 'Unauthorized access'})
    
    # Clear analytics cache for this store
    clear_cache('analytics', str(store_id))
    clear_cache('daily_sales', str(store_id))
    
    return jsonify({'success': True, 'message': 'Analytics cache cleared'})

@app.before_request
def security_headers():
    """Add security headers to all responses"""
    # Force HTTPS in production
    if not request.is_secure and request.headers.get('X-Forwarded-Proto') != 'https':
        if 'localhost' not in request.host and '127.0.0.1' not in request.host:
            return redirect(request.url.replace('http://', 'https://'))

@app.after_request
def after_request(response):
    """Add security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.plot.ly; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
    return response

if __name__ == '__main__':
    # Create initial backup on startup
    create_backup()
    app.run(host='0.0.0.0', port=5000)
