# Retail Analytics System

A comprehensive web-based retail management and analytics platform built with Flask, designed for small to medium-sized retail businesses.

## 🏪 What This System Does

The Retail Analytics System is a complete retail management solution that provides:

### Core Features
- **Multi-Store Management**: Support for up to 100 users managing multiple retail stores
- **Inventory Management**: Track up to 250 products per store with automatic low-stock alerts
- **Point of Sale (POS) System**: Modern web-based POS with barcode scanning support
- **Real-time Analytics**: Interactive charts and reports using Plotly for sales analysis
- **User Management**: Role-based access control (Admin vs Store Owners)
- **Payment Tracking**: Monthly subscription management with automatic account freezing
- **News & Communication**: Admin can broadcast updates and send private messages
- **Forensic Auditing**: Complete audit trail for security and compliance

## 🚀 Security Features

### 1. **Secure Authentication**
- Implemented password hashing using `bcrypt` for storing passwords securely.
- User accounts require strong passwords and are subject to freezing for non-payment, enhancing security.

### 2. **Session Management**
- Sessions are managed securely to prevent unauthorized access.
- Included session timeouts to minimize risk from abandoned sessions.

### 3. **Request Context Handling**
- Enhanced logging functions to safely handle information without compromising user data during application startup.

### 4. **Security Headers**
- Integrated `Flask-Talisman` to enforce security headers against common vulnerabilities such as XSS and clickjacking.

### 5. **Environment Variables Management**
- Utilized `python-dotenv` for managing sensitive configuration data such as API keys and database credentials securely.

### Admin Capabilities
- 👥 **User Management**: Add, freeze, unfreeze, and delete user accounts
- 🏪 **Store Management**: Create and manage multiple stores
- 💰 **Payment Monitoring**: Track monthly fees and freeze non-paying accounts
- 📰 **News Broadcasting**: Publish system-wide updates and announcements
- 💬 **Private Messaging**: Direct communication with store owners
- 🔍 **Forensic Auditing**: Complete system activity monitoring and security analysis
- 📊 **System Analytics**: Overview of all stores, products, and user activity

### Store Owner Capabilities
- 📦 **Product Management**: Add, update, and delete products
- 🛒 **POS System**: Process sales with barcode scanning
- 📈 **Sales Analytics**: View detailed sales reports and trends
- 📊 **Inventory Tracking**: Monitor stock levels with automatic reorder alerts
- 📰 **News & Messages**: Receive updates and communications from admin
- 📄 **Report Generation**: Export daily sales reports and analytics
real-time analytics

## 📊 Use Cases

### Perfect For:
- Small to medium retail businesses
- Multi-location stores
- Businesses needing basic inventory management
- Organizations requiring audit trails
- Companies wanting integrated POS and analytics


## 🛠️ Technical Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Plotly.js


## 🆘 Support

For technical support or feature requests, contact the system administrator through the admin dashboard messaging system.  0r 078354406