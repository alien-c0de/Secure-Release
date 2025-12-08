"""
Quick setup script to configure logging for Secure Release
This script helps you set up the logging configuration in config.yaml
"""

import yaml
from pathlib import Path


def setup_logging_config(config_path="config.yaml"):
    """Add or update logging configuration in config.yaml"""
    
    print("🔧 Secure Release - Logging Setup\n")
    print("="*50)
    
    # Check if config file exists
    if not Path(config_path).exists():
        print(f"❌ Error: {config_path} not found!")
        return False
    
    # Load existing config
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        print(f"✅ Loaded configuration from {config_path}")
    except Exception as e:
        print(f"❌ Error loading config: {e}")
        return False
    
    # Default logging configuration
    default_logging_config = {
        'enabled': True,
        'level': 'INFO',
        'log_dir': './logs',
        'max_file_size_mb': 10,
        'backup_count': 5,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        'date_format': '%Y-%m-%d %H:%M:%S',
        'modules': {
            'dependency_checker': 'DEBUG',
            'secret_scanner': 'INFO',
            'code_analyzer': 'INFO',
            'html_report': 'WARNING',
            'json_report': 'WARNING'
        }
    }
    
    # Check if logging section already exists
    if 'logging' in config:
        print("\n⚠️  Logging configuration already exists!")
        response = input("Do you want to overwrite it? (y/N): ").strip().lower()
        if response != 'y':
            print("❌ Setup cancelled.")
            return False
    
    # Add logging configuration
    config['logging'] = default_logging_config
    
    # Save updated config
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        print(f"\n✅ Logging configuration added to {config_path}")
    except Exception as e:
        print(f"\n❌ Error saving config: {e}")
        return False
    
    # Create logs directory
    log_dir = Path(default_logging_config['log_dir'])
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Created logs directory: {log_dir.absolute()}")
    except Exception as e:
        print(f"⚠️  Warning: Could not create logs directory: {e}")
    
    print("\n" + "="*50)
    print("🎉 Logging setup complete!\n")
    print("📋 Configuration Details:")
    print(f"   • Status: {'ENABLED' if default_logging_config['enabled'] else 'DISABLED'}")
    print(f"   • Log Level: {default_logging_config['level']}")
    print(f"   • Log Directory: {default_logging_config['log_dir']}")
    print(f"   • Max File Size: {default_logging_config['max_file_size_mb']} MB")
    print(f"   • Backup Count: {default_logging_config['backup_count']} files")
    print("\n💡 To disable logging, set 'enabled: false' in config.yaml")
    print("💡 To change log level, modify 'level' in config.yaml")
    print(f"\n📁 Logs will be saved to: {log_dir.absolute()}")
    print("\n✨ You're all set! Run your scans and check the logs folder.")
    
    return True


def verify_logger_module():
    """Verify that logger_config.py exists"""
    logger_path = Path("Utils/logger_config.py")
    if not logger_path.exists():
        print(f"\n⚠️  Warning: {logger_path} not found!")
        print("Please make sure you have created the Utils/logger_config.py file.")
        return False
    print(f"✅ Found logger module: {logger_path}")
    return True


def test_logging():
    """Test if logging is working"""
    print("\n" + "="*50)
    print("🧪 Testing logging functionality...\n")
    
    try:
        from Utils.logger_config import get_logger
        
        # Create test logger
        test_logger = get_logger("setup_test")
        
        # Test different log levels
        test_logger.debug("This is a DEBUG message")
        test_logger.info("This is an INFO message")
        test_logger.warning("This is a WARNING message")
        test_logger.error("This is an ERROR message")
        
        print("✅ Logging test completed!")
        print("📁 Check your logs directory for test log files")
        return True
        
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        return False


def main():
    """Main setup function"""
    
    # Verify logger module exists
    if not verify_logger_module():
        print("\n❌ Setup aborted. Please create logger_config.py first.")
        return
    
    # Setup logging configuration
    if not setup_logging_config():
        print("\n❌ Setup failed!")
        return
    
    # Ask if user wants to test
    print("\n" + "="*50)
    response = input("\n🧪 Would you like to test the logging system? (Y/n): ").strip().lower()
    if response != 'n':
        test_logging()
    
    print("\n" + "="*50)
    print("✅ Setup complete! Happy scanning! 🚀\n")


if __name__ == "__main__":
    main()
