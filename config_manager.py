# config_manager.py
import configparser
import os

CONFIG_FILE = 'config.ini'

def save_settings(data):
    """Salva as configurações no arquivo config.ini."""
    config = configparser.ConfigParser()
    config['ZABBIX'] = {
        'url': data['zabbix_url'],
        'user': data['zabbix_user'],
        'password': data['zabbix_pass']
    }
    config['SSH'] = {
        'user': data['ssh_user'],
        'password': data['ssh_pass']
    }
    
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

def load_settings():
    """Carrega as configurações do arquivo config.ini."""
    if not os.path.exists(CONFIG_FILE):
        return None
        
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    try:
        settings = {
            'zabbix_url': config.get('ZABBIX', 'url'),
            'zabbix_user': config.get('ZABBIX', 'user'),
            'zabbix_pass': config.get('ZABBIX', 'password'),
            'ssh_user': config.get('SSH', 'user'),
            'ssh_pass': config.get('SSH', 'password')
        }
        return settings
    except (configparser.NoSectionError, configparser.NoOptionError):
        return None