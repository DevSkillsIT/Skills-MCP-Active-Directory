"""Configuration loader for Active Directory MCP."""

import json
import os
import logging
from pathlib import Path
from typing import Optional

from ..core.redaction import register_secret
from .models import Config

logger = logging.getLogger(__name__)


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from JSON file.
    
    Args:
        config_path: Path to configuration file. If None, uses AD_MCP_CONFIG
                    environment variable.
    
    Returns:
        Config: Loaded and validated configuration
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
        json.JSONDecodeError: If config file is not valid JSON
    """
    # Determine config file path
    if config_path is None:
        config_path = os.getenv("AD_MCP_CONFIG")
        if not config_path:
            raise ValueError(
                "No configuration file specified. Either provide config_path or set AD_MCP_CONFIG environment variable."
            )
    
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    logger.info(f"Loading configuration from: {config_path}")
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = json.load(f)
        
        # Secrets are registered before validation, whose errors echo input.
        if isinstance(config_data, dict):
            for secao, chave in (("active_directory", "password"),
                                 ("client", "automation_token")):
                if isinstance(config_data.get(secao), dict):
                    register_secret(config_data[secao].get(chave))

        # Validate and create config object
        config = Config(**config_data)
        logger.info("Configuration loaded successfully")
        
        # Log configuration summary (without sensitive data)
        logger.debug(f"AD Server: {config.active_directory.server}")
        logger.debug(f"Domain: {config.active_directory.domain}")
        logger.debug(f"Base DN: {config.active_directory.base_dn}")
        logger.debug(f"SSL Enabled: {config.active_directory.use_ssl}")
        
        return config
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


def validate_config(config: Config) -> None:
    """
    Perform additional validation on configuration.
    
    Args:
        config: Configuration to validate
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Check if required OUs are under base DN
    base_dn = config.active_directory.base_dn.lower()
    
    ous = [
        config.organizational_units.users_ou,
        config.organizational_units.groups_ou,
        config.organizational_units.computers_ou,
        config.organizational_units.service_accounts_ou,
    ]
    
    for ou in ous:
        if not ou.lower().endswith(base_dn):
            logger.warning(f"OU {ou} is not under base DN {config.active_directory.base_dn}")
    
    # Validate bind DN
    if not config.active_directory.bind_dn.lower().endswith(base_dn):
        logger.warning(f"Bind DN {config.active_directory.bind_dn} is not under base DN")
    
    # Check SSL configuration
    if config.active_directory.use_ssl and config.security.enable_tls:
        if not config.active_directory.server.startswith('ldaps://'):
            logger.warning("SSL enabled but server URL doesn't use ldaps://")
    
    logger.info("Configuration validation completed")
