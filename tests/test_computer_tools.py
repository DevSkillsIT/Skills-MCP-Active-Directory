"""Tests for computer management tools."""

import pytest
from unittest.mock import Mock, patch
import json
from datetime import datetime, timedelta

from active_directory_mcp.tools.computer import ComputerTools
from mcp.types import TextContent
from active_directory_mcp.config.models import (
    ActiveDirectoryConfig, OrganizationalUnitsConfig)


@pytest.fixture
def mock_ldap_manager():
    """Mock LDAP manager for testing."""
    manager = Mock()
    # A Mock() answers "is the channel secure?" with a Mock, which the
    # fail-closed password pre-flight reads as no. Production runs LDAPS.
    manager.is_secure_channel.return_value = True
    manager.ad_config = ActiveDirectoryConfig(
        server="ldap://test.local:389", domain="test.local",
        base_dn="DC=test,DC=local", bind_dn="CN=svc,DC=test,DC=local", password="x")
    manager.ou_config = OrganizationalUnitsConfig(
        users_ou="OU=Users,DC=test,DC=local",
        groups_ou="OU=Groups,DC=test,DC=local",
        computers_ou="OU=Computers,DC=test,DC=local",
        service_accounts_ou="OU=Service Accounts,DC=test,DC=local")
    return manager


@pytest.fixture
def computer_tools(mock_ldap_manager):
    """Computer tools instance for testing."""
    return ComputerTools(mock_ldap_manager)


class TestComputerTools:
    """Test computer management functionality."""
    
    def test_list_computers_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer listing."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=WORKSTATION01,CN=Computers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['WORKSTATION01$'],
                    'dNSHostName': ['workstation01.test.local'],
                    'operatingSystem': ['Windows 10 Pro'],
                    'operatingSystemVersion': ['10.0 (19043)'],
                    'operatingSystemServicePack': [''],
                    'description': ['John Doe workstation'],
                    'userAccountControl': [4096],  # Workstation trust account
                    'whenCreated': [datetime.now()],
                    'lastLogon': [datetime.now() - timedelta(days=1)]
                }
            },
            {
                'dn': 'CN=SERVER01,OU=Servers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['SERVER01$'],
                    'dNSHostName': ['server01.test.local'],
                    'operatingSystem': ['Windows Server 2019 Standard'],
                    'operatingSystemVersion': ['10.0 (17763)'],
                    'description': ['File Server'],
                    'userAccountControl': [532480],  # Server trust account
                    'whenCreated': [datetime.now() - timedelta(days=30)],
                    'lastLogon': [datetime.now()]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test list_computers
        result = computer_tools.list_computers()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['count'] == 2
        assert len(response_data['computers']) == 2
        
        # Check first computer
        comp1 = response_data['computers'][0]
        assert comp1['sAMAccountName'] == 'WORKSTATION01$'
        assert comp1['dNSHostName'] == 'workstation01.test.local'
        assert comp1['operatingSystem'] == 'Windows 10 Pro'
        assert comp1['enabled'] == True
        
        # Check second computer
        comp2 = response_data['computers'][1]
        assert comp2['sAMAccountName'] == 'SERVER01$'
        assert comp2['operatingSystem'] == 'Windows Server 2019 Standard'
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer retrieval."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=WORKSTATION01,CN=Computers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['WORKSTATION01$'],
                    'dNSHostName': ['workstation01.test.local'],
                    'operatingSystem': ['Windows 10 Pro'],
                    'operatingSystemVersion': ['10.0 (19043)'],
                    'description': ['John Doe workstation'],
                    'userAccountControl': [4096],
                    'whenCreated': [datetime.now()],
                    'whenChanged': [datetime.now()],
                    'lastLogon': [datetime.now() - timedelta(hours=2)],
                    'servicePrincipalName': [
                        'HOST/workstation01',
                        'HOST/workstation01.test.local'
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_computer
        result = computer_tools.get_computer('WORKSTATION01')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['dn'] == 'CN=WORKSTATION01,CN=Computers,DC=test,DC=local'
        assert response_data['attributes']['sAMAccountName'] == ['WORKSTATION01$']
        
        # Check computed fields
        computed = response_data['computed']
        assert computed['enabled'] == True
        assert computed['computer_type'] == 'workstation'
        
        # Verify LDAP search was called with correct filter
        mock_ldap_manager.search.assert_called_once()
        call_args = mock_ldap_manager.search.call_args
        assert 'sAMAccountName=WORKSTATION01$' in call_args[1]['search_filter']
    
    def test_get_computer_not_found(self, computer_tools, mock_ldap_manager):
        """Test computer not found scenario."""
        # Mock empty search results
        mock_ldap_manager.search.return_value = []
        
        # Test get_computer
        result = computer_tools.get_computer('nonexistent')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'not found' in response_data['error']
    
    def test_create_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer creation."""
        # Mock search for existing computer (empty result)
        mock_ldap_manager.search.return_value = []
        
        # Mock successful LDAP operations
        mock_ldap_manager.add.return_value = True
        mock_ldap_manager.modify.return_value = True
        
        # Test create_computer
        result = computer_tools.create_computer(
            computer_name='NEWPC01',
            dns_hostname='newpc01.test.local',
            description='New test computer'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert response_data['computer_name'] == 'NEWPC01'
        assert response_data['dn'] == 'CN=NEWPC01,OU=Computers,DC=test,DC=local'
        assert response_data['dns_hostname'] == 'newpc01.test.local'
        
        # Verify LDAP operations were called
        mock_ldap_manager.search.assert_called()  # Check for existing computer
        mock_ldap_manager.add.assert_called_once()  # Create computer
        mock_ldap_manager.modify.assert_called()  # Enable account
    
    def test_create_computer_already_exists(self, computer_tools, mock_ldap_manager):
        """Test computer creation when computer already exists."""
        # Mock search for existing computer (computer found)
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=EXISTINGPC,OU=Computers,DC=test,DC=local'}
        ]
        
        # Test create_computer
        result = computer_tools.create_computer(
            computer_name='EXISTINGPC',
            dns_hostname='existingpc.test.local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'already exists' in response_data['error']
        
        # Verify no add operation was called
        mock_ldap_manager.add.assert_not_called()
    
    def test_modify_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer modification."""
        # Mock search for computer
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=TESTPC,OU=Computers,DC=test,DC=local'}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test modify_computer
        attributes = {
            'description': 'Updated description',
            'location': 'Building A, Room 101'
        }
        result = computer_tools.modify_computer('TESTPC', attributes)
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'modified successfully' in response_data['message']
        assert response_data['modified_attributes'] == ['description', 'location']
        
        # Verify LDAP modify was called
        mock_ldap_manager.modify.assert_called_once()
    
    def test_delete_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer deletion."""
        # Mock search for computer
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=OLDPC,OU=Computers,DC=test,DC=local', 'attributes': {'userAccountControl': 4096}}
        ]
        
        # Mock successful delete operation
        mock_ldap_manager.delete.return_value = True
        
        # Test delete_computer
        result = computer_tools.delete_computer('OLDPC')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'deleted successfully' in response_data['message']
        
        # Verify LDAP delete was called
        mock_ldap_manager.delete.assert_called_once()
    
    def test_enable_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer enabling."""
        # Mock search for computer
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=DISABLEDPC,OU=Computers,DC=test,DC=local',
             'attributes': {'userAccountControl': 4098}}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test enable_computer
        result = computer_tools.enable_computer('DISABLEDPC')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'enabled successfully' in response_data['message']
        
        # Verify LDAP modify was called with correct UAC value
        mock_ldap_manager.modify.assert_called_once()
        call_args = mock_ldap_manager.modify.call_args
        modifications = call_args[0][1]
        assert modifications['userAccountControl'][0][1] == [4096]  # Enabled computer account
    
    def test_disable_computer_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer disabling."""
        # Mock search for computer
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=ENABLEDPC,OU=Computers,DC=test,DC=local',
             'attributes': {'userAccountControl': 4096}}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test disable_computer
        result = computer_tools.disable_computer('ENABLEDPC')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'disabled successfully' in response_data['message']
        
        # Verify LDAP modify was called with correct UAC value
        mock_ldap_manager.modify.assert_called_once()
        call_args = mock_ldap_manager.modify.call_args
        modifications = call_args[0][1]
        assert modifications['userAccountControl'][0][1] == [4098]  # Disabled computer account
    
    def test_reset_computer_password_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer password reset."""
        # Mock search for computer
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=TESTPC,OU=Computers,DC=test,DC=local', 'attributes': {'userAccountControl': 4096}}
        ]
        
        # Mock successful modify operations
        mock_ldap_manager.modify.return_value = True
        
        # Test reset_computer_password
        result = computer_tools.reset_computer_password('TESTPC')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'new random password written, not returned' in response_data['message']
        # The old answer carried a random password that was never written.
        assert 'new_password' not in response_data
        assert 'Test-ComputerSecureChannel' in response_data['next_step']
        
        # a strong random password is WRITTEN (never ADUC's guessable default)
        mudanca = mock_ldap_manager.modify.call_args[0][1]
        gravada = mudanca['unicodePwd'][0][1][0]
        assert gravada != '"testpc"'.encode('utf-16-le') and len(gravada) > 40
    
    def test_get_computer_status_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer status retrieval."""
        last_logon = datetime.now() - timedelta(hours=2)
        pwd_last_set = datetime.now() - timedelta(days=30)
        
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=STATUSPC,OU=Computers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['STATUSPC$'],
                    'userAccountControl': [4096],  # Enabled
                    'lastLogon': [last_logon],
                    'pwdLastSet': [pwd_last_set],
                    'operatingSystem': ['Windows 10 Pro'],
                    'operatingSystemVersion': ['10.0 (19043)']
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_computer_status
        result = computer_tools.get_computer_status('STATUSPC')
        
        # These three return a plain dict (they wrap the List[TextContent]
        # tools and parse the payload), so there is no TextContent envelope.
        response_data = result
        # Flat shape, and no 'online'/'domain_trust_ok': those were hardcoded
        # True without ever pinging or checking a trust, so they were removed.
        assert response_data['computer_name'] == 'STATUSPC'
        assert response_data['enabled'] == True
        assert 'password_age_days' in response_data
        assert 'online' not in response_data, "campo nao medido voltou"
        assert 'domain_trust_ok' not in response_data, "campo nao medido voltou"
    
    def test_search_stale_computers_success(self, computer_tools, mock_ldap_manager):
        """Test successful stale computer search."""
        old_date = datetime.now() - timedelta(days=90)
        recent_date = datetime.now() - timedelta(days=1)
        
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=STALEPC1,OU=Computers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['STALEPC1$'],
                    'dNSHostName': ['stalepc1.test.local'],
                    'lastLogon': [old_date],
                    'pwdLastSet': [old_date],
                    'userAccountControl': [4096]
                }
            },
            {
                'dn': 'CN=ACTIVEPC1,OU=Computers,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['ACTIVEPC1$'],
                    'dNSHostName': ['activepc1.test.local'],
                    'lastLogon': [recent_date],
                    'pwdLastSet': [recent_date],
                    'userAccountControl': [4096]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test search_stale_computers with 30-day threshold
        result = computer_tools.search_stale_computers(days_inactive=30)
        
        # These three return a plain dict (they wrap the List[TextContent]
        # tools and parse the payload), so there is no TextContent envelope.
        response_data = result
        assert response_data['days_threshold'] == 30
        
        # Should find only the stale computer (90 days > 30 days threshold)
        stale_computers = response_data['stale_computers']
        assert len(stale_computers) == 1
        assert stale_computers[0]['computer_name'] == 'STALEPC1$'
        assert stale_computers[0]['days_inactive'] >= 30
    
    def test_get_computer_groups_success(self, computer_tools, mock_ldap_manager):
        """Test successful computer group membership retrieval."""
        # Mock search for computer
        computer_search_result = [
            {
                'dn': 'CN=MEMBERPC,OU=Computers,DC=test,DC=local',
                'attributes': {
                    'memberOf': [
                        'CN=Domain Computers,CN=Users,DC=test,DC=local',
                        'CN=Workstations,OU=Groups,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        # Mock search for groups
        group_search_results = [
            [
                {
                    'attributes': {
                        'sAMAccountName': ['Domain Computers'],
                        'displayName': ['Domain Computers'],
                        'description': ['All workstations and servers'],
                        'groupType': [-2147483646]
                    }
                }
            ],
            [
                {
                    'attributes': {
                        'sAMAccountName': ['Workstations'],
                        'displayName': ['Workstation Computers'],
                        'description': ['All workstation computers'],
                        'groupType': [-2147483646]
                    }
                }
            ]
        ]
        
        # Configure mock to return different results for different calls
        mock_ldap_manager.search.side_effect = [computer_search_result] + group_search_results
        
        # Test get_computer_groups
        result = computer_tools.get_computer_groups('MEMBERPC')
        
        # These three return a plain dict (they wrap the List[TextContent]
        # tools and parse the payload), so there is no TextContent envelope.
        response_data = result
        assert response_data['computer_name'] == 'MEMBERPC'
        assert response_data['group_count'] == 2
        assert len(response_data['groups']) == 2
        
        # Check group information
        groups = response_data['groups']
        assert groups[0]['group_name'] == 'Domain Computers'
        assert groups[1]['group_name'] == 'Workstations'
    
    def test_computer_account_control_checks(self, computer_tools):
        """Test computer account control flag checking."""
        # Test enabled computer account
        assert computer_tools._is_computer_enabled(4096) == True  # Normal computer account
        
        # Test disabled computer account
        assert computer_tools._is_computer_enabled(4098) == False  # Disabled computer account
        
        # Test computer type detection
        assert computer_tools._get_computer_type(4096) == 'workstation'  # Workstation
        assert computer_tools._get_computer_type(532480) == 'server'  # Server
        assert computer_tools._get_computer_type(8192) == 'domain_controller'  # Domain Controller
    
    def test_is_computer_stale(self, computer_tools):
        """Test stale computer detection logic."""
        # Test recent activity - should not be stale
        recent_date = datetime.now() - timedelta(days=1)
        assert computer_tools._is_computer_stale({'lastLogon': [recent_date]}, 30) == False
        
        # Test old activity - should be stale
        old_date = datetime.now() - timedelta(days=45)
        assert computer_tools._is_computer_stale({'lastLogon': [old_date]}, 30) == True
        
        # Test no last logon - should be stale
        assert computer_tools._is_computer_stale({'lastLogon': [None]}, 30) == True
        
        # Test missing lastLogon attribute - should be stale
        assert computer_tools._is_computer_stale({}, 30) == True
    
    def test_generate_computer_password(self, computer_tools):
        """Test computer password generation functionality."""
        # Test password generation
        password = computer_tools._generate_computer_password()
        
        # Computer passwords should be longer and more complex
        assert len(password) >= 32
        assert any(c.islower() for c in password)  # At least one lowercase
        assert any(c.isupper() for c in password)  # At least one uppercase
        assert any(c.isdigit() for c in password)  # At least one digit
        assert any(c in "!@#$%^&*+-=" for c in password)  # At least one special char
    
    def test_ldap_error_handling(self, computer_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test list_computers with error
        result = computer_tools.list_computers()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_get_schema_info(self, computer_tools):
        """Test schema information retrieval."""
        schema = computer_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'computer_attributes' in schema
        assert 'computer_types' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'list_computers' in operations
        assert 'create_computer' in operations
        assert 'modify_computer' in operations
        assert 'delete_computer' in operations
        assert 'enable_computer' in operations
        assert 'disable_computer' in operations
        assert 'reset_computer_password' in operations
        assert 'search_stale_computers' in operations
        
        # Check computer types
        assert 'workstation' in schema['computer_types']
        assert 'server' in schema['computer_types']
        assert 'domain_controller' in schema['computer_types']

