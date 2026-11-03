"""Tests for user management tools."""

import pytest
from unittest.mock import Mock, patch
import json

from active_directory_mcp.tools.user import UserTools
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
def user_tools(mock_ldap_manager):
    """User tools instance for testing."""
    return UserTools(mock_ldap_manager)


class TestUserTools:
    """Test user management functionality."""
    
    def test_list_users_success(self, user_tools, mock_ldap_manager):
        """Test successful user listing."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=John Doe,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['jdoe'],
                    'displayName': ['John Doe'],
                    'mail': ['jdoe@test.local'],
                    'userAccountControl': [512]  # Enabled account
                }
            },
            {
                'dn': 'CN=Jane Smith,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['jsmith'],
                    'displayName': ['Jane Smith'],
                    'mail': ['jsmith@test.local'],
                    'userAccountControl': [514]  # Disabled account
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test list_users
        result = user_tools.list_users()
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['count'] == 2
        assert len(response_data['users']) == 2
        
        # Check first user
        user1 = response_data['users'][0]
        assert user1['sAMAccountName'] == 'jdoe'
        assert user1['displayName'] == 'John Doe'
        assert user1['enabled'] == True
        
        # Check second user
        user2 = response_data['users'][1]
        assert user2['sAMAccountName'] == 'jsmith'
        assert user2['enabled'] == False
        
        # Verify LDAP search was called
        mock_ldap_manager.search.assert_called_once()
    
    def test_get_user_success(self, user_tools, mock_ldap_manager):
        """Test successful user retrieval."""
        # Mock LDAP search results
        mock_results = [
            {
                'dn': 'CN=John Doe,OU=Users,DC=test,DC=local',
                'attributes': {
                    'sAMAccountName': ['jdoe'],
                    'displayName': ['John Doe'],
                    'mail': ['jdoe@test.local'],
                    'userAccountControl': [512],
                    'memberOf': [
                        'CN=Domain Users,CN=Users,DC=test,DC=local',
                        'CN=Sales,OU=Groups,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        mock_ldap_manager.search.return_value = mock_results
        
        # Test get_user
        result = user_tools.get_user('jdoe')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['dn'] == 'CN=John Doe,OU=Users,DC=test,DC=local'
        assert response_data['attributes']['sAMAccountName'] == ['jdoe']
        assert response_data['computed']['enabled'] == True
        # The groups come in the same answer (the separate group tool was merged).
        assert [g['nome'] for g in response_data['resumo']['grupos']] == ['Domain Users', 'Sales']
        assert response_data['resumo']['ou_caminho'] == 'Users'
        
        # Verify LDAP search was called with correct filter
        call_args = mock_ldap_manager.search.call_args_list[0]
        assert 'sAMAccountName=jdoe' in call_args[1]['search_filter']
        assert 'objectCategory=person' in call_args[1]['search_filter']
    
    def test_get_user_not_found(self, user_tools, mock_ldap_manager):
        """Test user not found scenario."""
        # Mock empty search results
        mock_ldap_manager.search.return_value = []
        
        # Test get_user
        result = user_tools.get_user('nonexistent')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'not found' in response_data['error']
    
    def test_create_user_success(self, user_tools, mock_ldap_manager):
        """Test successful user creation."""
        # Mock search for existing user (empty result)
        mock_ldap_manager.search.return_value = []
        
        # Mock successful LDAP operations
        mock_ldap_manager.add.return_value = True
        mock_ldap_manager.modify.return_value = True
        
        # Test create_user
        result = user_tools.create_user(
            username='newuser',
            password='Password123!',
            first_name='New',
            last_name='User',
            email='newuser@test.local'
        )
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert response_data['username'] == 'newuser'
        assert response_data['dn'] == 'CN=New User,OU=Users,DC=test,DC=local'
        
        # Verify LDAP operations were called
        mock_ldap_manager.search.assert_called()  # Check for existing user
        mock_ldap_manager.add.assert_called_once()  # Create user
        # password, enable, and "must change at next logon" (ADUC default)
        assert mock_ldap_manager.modify.call_count == 3
        mudancas = [c[0][1] for c in mock_ldap_manager.modify.call_args_list]
        assert {'pwdLastSet': [('MODIFY_REPLACE', [0])]} in mudancas
    
    def test_create_user_already_exists(self, user_tools, mock_ldap_manager):
        """Test user creation when user already exists."""
        # Mock search for existing user (user found)
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Existing User,OU=Users,DC=test,DC=local'}
        ]
        
        # Test create_user
        result = user_tools.create_user(
            username='existinguser',
            password='Password123!',
            first_name='Existing',
            last_name='User'
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
    
    def test_enable_user_success(self, user_tools, mock_ldap_manager):
        """Test successful user enabling."""
        # Mock search for user
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
             'attributes': {'userAccountControl': 514}}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test enable_user
        result = user_tools.enable_user('testuser')
        
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
        assert modifications['userAccountControl'][0][1] == [512]  # Enabled account
    
    def test_disable_user_success(self, user_tools, mock_ldap_manager):
        """Test successful user disabling."""
        # Mock search for user
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
             'attributes': {'userAccountControl': 512}}
        ]
        
        # Mock successful modify operation
        mock_ldap_manager.modify.return_value = True
        
        # Test disable_user
        result = user_tools.disable_user('testuser')
        
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
        assert modifications['userAccountControl'][0][1] == [514]  # Disabled account
    
    def test_reset_password_with_generated_password(self, user_tools, mock_ldap_manager):
        """Test password reset with auto-generated password."""
        # Mock search for user
        # LDAPManager.search always returns dn + attributes; omitting
        # 'attributes' made the tool raise KeyError and report success=False.
        mock_ldap_manager.search.return_value = [
            {'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
             'attributes': {'sAMAccountName': 'testuser', 'userAccountControl': 512}}
        ]
        
        # Mock successful modify operations
        mock_ldap_manager.modify.return_value = True
        
        # Test reset_password without providing new password
        result = user_tools.reset_password('testuser')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == True
        assert 'new_password' in response_data
        assert len(response_data['new_password']) >= 12  # Generated password should be at least 12 chars
        # Response now reports requested inputs and the verified effect separately.
        assert response_data['requested']['force_change'] == True
        assert 'set must change at next logon' in response_data['changes_applied']
        assert 'effective' in response_data

        # Verify LDAP modify was called (password + force change)
        assert mock_ldap_manager.modify.call_count == 2
    
    def test_get_user_groups_success(self, user_tools, mock_ldap_manager):
        """Test successful user group retrieval."""
        # Mock search for user
        user_search_result = [
            {
                'dn': 'CN=Test User,OU=Users,DC=test,DC=local',
                'attributes': {
                    'memberOf': [
                        'CN=Domain Users,CN=Users,DC=test,DC=local',
                        'CN=Sales,OU=Groups,DC=test,DC=local'
                    ]
                }
            }
        ]
        
        # Mock search for groups
        group_search_results = [
            [
                {
                    'attributes': {
                        'sAMAccountName': ['Domain Users'],
                        'displayName': ['Domain Users'],
                        'description': ['All domain users'],
                        'groupType': [-2147483646]
                    }
                }
            ],
            [
                {
                    'attributes': {
                        'sAMAccountName': ['Sales'],
                        'displayName': ['Sales Team'],
                        'description': ['Sales department'],
                        'groupType': [-2147483646]
                    }
                }
            ]
        ]
        
        # Configure mock to return different results for different calls
        mock_ldap_manager.search.side_effect = [user_search_result] + group_search_results
        
        # Test get_user_groups
        result = user_tools.get_user_groups('testuser')
        
        # Verify result
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['username'] == 'testuser'
        assert response_data['group_count'] == 2
        assert len(response_data['groups']) == 2
        
        # Check group information
        groups = response_data['groups']
        assert groups[0]['sAMAccountName'] == 'Domain Users'
        assert groups[1]['sAMAccountName'] == 'Sales'
    
    def test_ldap_error_handling(self, user_tools, mock_ldap_manager):
        """Test LDAP error handling."""
        # Mock LDAP exception
        from ldap3.core.exceptions import LDAPException
        mock_ldap_manager.search.side_effect = LDAPException("Connection failed")
        
        # Test list_users with error
        result = user_tools.list_users()
        
        # Verify error handling
        assert len(result) == 1
        assert isinstance(result[0], TextContent)
        
        # Parse JSON response
        response_data = json.loads(result[0].text)
        assert response_data['success'] == False
        assert 'Connection failed' in response_data['error']
        assert response_data['type'] == 'LDAPException'
    
    def test_password_generation(self, user_tools):
        """Test password generation functionality."""
        # Test password generation
        password = user_tools._generate_password()
        
        # Verify password meets requirements
        assert len(password) >= 12
        assert any(c.islower() for c in password)  # At least one lowercase
        assert any(c.isupper() for c in password)  # At least one uppercase
        assert any(c.isdigit() for c in password)  # At least one digit
        assert any(c in "!@#$%^&*" for c in password)  # At least one special char
    
    def test_user_account_control_checks(self, user_tools):
        """Test user account control flag checking."""
        # Test enabled account
        assert user_tools._is_user_enabled(512) == True  # Normal account
        
        # Test disabled account
        assert user_tools._is_user_enabled(514) == False  # Disabled account
        
        # Test locked account
        assert user_tools._is_user_locked(16) == True  # Lockout flag set
        assert user_tools._is_user_locked(512) == False  # Normal account
    
    def test_get_schema_info(self, user_tools):
        """Test schema information retrieval."""
        schema = user_tools.get_schema_info()
        
        assert 'operations' in schema
        assert 'user_attributes' in schema
        assert 'required_permissions' in schema
        
        # Check some expected operations
        operations = schema['operations']
        assert 'list_users' in operations
        assert 'create_user' in operations
        assert 'modify_user' in operations
        assert 'delete_user' in operations
