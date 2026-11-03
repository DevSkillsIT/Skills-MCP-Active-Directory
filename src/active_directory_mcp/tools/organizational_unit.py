"""Organizational Unit management tools for Active Directory."""

from typing import List, Dict, Any, Optional

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE, BASE

from .base import BaseTool
from ..core.logging import log_ldap_operation


class OrganizationalUnitTools(BaseTool):
    """Tools for managing Active Directory Organizational Units."""
    
    def list_ous(self, parent_ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                attributes: Optional[List[str]] = None, recursive: bool = True) -> List[Dict[str, Any]]:
        """
        List Organizational Units in Active Directory.
        
        Args:
            parent_ou: Parent OU to search in (optional, defaults to base DN)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            recursive: Search recursively in sub-OUs (default: True)
            
        Returns:
            List of MCP content objects with OU information
        """
        recusa = self._recusa_de_consulta("list_ous", filter_criteria, attributes)
        if recusa is not None:
            return recusa
        try:
            # Determine search base
            if parent_ou:
                search_base = parent_ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter
            base_filter = "(objectClass=organizationalUnit)"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
            # Determine search scope
            search_scope = ldap3.SUBTREE if recursive else 1  # 1 = ONELEVEL equivalent
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'name', 'description', 'managedBy', 'whenCreated', 'whenChanged',
                    'gPLink', 'gPOptions', 'streetAddress', 'l', 'st', 'postalCode', 'c'
                ]
            
            self.logger.info(f"Listing OUs from {search_base} (recursive: {recursive})")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
                search_scope=search_scope
            )
            
            # Process results
            ous = []
            for entry in results:
                ou_info = {
                    'dn': entry['dn'],
                    'name': self._get_attr(entry['attributes'], 'name', ''),
                    'description': self._get_attr(entry['attributes'], 'description', ''),
                    'level': self._calculate_ou_level(entry['dn'], search_base)
                }
                
                # Add managed by information
                managed_by = entry['attributes'].get('managedBy', [])
                if managed_by:
                    ou_info['managedBy'] = managed_by[0]
                
                # Add GP Link information if present
                gp_link = entry['attributes'].get('gPLink', [])
                if gp_link:
                    ou_info['linkedGPOs'] = self._parse_gp_link(gp_link[0])
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['name', 'description', 'managedBy', 'gPLink'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if isinstance(value, list) and len(value) == 1:
                            ou_info[attr] = value[0]
                        else:
                            ou_info[attr] = value
                
                ous.append(ou_info)
            
            # Sort by level and name for better organization
            ous.sort(key=lambda x: (x['level'], x['name']))
            
            log_ldap_operation("list_ous", search_base, True, f"Found {len(ous)} OUs")
            
            response_data = {
                "organizational_units": ous,
                "count": len(ous),
                "search_base": search_base,
                "recursive": recursive,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_ous")
            
        except Exception as e:
            return self._handle_ldap_error(e, "list_ous", search_base)
    
    def get_ou(self, ou_dn: str, attributes: Optional[List[str]] = None,
               object_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get an Organizational Unit together with what it contains.

        The OU's attributes and its direct children come back in one answer:
        measured 2026-09-19, a model checking a move called details and
        contents of the same two OUs in pairs, six rounds in a row.

        Args:
            ou_dn: Distinguished name of the OU
            attributes: Specific attributes to retrieve (optional)
            object_types: Which children to list (user, group, computer,
                organizationalUnit); None lists all of them

        Returns:
            List of MCP content objects with OU information
        """
        try:
            # Validate DN
            if not self._validate_dn(ou_dn):
                return self._format_response({
                    "success": False,
                    "error": f"Invalid DN format: {ou_dn}",
                    "ou_dn": ou_dn
                }, "get_ou")
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'name', 'description', 'managedBy', 'whenCreated', 'whenChanged',
                    'gPLink', 'gPOptions', 'streetAddress', 'l', 'st', 'postalCode', 'c',
                    'objectGUID', 'objectSid'
                ]
            
            self.logger.info(f"Getting OU information for: {ou_dn}")
            
            # Perform search
            results = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=attributes,
                search_scope=ldap3.BASE
            )
            
            if not results:
                log_ldap_operation("get_ou", ou_dn, False, "OU not found")
                return self._format_response({
                    "success": False,
                    "error": f"OU not found: {ou_dn}",
                    "ou_dn": ou_dn
                }, "get_ou")
            
            ou_entry = results[0]
            ou_info = {
                'dn': ou_entry['dn'],
                # Null attributes carried no information and cost tokens.
                'attributes': {k: v for k, v in ou_entry['attributes'].items()
                               if v not in (None, "", [])}
            }
            
            # One LEVEL search answers both the counts and the listing; it
            # used to take two extra searches just to count.
            todos = self._listar_conteudo(ou_dn, None)
            conteudo = self._listar_conteudo(ou_dn, object_types) \
                if object_types else todos
            ou_info['computed'] = {
                'child_objects_count': len(todos),
                'sub_ous_count': sum(1 for o in todos if o['type'] == 'organizationalUnit'),
                'level': self._calculate_ou_level(ou_dn, self.ldap.ad_config.base_dn)
            }

            # gPLink is single-valued: ldap3 hands back a str, and the old
            # gp_link[0] parsed its FIRST CHARACTER, so no GPO was ever listed.
            gp_link = self._get_attr(ou_entry['attributes'], 'gPLink', '')
            if gp_link:
                ou_info['computed']['linked_gpos'] = self._parse_gp_link(str(gp_link))

            ou_info.update(self._resumo_do_conteudo(conteudo, object_types))
            
            log_ldap_operation("get_ou", ou_dn, True, f"Retrieved OU: {ou_dn}")
            
            return self._format_response(ou_info, "get_ou")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_ou", ou_dn)
    
    def create_ou(self, name: str, parent_ou: Optional[str] = None, description: Optional[str] = None,
                 managed_by: Optional[str] = None, additional_attributes: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Create a new Organizational Unit.
        
        Args:
            name: Name of the OU
            parent_ou: Parent OU DN (optional, defaults to base DN)
            description: OU description (optional)
            managed_by: DN of user/group managing this OU (optional)
            additional_attributes: Additional attributes to set (optional)
            
        Returns:
            List of MCP content objects with creation result
        """
        try:
            # Determine parent OU
            if parent_ou is None:
                parent_ou = self.ldap.ad_config.base_dn
            
            # Build DN
            ou_dn = f"OU={name},{parent_ou}"

            # Check if OU already exists by searching the PARENT container.
            # Searching with search_base=ou_dn would raise NO_OBJECT when the OU
            # does not exist yet, so we query the parent and filter by name.
            escaped_name = self._escape_ldap_filter(name)
            existing_ou = self.ldap.search(
                search_base=parent_ou,
                search_filter=f"(&(objectClass=organizationalUnit)(ou={escaped_name}))",
                attributes=['name'],
                search_scope=ldap3.LEVEL
            )
            
            if existing_ou:
                log_ldap_operation("create_ou", ou_dn, False, "OU already exists")
                return self._format_response({
                    "success": False,
                    "error": f"OU '{name}' already exists in {parent_ou}",
                    "ou_name": name,
                    "parent_ou": parent_ou
                }, "create_ou")
            
            # Prepare OU attributes
            ou_attributes = {
                'objectClass': ['top', 'organizationalUnit'],
                'name': name,
                'ou': name
            }
            
            if description:
                ou_attributes['description'] = description
            
            if managed_by:
                ou_attributes['managedBy'] = managed_by
            
            # Add additional attributes
            if additional_attributes:
                ou_attributes.update(additional_attributes)
            
            self.logger.info(f"Creating OU: {name} ({ou_dn})")
            
            # Create OU
            success = self.ldap.add(ou_dn, ou_attributes)
            
            if success:
                log_ldap_operation("create_ou", ou_dn, True, f"Created OU: {name}")
                
                return self._success_response(
                    f"OU '{name}' created successfully",
                    {
                        "ou_name": name,
                        "dn": ou_dn,
                        "parent_ou": parent_ou
                    }
                )
            else:
                raise Exception("Failed to create OU")
            
        except Exception as e:
            return self._handle_ldap_error(e, "create_ou", ou_dn if 'ou_dn' in locals() else name)
    
    def modify_ou(self, ou_dn: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify OU attributes.
        
        Args:
            ou_dn: OU distinguished name to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Validate DN
            if not self._validate_dn(ou_dn):
                return self._format_response({
                    "success": False,
                    "error": f"Invalid DN format: {ou_dn}",
                    "ou_dn": ou_dn
                }, "modify_ou")
            
            # Check if OU exists
            existing_ou = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=['name'],
                search_scope=ldap3.BASE
            )
            
            if not existing_ou:
                return self._format_response({
                    "success": False,
                    "error": f"OU not found: {ou_dn}",
                    "ou_dn": ou_dn
                }, "modify_ou")
            
            # Prepare modifications
            modifications = {}
            for attr, value in attributes.items():
                if isinstance(value, list):
                    modifications[attr] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[attr] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying OU: {ou_dn}")
            
            # Apply modifications
            success = self.ldap.modify(ou_dn, modifications)
            
            if success:
                log_ldap_operation("modify_ou", ou_dn, True, f"Modified OU: {ou_dn}")
                
                return self._success_response(
                    f"OU '{ou_dn}' modified successfully",
                    {
                        "ou_dn": ou_dn,
                        "modified_attributes": list(attributes.keys())
                    }
                )
            else:
                raise Exception("Failed to modify OU attributes")
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_ou", ou_dn)
    
    def delete_ou(self, ou_dn: str, force: bool = False) -> List[Dict[str, Any]]:
        """
        Delete an Organizational Unit.
        
        Args:
            ou_dn: OU distinguished name to delete
            force: Force deletion even if OU contains objects (default: False)
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Validate DN
            if not self._validate_dn(ou_dn):
                return self._format_response({
                    "success": False,
                    "error": f"Invalid DN format: {ou_dn}",
                    "ou_dn": ou_dn
                }, "delete_ou")
            
            # Check if OU exists
            existing_ou = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=['name'],
                search_scope=ldap3.BASE
            )
            
            if not existing_ou:
                return self._format_response({
                    "success": False,
                    "error": f"OU not found: {ou_dn}",
                    "ou_dn": ou_dn
                }, "delete_ou")
            
            # Check for child objects if not forcing
            if not force:
                child_count = self._count_child_objects(ou_dn)
                if child_count > 0:
                    return self._format_response({
                        "success": False,
                        "error": f"OU contains child objects. Use force=True to delete anyway.",
                        "ou_dn": ou_dn,
                        "child_count": child_count
                    }, "delete_ou")
            
            self.logger.info(f"Deleting OU: {ou_dn} (force: {force})")
            
            # If forcing deletion, delete all child objects first
            if force:
                self._delete_ou_contents(ou_dn)
            
            # Delete OU
            success = self.ldap.delete(ou_dn)
            
            if success:
                log_ldap_operation("delete_ou", ou_dn, True, f"Deleted OU: {ou_dn}")
                
                return self._success_response(
                    f"OU '{ou_dn}' deleted successfully",
                    {
                        "ou_dn": ou_dn,
                        "forced": force
                    }
                )
            else:
                raise Exception("Failed to delete OU")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_ou", ou_dn)
    
    def move_ou(self, ou_dn: str, new_parent_dn: str) -> List[Dict[str, Any]]:
        """
        Move an OU to a new parent.

        Args:
            ou_dn: OU distinguished name to move
            new_parent_dn: New parent OU distinguished name

        Returns:
            List of MCP content objects with result
        """
        return self.move_object(ou_dn, new_parent_dn, only_ou=True)

    def move_object(self, object_dn: str, new_parent_dn: str,
                    only_ou: bool = False) -> List[Dict[str, Any]]:
        """
        Move a user, computer, group or OU under another OU or container.

        The new DN in the answer is read back from the directory after the
        move, not computed: the previous version built it from name[0], which
        on a single-valued string is its FIRST LETTER ("OU=T,..." for "TI").

        Args:
            object_dn: DN of the object to move
            new_parent_dn: DN of the destination OU, container or domain root
            only_ou: refuse anything that is not an OU (the legacy move_ou)

        Returns:
            List of MCP content objects with result
        """
        operacao = "move_ou" if only_ou else "move_object"
        try:
            if not self._validate_dn(object_dn) or not self._validate_dn(new_parent_dn):
                return self._format_response({
                    "success": False,
                    "error": "Invalid DN format",
                    "object_dn": object_dn,
                    "new_parent_dn": new_parent_dn
                }, operacao)

            origem = self.ldap.search(
                search_base=object_dn,
                search_filter="(objectClass=*)",
                attributes=['objectClass', 'name'],
                search_scope=ldap3.BASE
            )
            if not origem:
                return self._format_response({
                    "success": False,
                    "error": f"Object not found: {object_dn}",
                    "object_dn": object_dn
                }, operacao)
            classes = origem[0]['attributes'].get('objectClass') or []
            if isinstance(classes, str):
                classes = [classes]
            tipo = self._detect_object_type([str(c) for c in classes])
            if only_ou and tipo != 'organizational_unit':
                return self._format_response({
                    "success": False,
                    "error": f"OU not found: {object_dn}",
                    "ou_dn": object_dn
                }, operacao)

            destino = self.ldap.search(
                search_base=new_parent_dn,
                search_filter="(|(objectClass=organizationalUnit)(objectClass=container)"
                              "(objectClass=domain))",
                attributes=['name'],
                search_scope=ldap3.BASE
            )
            if not destino:
                return self._format_response({
                    "success": False,
                    "error": f"Parent OU not found: {new_parent_dn}",
                    "new_parent_dn": new_parent_dn
                }, operacao)

            partes = self._split_dn(object_dn)
            origem_n = self._dn_normalizado(object_dn)
            destino_n = self._dn_normalizado(new_parent_dn)
            if destino_n == origem_n or destino_n.endswith("," + origem_n):
                return self._format_response({
                    "success": False,
                    "error": "An object cannot be moved into itself or into one of its "
                             "own sub-OUs",
                    "object_dn": object_dn,
                    "new_parent_dn": new_parent_dn
                }, operacao)
            if self._dn_normalizado(",".join(partes[1:])) == destino_n:
                return self._success_response(
                    "Object is already in the requested OU; nothing was changed",
                    {"old_dn": object_dn, "new_dn": object_dn,
                     "new_parent_dn": new_parent_dn, "object_type": tipo,
                     "verified": True, "changed": False})

            self.logger.info(f"Moving {tipo} {object_dn} to {new_parent_dn}")
            self.ldap.move(object_dn, new_parent_dn)

            novo_dn = f"{partes[0]},{new_parent_dn}"
            relido = self.ldap.search(
                search_base=novo_dn,
                search_filter="(objectClass=*)",
                attributes=['name'],
                search_scope=ldap3.BASE
            )
            verificado = bool(relido)
            if verificado:
                novo_dn = relido[0].get('dn') or novo_dn
            log_ldap_operation(operacao, object_dn, True, f"Moved to: {novo_dn}")
            return self._success_response(
                f"{tipo} moved successfully" if verificado else
                f"{tipo} move was accepted but the new DN could not be read back",
                {
                    "old_dn": object_dn,
                    "new_dn": novo_dn,
                    "new_parent_dn": new_parent_dn,
                    "object_type": tipo,
                    "verified": verificado,
                    "changed": True,
                }
            )

        except Exception as e:
            return self._handle_ldap_error(e, operacao, object_dn)

    @classmethod
    def _dn_normalizado(cls, dn: str) -> str:
        """Compare DNs by component. Removing every space made OU "A B" equal
        to its sibling "AB": a move between them answered "already there"."""
        partes = []
        for rdn in cls._split_dn(dn):
            chave, _, valor = rdn.partition("=")
            partes.append(f"{chave.strip().lower()}={valor.strip().lower()}")
        return ",".join(partes)

    @staticmethod
    def _split_dn(dn: str) -> List[str]:
        """Split a DN on unescaped commas."""
        partes, atual, escapado = [], [], False
        for c in str(dn):
            if escapado:
                atual.append(c)
                escapado = False
            elif c == "\\":
                atual.append(c)
                escapado = True
            elif c == ",":
                partes.append("".join(atual).strip())
                atual = []
            else:
                atual.append(c)
        partes.append("".join(atual).strip())
        return [p for p in partes if p]

    # Above this many children the listing is cut and says so.
    _LIMITE_CONTEUDO = 500

    def get_ou_contents(self, ou_dn: str, object_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get contents of an OU (users, groups, computers, sub-OUs).

        Args:
            ou_dn: OU distinguished name
            object_types: Types of objects to include (optional: user, group, computer, organizationalUnit)

        Returns:
            List of MCP content objects with OU contents
        """
        try:
            if not self._validate_dn(ou_dn):
                return self._format_response({
                    "success": False,
                    "error": f"Invalid DN format: {ou_dn}",
                    "ou_dn": ou_dn
                }, "get_ou_contents")
            conteudo = self._listar_conteudo(ou_dn, object_types)
            log_ldap_operation("get_ou_contents", ou_dn, True,
                               f"Retrieved {len(conteudo)} objects")
            return self._format_response(
                {"ou_dn": ou_dn, **self._resumo_do_conteudo(conteudo, object_types)},
                "get_ou_contents")
        except Exception as e:
            return self._handle_ldap_error(e, "get_ou_contents", ou_dn)

    _FILTRO_POR_TIPO = {
        'user': "(&(objectCategory=person)(objectClass=user))",
        'group': "(objectClass=group)",
        'computer': "(objectClass=computer)",
        'organizationalUnit': "(objectClass=organizationalUnit)",
    }

    def _listar_conteudo(self, ou_dn: str,
                         object_types: Optional[List[str]]) -> List[Dict[str, Any]]:
        """Direct children of an OU, one LEVEL search, sorted by type and name.

        Raises ValueError for an unknown type instead of silently listing
        nothing: an empty answer would read as "this OU is empty".
        """
        tipos = list(object_types) if object_types else list(self._FILTRO_POR_TIPO)
        desconhecidos = [t for t in tipos if t not in self._FILTRO_POR_TIPO]
        if desconhecidos:
            raise ValueError(
                f"object_types desconhecido(s): {desconhecidos}. Valores aceitos: "
                f"{', '.join(self._FILTRO_POR_TIPO)}.")
        filtro = "(|" + "".join(self._FILTRO_POR_TIPO[t] for t in tipos) + ")"
        resultados = self.ldap.search(
            search_base=ou_dn,
            search_filter=filtro,
            attributes=['objectClass', 'sAMAccountName', 'name', 'displayName',
                        'description', 'userAccountControl'],
            search_scope=ldap3.LEVEL
        )
        conteudo = []
        for entry in resultados:
            attrs = entry['attributes']
            classes = [str(c).lower() for c in self._get_attr_list(attrs, 'objectClass')]
            if 'computer' in classes:
                tipo = 'computer'
            elif 'user' in classes:
                tipo = 'user'
            elif 'group' in classes:
                tipo = 'group'
            elif 'organizationalunit' in classes:
                tipo = 'organizationalUnit'
            else:
                tipo = 'unknown'
            item = {
                'type': tipo,
                'name': self._get_attr(attrs, 'name', '') or self._get_attr(attrs, 'sAMAccountName', ''),
                'dn': entry['dn'],
            }
            for chave, atributo in (('login', 'sAMAccountName'), ('displayName', 'displayName'),
                                    ('description', 'description')):
                valor = self._get_attr(attrs, atributo, '')
                if valor and valor != item['name']:
                    item[chave] = valor
            if tipo in ('user', 'computer'):
                uac = self._get_attr(attrs, 'userAccountControl', None)
                if uac is not None:
                    item['enabled'] = not (int(uac) & 0x2)
            conteudo.append(item)
        conteudo.sort(key=lambda x: (x['type'], str(x['name']).lower()))
        return conteudo

    def _resumo_do_conteudo(self, conteudo: List[Dict[str, Any]],
                            object_types: Optional[List[str]]) -> Dict[str, Any]:
        type_counts: Dict[str, int] = {}
        for obj in conteudo:
            type_counts[obj['type']] = type_counts.get(obj['type'], 0) + 1
        resumo = {
            "contents": conteudo[:self._LIMITE_CONTEUDO],
            "total_count": len(conteudo),
            "type_counts": type_counts,
            "object_types": object_types or list(self._FILTRO_POR_TIPO),
        }
        if len(conteudo) > self._LIMITE_CONTEUDO:
            resumo["LISTA_CORTADA"] = (
                f"A OU tem {len(conteudo)} objetos diretos; a lista mostra os primeiros "
                f"{self._LIMITE_CONTEUDO} (por tipo e nome). Filtre com object_types ou "
                "consulte uma sub-OU.")
        return resumo

    def _calculate_ou_level(self, ou_dn: str, base_dn: str) -> int:
        """Calculate the level of an OU relative to base DN."""
        try:
            # Remove base DN from OU DN
            if ou_dn.lower().endswith(base_dn.lower()):
                relative_dn = ou_dn[:-len(base_dn)].rstrip(',')
                # Count OU components
                if not relative_dn:
                    return 0
                return len([part for part in relative_dn.split(',') if part.strip().startswith('OU=')])
            return 0
        except:
            return 0
    
    def _count_child_objects(self, ou_dn: str) -> int:
        """Count all child objects in an OU."""
        try:
            results = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=*)",
                attributes=['objectClass'],
                search_scope=ldap3.LEVEL  # ONELEVEL equivalent
            )
            return len(results)
        except:
            return 0
    
    def _count_sub_ous(self, ou_dn: str) -> int:
        """Count sub-OUs in an OU."""
        try:
            results = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=organizationalUnit)",
                attributes=['objectClass'],
                search_scope=ldap3.LEVEL  # ONELEVEL equivalent
            )
            return len(results)
        except:
            return 0
    
    def _parse_gp_link(self, gp_link: str) -> List[Dict[str, Any]]:
        """Parse GP Link attribute to extract linked GPOs."""
        try:
            gpos = []
            # GP Link format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain;0]
            parts = gp_link.split('[')
            for part in parts[1:]:  # Skip first empty part
                if ';' in part:
                    gpo_path, options = part.split(';', 1)
                    options = options.rstrip(']')
                    
                    # Extract GUID from path
                    gpo_guid = ""
                    if 'cn={' in gpo_path and '}' in gpo_path:
                        start = gpo_path.find('{') + 1
                        end = gpo_path.find('}')
                        gpo_guid = gpo_path[start:end]
                    
                    gpos.append({
                        'path': gpo_path,
                        'guid': gpo_guid,
                        'options': int(options) if options.isdigit() else 0,
                        'enabled': int(options) == 0 if options.isdigit() else True
                    })
            
            return gpos
        except:
            return []
    
    def _delete_ou_contents(self, ou_dn: str) -> None:
        """Recursively delete all contents of an OU."""
        try:
            # Get all child objects
            results = self.ldap.search(
                search_base=ou_dn,
                search_filter="(objectClass=*)",
                attributes=['objectClass'],
                search_scope=ldap3.LEVEL  # ONELEVEL equivalent
            )
            
            # Delete in reverse order (deepest first)
            for entry in reversed(results):
                child_dn = entry['dn']
                object_classes = entry['attributes'].get('objectClass', [])
                
                # If it's an OU, recursively delete its contents first
                if 'organizationalUnit' in object_classes:
                    self._delete_ou_contents(child_dn)
                
                # Delete the object
                try:
                    self.ldap.delete(child_dn)
                except Exception as e:
                    self.logger.warning(f"Failed to delete child object {child_dn}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error deleting OU contents: {e}")
    
    # Alias methods for backward compatibility
    def list_organizational_units(self, parent_ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                                attributes: Optional[List[str]] = None, recursive: bool = True) -> List[Dict[str, Any]]:
        """Alias for list_ous method."""
        return self.list_ous(parent_ou, filter_criteria, attributes, recursive)
    
    def get_organizational_unit(self, ou_dn: str, attributes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Alias for get_ou method."""
        return self.get_ou(ou_dn, attributes)
    
    def create_organizational_unit(self, name: str, parent_ou: Optional[str] = None, 
                                 parent_dn: Optional[str] = None, description: Optional[str] = None, 
                                 manager_dn: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Alias for create_ou method."""
        # Handle both parameter names for backward compatibility
        if parent_dn is not None:
            parent_ou = parent_dn
        if manager_dn is not None:
            kwargs['managed_by'] = manager_dn
        return self.create_ou(name, parent_ou, description, **kwargs)
    
    def modify_organizational_unit(self, ou_dn: str, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for modify_ou method."""
        return self.modify_ou(ou_dn, attributes)
    
    def delete_organizational_unit(self, ou_dn: str, force: bool = False) -> Dict[str, Any]:
        """Alias for delete_ou method."""
        return self.delete_ou(ou_dn, force)
    
    def move_organizational_unit(self, ou_dn: str = None, source_dn: str = None, 
                                new_parent_dn: str = None, destination_parent_dn: str = None, 
                                target_parent_dn: str = None) -> Dict[str, Any]:
        """Alias for move_ou method."""
        # Handle both parameter names for backward compatibility
        if source_dn is not None:
            ou_dn = source_dn
        if destination_parent_dn is not None:
            new_parent_dn = destination_parent_dn
        if target_parent_dn is not None:
            new_parent_dn = target_parent_dn
        return self.move_ou(ou_dn, new_parent_dn)
        
    # Additional methods that tests expect
    def get_ou_children(self, ou_dn: str) -> Dict[str, Any]:
        """Get child objects of an OU."""
        return self.get_ou_contents(ou_dn)
    
    
    
    def get_ou_statistics(self, ou_dn: str) -> Dict[str, Any]:
        """Get statistics for an OU."""
        try:
            # get_ou_contents returns List[Content], parse the JSON response
            contents_response = self.get_ou_contents(ou_dn)
            if not contents_response or len(contents_response) == 0:
                return {'success': False, 'error': 'OU contents not found', 'ou_dn': ou_dn}
                
            import json
            contents = json.loads(contents_response[0].text)
            
            if not contents.get('success', True):
                return {'success': False, 'error': contents.get('error', 'Unknown error'), 'ou_dn': ou_dn}
                
            # get_ou_contents answers with total_count and a type_counts map;
            # reading total_objects/users_count/... found nothing, so every
            # statistic came back as zero regardless of the OU's real content.
            por_tipo = contents.get('type_counts', {})
            stats = {
                'ou_dn': ou_dn,
                'total_objects': contents.get('total_count', 0),
                'users': por_tipo.get('user', 0),
                'groups': por_tipo.get('group', 0),
                'computers': por_tipo.get('computer', 0),
                'sub_ous': por_tipo.get('organizationalUnit', 0),
            }

            # Arguments were swapped here too: _format_response(data, operation).
            return self._format_response(stats, "get_ou_statistics")
            
        except Exception as e:
            return self._handle_ldap_error(e, 'get_ou_statistics', ou_dn)
    
    # Helper methods that tests expect
    def _validate_ou_dn(self, ou_dn: str) -> bool:
        """Validate if DN is a proper OU DN."""
        return ou_dn.upper().startswith('OU=') and 'DC=' in ou_dn.upper()
    
    def _extract_ou_name(self, ou_dn: str) -> str:
        """Extract OU name from DN."""
        if ou_dn.upper().startswith('OU='):
            return ou_dn.split(',')[0][3:]  # Remove 'OU=' prefix
        return ''  # Return empty string for non-OU DNs
    
    def _detect_object_type(self, object_classes: List[str]) -> str:
        """Detect object type from objectClass attributes."""
        classes = [cls.lower() for cls in object_classes]
        if 'computer' in classes:
            return 'computer'
        elif 'user' in classes:
            return 'user'
        elif 'group' in classes:
            return 'group'
        elif 'organizationalunit' in classes:
            return 'organizational_unit'
        else:
            return 'unknown'

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for OU operations."""
        return {
            "operations": [
                "list_ous", "get_ou", "create_ou", "modify_ou", "delete_ou",
                "move_ou", "get_ou_contents", "list_organizational_units"
            ],
            "ou_attributes": [
                "name", "description", "managedBy", "gPLink", "gPOptions",
                "streetAddress", "l", "st", "postalCode", "c"
            ],
            "supported_child_types": ["user", "group", "computer", "organizationalUnit"],
            "required_permissions": [
                "Create OU Objects", "Delete OU Objects", "Modify OU Attributes",
                "Manage OU Contents"
            ],
            "delegation_permissions": ["Full Control", "Read", "Write", "Create All Child Objects"]
        }
