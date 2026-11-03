"""Group management tools for Active Directory."""

from typing import List, Dict, Any, Optional

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.resolver import normalizar_dn
from ..core.logging import log_ldap_operation


class GroupTools(BaseTool):
    """Tools for managing Active Directory groups."""
    
    def list_groups(self, ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                   attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List groups in Active Directory.
        
        Args:
            ou: Organizational Unit to search in (optional)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with group information
        """
        recusa = self._recusa_de_consulta("list_groups", filter_criteria, attributes)
        if recusa is not None:
            return recusa
        try:
            # Determine search base
            if ou:
                search_base = ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter
            base_filter = "(objectClass=group)"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'description', 'mail',
                    'groupType', 'member', 'memberOf',
                    'whenCreated', 'whenChanged', 'managedBy'
                ]
            
            self.logger.info(f"Listing groups from {search_base}")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )
            
            # Process results
            groups = []
            for entry in results:
                group_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                    'displayName': self._get_attr(entry['attributes'], 'displayName', ''),
                    'description': self._get_attr(entry['attributes'], 'description', ''),
                    'groupType': self._get_attr(entry['attributes'], 'groupType', 0),
                    'memberCount': len(self._get_attr_list(entry['attributes'], 'member'))
                }
                
                # Add group scope information
                group_type = self._get_attr(entry['attributes'], 'groupType', 0)
                group_info['scope'] = self._get_group_scope(group_type)
                group_info['type'] = self._get_group_type(group_type)
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'displayName', 'description', 'groupType'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if value is not None and isinstance(value, list) and len(value) == 1:
                            group_info[attr] = value[0]
                        else:
                            group_info[attr] = value
                
                groups.append(group_info)
            
            log_ldap_operation("list_groups", search_base, True, f"Found {len(groups)} groups")
            
            response_data = {
                "groups": groups,
                "count": len(groups),
                "search_base": search_base,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "list_groups", search_base)
    
    _LIMITE_MEMBROS = 1000

    def get_group(self, group_name: str, attributes: Optional[List[str]] = None,
                  recursive: bool = False) -> List[Dict[str, Any]]:
        """
        A group with its members, by name, login and type, in one answer.

        Members come from one (memberOf=<group>) search instead of the raw
        'member' DN list; with recursive=True nested groups are expanded (one
        search per nested group, not per member). This replaces calling
        details and then a separate member listing.

        Args:
            group_name: Group name (sAMAccountName) to search for
            attributes: Specific attributes to retrieve (optional)
            recursive: also list members of nested groups

        Returns:
            List of MCP content objects with group information
        """
        recusa = self._recusa_de_consulta("get_group", None, attributes)
        if recusa is not None:
            return recusa
        try:
            escaped_group_name = self._escape_ldap_filter(group_name)
            search_filter = f"(&(objectClass=group)(sAMAccountName={escaped_group_name}))"
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'description', 'mail',
                    'groupType', 'memberOf', 'whenCreated', 'whenChanged', 'managedBy', 'info'
                ]
            lidos = list(attributes) + [a for a in ('groupType', 'objectSid', 'memberOf')
                                        if a not in attributes]

            self.logger.info(f"Getting group information for: {group_name}")
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=lidos
            )
            if not results:
                log_ldap_operation("get_group", group_name, False, "Group not found")
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "get_group")

            group_entry = results[0]
            todos = group_entry['attributes']
            pedidos = {a.lower() for a in attributes}
            visiveis = {k: v for k, v in todos.items()
                        if k.lower() in pedidos and k.lower() not in ('member', 'memberof')
                        and v not in (None, "", [])}
            membros = self._membros(group_entry['dn'], recursive)
            group_type = int(self._get_attr(todos, 'groupType', 0) or 0)
            group_info: Dict[str, Any] = {
                'dn': group_entry['dn'],
                'attributes': visiveis,
                'computed': {
                    'scope': self._get_group_scope(group_type),
                    'type': self._get_group_type(group_type),
                    'member_count': len(membros),
                    'parent_groups_count': len(self._get_attr_list(todos, 'memberOf')),
                    'ou': self._caminho_da_ou(group_entry['dn']),
                },
                'members': membros[:self._LIMITE_MEMBROS],
                'recursive': recursive,
                'member_of': [self._nome_do_dn(g) for g in self._get_attr_list(todos, 'memberOf')],
            }
            if len(membros) > self._LIMITE_MEMBROS:
                group_info['LISTA_CORTADA'] = (
                    f"O grupo tem {len(membros)} membros; a lista mostra os primeiros "
                    f"{self._LIMITE_MEMBROS}.")
            primarios = self._membros_pelo_grupo_primario(todos)
            if primarios:
                group_info['computed']['members_by_primary_group'] = primarios
                group_info['computed']['nota_grupo_primario'] = (
                    "Estas contas pertencem ao grupo por primaryGroupID (grupo primario) e "
                    "nao aparecem na lista de membros; o AD nao as grava em 'member'.")

            log_ldap_operation("get_group", group_name, True, f"Retrieved group: {group_entry['dn']}")
            return self._format_response(group_info, "get_group")

        except Exception as e:
            return self._handle_ldap_error(e, "get_group", group_name)

    def _membros(self, group_dn: str, recursive: bool) -> List[Dict[str, Any]]:
        """Direct (and, if asked, nested) members, one search per group."""
        vistos_grupos = {group_dn.lower()}
        vistos_membros = set()
        fila = [(group_dn, 0, None)]
        membros: List[Dict[str, Any]] = []
        while fila:
            atual, nivel, via = fila.pop(0)
            resultados = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(memberOf={self._escape_ldap_filter(atual)})",
                attributes=['objectClass', 'sAMAccountName', 'name', 'displayName',
                            'userAccountControl'])
            for entrada in resultados:
                attrs = entrada['attributes']
                classes = [str(c).lower() for c in self._get_attr_list(attrs, 'objectClass')]
                tipo = ('computer' if 'computer' in classes else 'user' if 'user' in classes
                        else 'group' if 'group' in classes else 'contact' if 'contact' in classes
                        else 'other')
                chave = entrada['dn'].lower()
                if chave not in vistos_membros:
                    vistos_membros.add(chave)
                    item: Dict[str, Any] = {
                        'type': tipo,
                        'name': self._get_attr(attrs, 'name', '') or self._nome_do_dn(entrada['dn']),
                    }
                    login = self._get_attr(attrs, 'sAMAccountName', '')
                    if login and login != item['name']:
                        item['login'] = login
                    if tipo in ('user', 'computer'):
                        uac = self._get_attr(attrs, 'userAccountControl', None)
                        if uac is not None:
                            item['enabled'] = not (int(uac) & 0x2)
                    if recursive:
                        item['level'] = nivel
                        if via:
                            item['via'] = via
                    item['dn'] = entrada['dn']
                    membros.append(item)
                if recursive and tipo == 'group' and chave not in vistos_grupos:
                    vistos_grupos.add(chave)
                    fila.append((entrada['dn'], nivel + 1, self._nome_do_dn(entrada['dn'])))
        membros.sort(key=lambda m: (m.get('level', 0), m['type'], str(m['name']).lower()))
        return membros

    def _e_grupo_primario_de(self, grupo_attrs: Dict[str, Any], membro_dn: str) -> bool:
        sid = self._get_attr(grupo_attrs, 'objectSid', None)
        if not isinstance(sid, str) or not sid.rsplit("-", 1)[-1].isdigit():
            return False
        try:
            achado = self.ldap.search(search_base=membro_dn, search_filter="(objectClass=*)",
                                      attributes=['primaryGroupID'], search_scope=ldap3.BASE)
        except Exception:  # noqa: BLE001 - unknown is treated as "not primary"
            return False
        if not achado:
            return False
        rid = self._get_attr(achado[0]['attributes'], 'primaryGroupID', None)
        return rid is not None and str(int(rid)) == sid.rsplit("-", 1)[-1]

    def _membros_pelo_grupo_primario(self, attrs: Dict[str, Any]) -> int:
        """How many accounts use this group as their primary group (e.g. Domain Users)."""
        sid = self._get_attr(attrs, 'objectSid', None)
        if not isinstance(sid, str) or not sid.startswith("S-"):
            return 0
        rid = sid.rsplit("-", 1)[-1]
        if not rid.isdigit():
            return 0
        try:
            return len(self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(primaryGroupID={int(rid)})",
                attributes=['sAMAccountName']))
        except Exception:  # noqa: BLE001 - a count we could not read is left out
            return 0

    def create_group(self, group_name: str, display_name: Optional[str] = None,
                    description: Optional[str] = None, ou: Optional[str] = None,
                    group_scope: str = "Global", group_type: str = "Security",
                    additional_attributes: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Create a new group in Active Directory.
        
        Args:
            group_name: Group name (sAMAccountName)
            display_name: Display name for the group (optional)
            description: Group description (optional)
            ou: Organizational Unit to create group in (optional)
            group_scope: Group scope (Global, DomainLocal, Universal)
            group_type: Group type (Security, Distribution)
            additional_attributes: Additional attributes to set (optional)
            
        Returns:
            List of MCP content objects with creation result
        """
        try:
            # Determine OU
            if ou is None:
                ou = self._default_ou("groups")
            
            # Use display_name if provided, otherwise use group_name
            if display_name is None:
                display_name = group_name
            
            # Build DN
            group_dn = f"CN={display_name},{ou}"
            
            # Check if group already exists
            existing_group = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(sAMAccountName={self._escape_ldap_filter(group_name)})",
                attributes=['sAMAccountName']
            )
            
            if existing_group:
                log_ldap_operation("create_group", group_dn, False, "Group already exists")
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' already exists",
                    "group_name": group_name
                }, "create_group")
            
            # Calculate groupType value
            group_type_value = self._calculate_group_type(group_scope, group_type)
            
            # Prepare group attributes
            group_attributes = {
                'objectClass': ['top', 'group'],
                'sAMAccountName': group_name,
                'cn': display_name,
                'displayName': display_name,
                'groupType': group_type_value
            }
            
            if description:
                group_attributes['description'] = description
            
            # Add additional attributes
            if additional_attributes:
                group_attributes.update(additional_attributes)
            
            self.logger.info(f"Creating group: {group_name} ({group_dn})")
            
            # Create group
            success = self.ldap.add(group_dn, group_attributes)
            
            if success:
                log_ldap_operation("create_group", group_dn, True, f"Created group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' created successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn,
                        "display_name": display_name,
                        "scope": group_scope,
                        "type": group_type
                    }
                )
            else:
                raise Exception("Failed to create group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "create_group", group_dn if 'group_dn' in locals() else group_name)
    
    def modify_group(self, group_name: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify group attributes.
        
        Args:
            group_name: Group name to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['objectClass']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "modify_group")
            
            group_dn = group_results[0]['dn']

            recusa = self._recusa_atributo_reservado("modify_group", attributes)
            if recusa is not None:
                return recusa

            # Prepare modifications
            modifications = {}
            for attr, value in attributes.items():
                if isinstance(value, list):
                    modifications[attr] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[attr] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying group: {group_name} ({group_dn})")
            
            # Apply modifications
            success = self.ldap.modify(group_dn, modifications)
            
            if success:
                log_ldap_operation("modify_group", group_dn, True, f"Modified group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' modified successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn,
                        "modified_attributes": list(attributes.keys())
                    }
                )
            else:
                raise Exception("Failed to modify group attributes")
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_group", group_name)
    
    def delete_group(self, group_name: str) -> List[Dict[str, Any]]:
        """
        Delete a group from Active Directory.
        
        Args:
            group_name: Group name to delete
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['objectClass']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "delete_group")
            
            group_dn = group_results[0]['dn']
            
            self.logger.info(f"Deleting group: {group_name} ({group_dn})")
            
            # Delete group
            success = self.ldap.delete(group_dn)
            
            if success:
                log_ldap_operation("delete_group", group_dn, True, f"Deleted group: {group_name}")
                
                return self._success_response(
                    f"Group '{group_name}' deleted successfully",
                    {
                        "group_name": group_name,
                        "dn": group_dn
                    }
                )
            else:
                raise Exception("Failed to delete group")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_group", group_name)
    
    def add_member(self, group_name, member_dn) -> List[Dict[str, Any]]:
        """
        Add one or more members to one or more groups.

        Args:
            group_name: group login, or a list of them
            member_dn: member DN, or a list of them

        Returns:
            List of MCP content objects with result
        """
        return self.alterar_membros(group_name, member_dn, adicionar=True)

    def remove_member(self, group_name, member_dn) -> List[Dict[str, Any]]:
        """
        Remove one or more members from one or more groups.

        Args:
            group_name: group login, or a list of them
            member_dn: member DN, or a list of them

        Returns:
            List of MCP content objects with result
        """
        return self.alterar_membros(group_name, member_dn, adicionar=False)

    @staticmethod
    def _como_lista(valor) -> List[str]:
        if valor is None:
            return []
        if isinstance(valor, (list, tuple)):
            return [str(v) for v in valor if v not in (None, "")]
        return [str(valor)]

    def alterar_membros(self, grupos, membros, adicionar: bool) -> List[Dict[str, Any]]:
        """Every group x every member, idempotent, read back per group.

        Already a member (on add) or not a member (on remove) is reported as
        such, not as an error: repeating a request must not look like a
        failure. Each group is re-read after its changes, so 'verified' says
        what the directory holds, not what was sent.
        """
        operacao = "add_member" if adicionar else "remove_member"
        # The same object named twice (login and full name) resolves to the
        # same DN; sending it twice made AD answer "already exists" and the
        # call report a failure over a membership that was correct.
        lista_grupos = list(dict.fromkeys(self._como_lista(grupos)))
        lista_membros = list({normalizar_dn(m): m for m in self._como_lista(membros)}.values())
        try:
            # Every group is read (and judged) before anything is written: one
            # privileged group refuses the whole call, as one unresolved item
            # does, so a batch never ends half applied (upstream 48a965d).
            achados: Dict[str, Any] = {}
            privilegiados: List[Dict[str, Any]] = []
            for grupo in lista_grupos:
                achado = self.ldap.search(
                    search_base=self.ldap.ad_config.base_dn,
                    search_filter=f"(&(objectClass=group)"
                                  f"(sAMAccountName={self._escape_ldap_filter(grupo)}))",
                    attributes=['member', 'objectSid', 'adminCount', 'sAMAccountName', 'cn'])
                achados[grupo] = achado
                if achado and self._protecao_de_privilegiados_ativa():
                    motivo = self._motivo_privilegiado(achado[0]['attributes'], grupo)
                    if motivo:
                        privilegiados.append({"nome": self._nome_do_dn(achado[0]['dn']),
                                              "dn": achado[0]['dn'], "motivo": motivo})
            if privilegiados:
                return self._recusa_alvo_privilegiado(operacao, privilegiados)

            resultados: List[Dict[str, Any]] = []
            for grupo in lista_grupos:
                achado = achados[grupo]
                if not achado:
                    for membro in lista_membros:
                        resultados.append({"grupo": grupo, "membro": self._nome_do_dn(membro),
                                           "status": "grupo_nao_encontrado"})
                    continue
                group_dn = achado[0]['dn']
                atuais = {normalizar_dn(m) for m in
                          self._get_attr_list(achado[0]['attributes'], 'member')}
                alterados = []
                for membro in lista_membros:
                    item = {"grupo": self._nome_do_dn(group_dn), "membro": self._nome_do_dn(membro),
                            "member_dn": membro, "group_dn": group_dn}
                    presente = normalizar_dn(membro) in atuais
                    if adicionar and presente:
                        item["status"] = "ja_era_membro"
                    elif not adicionar and not presente:
                        if self._e_grupo_primario_de(achado[0]['attributes'], membro):
                            # memberOf never lists the primary group, so this
                            # used to read as "was not a member" -- while the
                            # account stayed in it.
                            item["status"] = "grupo_primario"
                            item["erro"] = ("Este e o grupo primario da conta (primaryGroupID); "
                                            "o AD nao deixa retira-la dele. Troque o grupo "
                                            "primario antes, se for mesmo o caso.")
                        else:
                            item["status"] = "nao_era_membro"
                    else:
                        try:
                            self.ldap.modify(group_dn, {
                                'member': [((MODIFY_ADD if adicionar else MODIFY_DELETE), [membro])]
                            })
                            item["status"] = "adicionado" if adicionar else "removido"
                            alterados.append(item)
                        except Exception as exc:  # noqa: BLE001 - reported per pair
                            item["status"] = "falhou"
                            item["erro"] = str(exc)[:200]
                    resultados.append(item)
                if alterados:
                    relido = self.ldap.search(search_base=group_dn,
                                              search_filter="(objectClass=group)",
                                              attributes=['member'], search_scope=ldap3.BASE)
                    agora = {normalizar_dn(m) for m in
                             self._get_attr_list(relido[0]['attributes'], 'member')} if relido else set()
                    for item in alterados:
                        presente = normalizar_dn(item["member_dn"]) in agora
                        item["verified"] = bool(relido) and (presente == adicionar)
                    log_ldap_operation(operacao, group_dn, True,
                                       f"{len(alterados)} member(s) {'added' if adicionar else 'removed'}")

            contagem: Dict[str, int] = {}
            for item in resultados:
                contagem[item["status"]] = contagem.get(item["status"], 0) + 1
            falhas = [r for r in resultados
                      if r["status"] in ("falhou", "grupo_nao_encontrado", "grupo_primario")
                      or r.get("verified") is False]
            resposta: Dict[str, Any] = {
                "success": not falhas,
                "message": (("Membro(s) incluido(s)" if adicionar else "Membro(s) removido(s)")
                            + ": " + ", ".join(f"{k}: {v}" for k, v in sorted(contagem.items()))),
                "resumo": contagem,
                "resultados": resultados,
            }
            if len(resultados) == 1:
                unico = resultados[0]
                resposta.update({"group_name": unico["grupo"],
                                 "group_dn": unico.get("group_dn"),
                                 "member_dn": unico.get("member_dn")})
            if falhas:
                resposta["error"] = f"{len(falhas)} alteracao(oes) nao aplicada(s); veja 'resultados'"
            return self._format_response(resposta, operacao)

        except Exception as e:
            return self._handle_ldap_error(e, operacao, f"{lista_grupos} -> {lista_membros}")

    def get_members(self, group_name: str, recursive: bool = False) -> List[Dict[str, Any]]:
        """
        Get members of a group.
        
        Args:
            group_name: Group name to get members for
            recursive: Include members of nested groups
            
        Returns:
            List of MCP content objects with member information
        """
        try:
            # Find group DN
            group_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=group)(sAMAccountName={self._escape_ldap_filter(group_name)}))",
                attributes=['member']
            )
            
            if not group_results:
                return self._format_response({
                    "success": False,
                    "error": f"Group '{group_name}' not found",
                    "group_name": group_name
                }, "get_members")
            
            group_dn = group_results[0]['dn']
            member_dns = self._get_attr_list(group_results[0]['attributes'], 'member')

            members = []
            processed_groups = set()  # To avoid infinite recursion
            
            def process_members(dns_to_process, level=0):
                for member_dn in dns_to_process:
                    try:
                        # Get member details
                        member_info = self.ldap.search(
                            search_base=member_dn,
                            search_filter="(|(objectClass=user)(objectClass=group))",
                            attributes=['objectClass', 'sAMAccountName', 'displayName', 'member'],
                            search_scope=ldap3.BASE
                        )
                        
                        if member_info:
                            member_data = member_info[0]['attributes']
                            object_classes = member_data.get('objectClass', [])
                            
                            member_entry = {
                                'dn': member_dn,
                                'sAMAccountName': self._get_attr(member_data, 'sAMAccountName', ''),
                                'displayName': self._get_attr(member_data, 'displayName', ''),
                                'type': 'group' if 'group' in object_classes else 'user',
                                'level': level
                            }
                            
                            members.append(member_entry)
                            
                            # If recursive and this is a group, process its members
                            if recursive and 'group' in object_classes and member_dn not in processed_groups:
                                processed_groups.add(member_dn)
                                nested_members = self._get_attr_list(member_data, 'member')
                                if nested_members:
                                    process_members(nested_members, level + 1)
                        
                    except Exception as e:
                        # Add error entry for members that can't be processed
                        members.append({
                            'dn': member_dn,
                            'error': f"Could not retrieve member details: {str(e)}",
                            'level': level
                        })
            
            # Process all members
            process_members(member_dns)
            
            log_ldap_operation("get_members", group_dn, True, f"Retrieved {len(members)} members")
            
            return self._format_response({
                "group_name": group_name,
                "group_dn": group_dn,
                "members": members,
                "member_count": len(members),
                "recursive": recursive
            }, "get_members")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_members", group_name)
    
    def _get_group_scope(self, group_type: int) -> str:
        """Get group scope from groupType value."""
        if group_type & 0x00000002:  # ADS_GROUP_TYPE_GLOBAL_GROUP  
            return "Global"
        elif group_type & 0x00000004:  # ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
            return "DomainLocal"
        elif group_type & 0x00000008:  # ADS_GROUP_TYPE_UNIVERSAL_GROUP
            return "Universal"
        else:
            return "Unknown"
    
    def _get_group_type(self, group_type: int) -> str:
        """Get group type from groupType value."""
        if group_type & 0x80000000:  # ADS_GROUP_TYPE_SECURITY_ENABLED
            return "Security"
        else:
            return "Distribution"
    
    def _calculate_group_type(self, scope: str, group_type: str) -> int:
        """Calculate groupType value from scope and type."""
        base_value = 0
        
        # Set scope
        if scope.lower() == "domainlocal":
            base_value |= 0x00000004  # ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP
        elif scope.lower() == "global":
            base_value |= 0x00000002  # ADS_GROUP_TYPE_GLOBAL_GROUP
        elif scope.lower() == "universal":
            base_value |= 0x00000008  # ADS_GROUP_TYPE_UNIVERSAL_GROUP
        else:
            base_value |= 0x00000002  # Default to Global
        
        # Set type
        if group_type.lower() == "security":
            base_value |= 0x80000000  # ADS_GROUP_TYPE_SECURITY_ENABLED
        
        return base_value
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for group operations."""
        return {
            "operations": [
                "list_groups", "get_group", "create_group", "modify_group",
                "delete_group", "add_member", "remove_member", "get_members"
            ],
            "group_attributes": [
                "sAMAccountName", "displayName", "description", "mail",
                "groupType", "member", "memberOf", "managedBy"
            ],
            "group_scopes": ["Global", "DomainLocal", "Universal"],
            "group_types": ["Security", "Distribution"],
            "required_permissions": [
                "Create Group Objects", "Delete Group Objects",
                "Modify Group Membership", "Modify Group Attributes"
            ]
        }
