"""User management tools for Active Directory."""

import hashlib
import secrets
import string
import unicodedata
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import ldap3
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from .base import BaseTool
from ..core.resolver import dividir_dn, normalizar_dn
from . import sd_acl
from ..core.logging import log_ldap_operation
from ..core.redaction import register_secret

# userAccountControl bit flags used by password/account operations
_UAC_ACCOUNTDISABLE = 0x0002       # 2
_UAC_DONT_EXPIRE_PASSWORD = 0x10000  # 65536


class UserTools(BaseTool):
    """Tools for managing Active Directory users."""
    
    def list_users(self, ou: Optional[str] = None, filter_criteria: Optional[str] = None, 
                   attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        List users in Active Directory.
        
        Args:
            ou: Organizational Unit to search in (optional)
            filter_criteria: Additional LDAP filter criteria (optional)
            attributes: Specific attributes to retrieve (optional)
            
        Returns:
            List of MCP content objects with user information
        """
        recusa = self._recusa_de_consulta("list_users", filter_criteria, attributes)
        if recusa is not None:
            return recusa
        try:
            # Determine search base
            if ou:
                search_base = ou
            else:
                search_base = self.ldap.ad_config.base_dn
            
            # Build search filter. Every computer is objectClass=user too, so
            # the old (objectClass=user) listed machine accounts as people.
            base_filter = "(&(objectCategory=person)(objectClass=user))"
            if filter_criteria:
                search_filter = f"(&{base_filter}{filter_criteria})"
            else:
                search_filter = base_filter
            
            # Determine attributes to retrieve
            if attributes is None:
                attributes = [
                    'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
                    'givenName', 'sn', 'telephoneNumber', 'department', 'title',
                    'whenCreated', 'whenChanged', 'userAccountControl', 'lastLogon',
                    'pwdLastSet', 'accountExpires'
                ]
            
            self.logger.info(f"Listing users from {search_base}")
            
            # Perform search
            results = self.ldap.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes
            )
            
            # Process results
            users = []
            for entry in results:
                user_info = {
                    'dn': entry['dn'],
                    'sAMAccountName': self._get_attr(entry['attributes'], 'sAMAccountName', ''),
                    'displayName': self._get_attr(entry['attributes'], 'displayName', ''),
                    'mail': self._get_attr(entry['attributes'], 'mail', ''),
                    'enabled': self._is_user_enabled(self._get_attr(entry['attributes'], 'userAccountControl', 0))
                }
                
                # Add additional attributes if present
                for attr in attributes:
                    if attr not in ['sAMAccountName', 'displayName', 'mail'] and attr in entry['attributes']:
                        value = entry['attributes'][attr]
                        if isinstance(value, list) and len(value) == 1:
                            user_info[attr] = value[0]
                        else:
                            user_info[attr] = value
                
                users.append(user_info)
            
            log_ldap_operation("list_users", search_base, True, f"Found {len(users)} users")
            
            response_data = {
                "users": users,
                "count": len(users),
                "search_base": search_base,
                "filter": search_filter
            }
            
            return self._format_response(response_data, "list_users")
            
        except Exception as e:
            return self._handle_ldap_error(e, "list_users", search_base)
    
    # Always read, whatever the caller asked for: the summary is built from them.
    _ATRIBUTOS_DO_RESUMO = ['sAMAccountName', 'cn', 'displayName', 'mail', 'userPrincipalName',
                            'userAccountControl', 'memberOf', 'primaryGroupID', 'objectSid',
                            'manager', 'pwdLastSet', 'accountExpires', 'lockoutTime',
                            'lastLogonTimestamp', 'title', 'department', 'company']

    _ATRIBUTOS_PADRAO = [
        'sAMAccountName', 'displayName', 'mail', 'userPrincipalName',
        'givenName', 'sn', 'telephoneNumber', 'mobile', 'department', 'title',
        'manager', 'directReports', 'whenCreated', 'whenChanged',
        'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet', 'accountExpires',
        'description', 'physicalDeliveryOfficeName', 'company'
    ]

    def get_user(self, username: str, attributes: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Everything about one account in a single answer.

        The 'resumo' block carries what an operator asks next -- groups (with
        the primary group memberOf never lists), the OU path, the manager's
        name and the account flags -- so a copy-the-groups or offboarding task
        does not need a second tool. Measured 2026-09-19: details, group list,
        OU details and OU contents were called separately, and a "0 groups"
        answer that hid Domain Users sent the model on a six-tool detour.

        Args:
            username: Username (sAMAccountName) to search for
            attributes: Extra LDAP attributes to show (optional)

        Returns:
            List of MCP content objects with user information
        """
        recusa = self._recusa_de_consulta("get_user", None, attributes)
        if recusa is not None:
            return recusa
        try:
            escaped_username = self._escape_ldap_filter(username)
            search_filter = (f"(&(objectCategory=person)(objectClass=user)"
                             f"(sAMAccountName={escaped_username}))")
            pedidos = list(attributes) if attributes else list(self._ATRIBUTOS_PADRAO)
            lidos = pedidos + [a for a in self._ATRIBUTOS_DO_RESUMO
                               if a.lower() not in {p.lower() for p in pedidos}]

            self.logger.info(f"Getting user information for: {username}")
            results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=search_filter,
                attributes=lidos
            )

            if not results:
                log_ldap_operation("get_user", username, False, "User not found")
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user")

            user_entry = results[0]
            todos = user_entry['attributes']
            pedidos_n = {p.lower() for p in pedidos}
            # Null and empty attributes carried no information and cost tokens.
            visiveis = {k: v for k, v in todos.items()
                        if k.lower() in pedidos_n and v not in (None, "", [])}

            uac = int(self._get_attr(todos, 'userAccountControl', 0) or 0)
            grupos = self._descrever_grupos(self._get_attr_list(todos, 'memberOf'))
            resumo: Dict[str, Any] = {
                "login": self._get_attr(todos, 'sAMAccountName', ''),
                "nome": self._get_attr(todos, 'cn', '') or self._nome_do_dn(user_entry['dn']),
                "ativa": self._is_user_enabled(uac),
                "bloqueada": self._is_user_locked(uac, todos),
                "deve_trocar_senha_no_proximo_logon": self._is_password_expired(todos),
                "senha_nunca_expira": bool(uac & _UAC_DONT_EXPIRE_PASSWORD),
                "conta_expirada": self._is_account_expired(todos),
                "ou": self._pai_do_dn(user_entry['dn']),
                "ou_caminho": self._caminho_da_ou(user_entry['dn']),
                "grupos": grupos,
                "total_grupos": len(grupos),
            }
            primario = self._grupo_primario(todos)
            if primario:
                resumo["grupo_primario"] = primario
            if not grupos:
                resumo["nota_grupos"] = (
                    "A conta nao e membro direto de nenhum grupo alem do grupo primario. "
                    "Nao ha grupos a copiar.")
            gestor = self._get_attr(todos, 'manager', None)
            if gestor:
                resumo["gestor"] = self._nome_do_dn(gestor)

            user_info = {
                'dn': user_entry['dn'],
                'resumo': resumo,
                'attributes': visiveis,
                # Kept for callers that read the older shape.
                'computed': {
                    'enabled': resumo["ativa"],
                    'locked': resumo["bloqueada"],
                    'password_expired': resumo["deve_trocar_senha_no_proximo_logon"],
                    'account_expired': resumo["conta_expirada"],
                },
            }

            log_ldap_operation("get_user", username, True, f"Retrieved user: {user_entry['dn']}")
            return self._format_response(user_info, "get_user")

        except Exception as e:
            return self._handle_ldap_error(e, "get_user", username)

    # Names an operator (or a PowerShell New-ADUser line) uses for the same
    # LDAP attribute. Keys are compared without case, spaces, '-' or '_'.
    _ALIASES_DE_ATRIBUTO = {
        "office": "physicalDeliveryOfficeName", "escritorio": "physicalDeliveryOfficeName",
        "physicaldeliveryofficename": "physicalDeliveryOfficeName",
        "officephone": "telephoneNumber", "phone": "telephoneNumber",
        "telephone": "telephoneNumber", "telefone": "telephoneNumber",
        "telephonenumber": "telephoneNumber",
        "mobilephone": "mobile", "mobile": "mobile", "celular": "mobile",
        "emailaddress": "mail", "email": "mail", "mail": "mail",
        "homepage": "wWWHomePage", "site": "wWWHomePage", "wwwhomepage": "wWWHomePage",
        "city": "l", "cidade": "l", "l": "l",
        "state": "st", "estado": "st", "uf": "st", "st": "st",
        "streetaddress": "streetAddress", "endereco": "streetAddress", "street": "streetAddress",
        "postalcode": "postalCode", "cep": "postalCode", "zip": "postalCode",
        "company": "company", "empresa": "company",
        "department": "department", "departamento": "department", "setor": "department",
        "title": "title", "cargo": "title", "jobtitle": "title",
        "description": "description", "descricao": "description",
        "displayname": "displayName", "nomedeexibicao": "displayName",
        "givenname": "givenName", "surname": "sn", "sn": "sn", "sobrenome": "sn",
        "userprincipalname": "userPrincipalName", "upn": "userPrincipalName",
        "ipphone": "ipPhone", "pager": "pager", "fax": "facsimileTelephoneNumber",
        "manager": "manager", "gestor": "manager", "employeeid": "employeeID",
        "employeenumber": "employeeNumber", "initials": "initials", "iniciais": "initials",
        "homephone": "homePhone", "pobox": "postOfficeBox",
    }
    # Keys that are not LDAP attributes but options of the creation itself.
    _OPCOES_DE_CRIACAO = {
        "changepasswordatlogon": "must_change_password",
        "mustchangepassword": "must_change_password",
        "trocarsenhanoproximologon": "must_change_password",
        "enabled": "enabled", "ativo": "enabled",
        "name": "cn", "cn": "cn", "nomecompleto": "cn", "fullname": "cn",
    }
    _IGNORADOS_NA_CRIACAO = {
        "accountpassword": "a senha vai no parametro password",
        "password": "a senha vai no parametro password",
        "samaccountname": "o login vai no parametro username",
        "objectclass": "definido pelo servidor",
        "useraccountcontrol": "definido pelo servidor (use enabled)",
        "pwdlastset": "use must_change_password",
        "memberof": "use copy_from_user ou ad_add_member_to_group",
    }
    _PAISES = {"brasil": "BR", "brazil": "BR", "portugal": "PT", "estadosunidos": "US",
               "unitedstates": "US", "usa": "US", "argentina": "AR", "paraguai": "PY"}

    @staticmethod
    def _chave_simples(chave: str) -> str:
        texto = unicodedata.normalize("NFKD", str(chave).casefold())
        texto = "".join(c for c in texto if not unicodedata.combining(c))
        return "".join(c for c in texto if c.isalnum())

    def _normalizar_atributos_de_criacao(self, extras: Optional[Dict[str, Any]]):
        """Map operator names to LDAP names and drop empty values.

        Returns (atributos, opcoes, avisos). An empty value is not "set it to
        nothing" on creation -- AD rejects the whole add with
        invalidAttributeSyntax (measured 2026-09-19: an empty mobile made the
        first create fail).
        """
        atributos: Dict[str, Any] = {}
        opcoes: Dict[str, Any] = {}
        avisos: Dict[str, List[str]] = {"ignorados_vazios": [], "renomeados": [],
                                        "ignorados": []}
        pendentes = list((extras or {}).items())
        while pendentes:
            chave, valor = pendentes.pop(0)
            simples = self._chave_simples(chave)
            if simples == "otherattributes" and isinstance(valor, dict):
                pendentes.extend(valor.items())
                continue
            if isinstance(valor, str):
                valor = valor.strip()
            if isinstance(valor, list):
                valor = [v.strip() if isinstance(v, str) else v for v in valor]
                valor = [v for v in valor if v not in (None, "")]
            if valor in (None, "", []):
                avisos["ignorados_vazios"].append(str(chave))
                continue
            if simples in self._OPCOES_DE_CRIACAO:
                opcoes[self._OPCOES_DE_CRIACAO[simples]] = valor
                continue
            if simples in self._IGNORADOS_NA_CRIACAO:
                avisos["ignorados"].append(f"{chave}: {self._IGNORADOS_NA_CRIACAO[simples]}")
                continue
            if simples in ("country", "pais", "c", "co"):
                texto = str(valor).strip()
                codigo = self._PAISES.get(self._chave_simples(texto),
                                          texto.upper() if len(texto) == 2 else None)
                if codigo:
                    atributos["c"] = codigo
                else:
                    atributos["co"] = texto
                if str(chave) not in ("c", "co"):
                    avisos["renomeados"].append(f"{chave} -> {'c' if codigo else 'co'}")
                continue
            nome_ldap = self._ALIASES_DE_ATRIBUTO.get(simples, str(chave))
            if nome_ldap != chave:
                avisos["renomeados"].append(f"{chave} -> {nome_ldap}")
            atributos[nome_ldap] = valor
        return atributos, opcoes, {k: v for k, v in avisos.items() if v}

    @staticmethod
    def _eh_erro_de_atributo(erro: Exception) -> bool:
        texto = str(erro).lower()
        return any(t in texto for t in (
            "invalidattributesyntax", "undefinedattributetype", "invalid attribute type",
            "attribute conversion", "constraintviolation", "objectclassviolation",
            "invalid attribute value"))

    @staticmethod
    def _como_booleano(valor: Any, padrao: bool) -> bool:
        if isinstance(valor, bool):
            return valor
        if valor is None:
            return padrao
        return str(valor).strip().lower().lstrip("$") in ("true", "1", "sim", "yes", "s")

    def create_user(self, username: str, password: str, first_name: str, last_name: str,
                   email: Optional[str] = None, ou: Optional[str] = None,
                   additional_attributes: Optional[Dict[str, Any]] = None,
                   must_change_password: Optional[bool] = None,
                   copy_from_user: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Create a user -- the whole onboarding in one call.

        With copy_from_user the new account lands in the model account's OU
        (unless ou is given) and joins every group the model account is a
        direct member of. The answer is read back from the directory: DN,
        enabled state, "must change password" and the groups actually joined.

        Args:
            username: Username (sAMAccountName) of the NEW account
            password: Initial password
            first_name: givenName
            last_name: sn
            email: mail (optional)
            ou: DN of the OU to create in (optional)
            additional_attributes: more LDAP attributes; operator and
                PowerShell names (Office, OfficePhone, City...) are accepted
            must_change_password: force a password change at next logon
                (default True, as in ADUC)
            copy_from_user: login of an existing account to copy groups and
                OU from (already resolved by the server)

        Returns:
            List of MCP content objects with creation result
        """
        user_dn = username
        try:
            problema = self._login_invalido(username)
            if problema:
                return self._format_response({
                    "success": False,
                    "error": (f"'{username}' nao serve como login (sAMAccountName) da conta nova: "
                              f"{problema}. Informe so o login, ex.: joana.lima. Nada foi criado."),
                    "username": username,
                }, "create_user")
            if isinstance(additional_attributes, dict):
                recusa = self._recusa_atributo_reservado("create_user", {
                    k: v for k, v in additional_attributes.items()
                    if str(k).split(";", 1)[0].strip().lower() in self._ATRIBUTOS_DE_SENHA})
                if recusa is not None:
                    return recusa
            extras, opcoes, avisos = self._normalizar_atributos_de_criacao(additional_attributes)
            if must_change_password is None:
                must_change_password = self._como_booleano(
                    opcoes.get("must_change_password"), True)
            habilitar = self._como_booleano(opcoes.get("enabled"), True)
            nome_completo = str(opcoes.get("cn") or f"{first_name} {last_name}").strip()

            # The model account, when there is one: its groups and its OU.
            modelo = None
            if copy_from_user:
                achado = self.ldap.search(
                    search_base=self.ldap.ad_config.base_dn,
                    search_filter=f"(&(objectCategory=person)(objectClass=user)"
                                  f"(sAMAccountName={self._escape_ldap_filter(copy_from_user)}))",
                    attributes=['sAMAccountName', 'memberOf', 'userAccountControl'])
                if not achado:
                    return self._format_response({
                        "success": False,
                        "error": f"Model account '{copy_from_user}' not found; nothing was created",
                        "copy_from_user": copy_from_user,
                    }, "create_user")
                modelo = achado[0]

            if ou is None and modelo is not None:
                ou_do_modelo = self._pai_do_dn(modelo['dn'])
                if self._parece_ou_de_desligados(ou_do_modelo):
                    # A replacement done in the "wrong" order (offboard first,
                    # then copy) would drop the new hire into _DESATIVADOS.
                    return self._format_response({
                        "success": False,
                        "error": (
                            f"A conta modelo '{copy_from_user}' esta em "
                            f"'{self._caminho_da_ou(modelo['dn'])}', uma OU de desligados, entao "
                            "a OU dela nao serve para a conta nova. Nada foi criado. Repita "
                            "informando 'ou' com o setor da pessoa (os grupos continuam sendo "
                            "copiados do modelo)."),
                        "copy_from_user": copy_from_user,
                        "ou_do_modelo": ou_do_modelo,
                    }, "create_user")
                ou = ou_do_modelo
            elif ou is None:
                ou = self._default_ou("users")

            user_dn = f"CN={self._escapar_rdn(nome_completo)},{ou}"

            existing_user = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(sAMAccountName={self._escape_ldap_filter(username)})",
                attributes=['sAMAccountName']
            )
            if existing_user:
                log_ldap_operation("create_user", user_dn, False, "User already exists")
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' already exists",
                    "username": username,
                    "existing_dn": existing_user[0]['dn'],
                }, "create_user")

            base = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                'sAMAccountName': username,
                'userPrincipalName': f"{username}@{self.ldap.ad_config.domain}",
                'givenName': first_name,
                'sn': last_name,
                'cn': nome_completo,
                'displayName': f"{first_name} {last_name}",
                'userAccountControl': 514  # disabled until the password is set
            }
            if email:
                base['mail'] = email
            base.update(extras)
            base['cn'] = nome_completo  # the RDN; cannot differ from the DN

            self.logger.info(f"Creating user: {username} ({user_dn})")

            # Fast path: everything in one add. If AD refuses an attribute the
            # whole add fails and nothing exists yet, so the account is created
            # with the essentials and each extra is applied on its own -- the
            # answer then names exactly which attribute was refused and why.
            recusados: Dict[str, str] = {}
            try:
                self.ldap.add(user_dn, base)
            except Exception as erro_add:
                if "entryalreadyexists" in str(erro_add).lower().replace(" ", ""):
                    return self._format_response({
                        "success": False,
                        "error": (f"Ja existe um objeto chamado '{nome_completo}' nesta OU "
                                  "(nome completo/CN repetido, login diferente). Nada foi "
                                  "criado. Informe outro nome completo em "
                                  "additional_attributes.name, ex.: com o sobrenome do meio."),
                        "username": username, "dn": user_dn,
                    }, "create_user")
                if not extras or not self._eh_erro_de_atributo(erro_add):
                    raise
                essenciais = {k: v for k, v in base.items() if k not in extras
                              or k in ('sAMAccountName', 'userPrincipalName', 'cn')}
                essenciais['userAccountControl'] = 514
                self.ldap.add(user_dn, essenciais)
                for nome, valor in extras.items():
                    if nome in ('sAMAccountName', 'cn', 'userAccountControl'):
                        continue
                    try:
                        self.ldap.modify(user_dn, {nome: [(MODIFY_REPLACE,
                                                           valor if isinstance(valor, list)
                                                           else [valor])]})
                    except Exception as erro_attr:  # noqa: BLE001 - reported per attribute
                        recusados[nome] = str(erro_attr)[:200]

            try:
                self._set_user_password(user_dn, password)
            except Exception as pwd_error:
                # Most common cause: AD password policy (length, complexity,
                # history, or part of the account name) -> WILL_NOT_PERFORM
                # (0x0000052D). Roll back so no password-less orphan is left.
                rolled_back = False
                try:
                    self.ldap.delete(user_dn)
                    rolled_back = True
                except Exception:
                    pass
                err = str(pwd_error)
                if any(token in err for token in ('WILL_NOT_PERFORM', '0000052D', '5003')):
                    reason = ("password rejected by Active Directory policy "
                              "(length/complexity/history, or it contains part of "
                              "the account name)")
                else:
                    reason = f"failed to set password: {pwd_error}"
                cleanup = "account was rolled back" if rolled_back else \
                    "WARNING: account could not be rolled back and may need manual cleanup"
                raise Exception(f"User '{username}' NOT created - {reason} ({cleanup})")

            # Enabling and "must change" are part of creating the account: if
            # either fails, the account is removed rather than left disabled,
            # with a password and without the forced change -- a retry would
            # then only have answered "already exists" (audit 2026-09-19).
            try:
                if habilitar:
                    self.ldap.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
                if must_change_password:
                    self.ldap.modify(user_dn, {'pwdLastSet': [(MODIFY_REPLACE, [0])]})
            except Exception as passo_erro:
                desfeita = False
                try:
                    self.ldap.delete(user_dn)
                    desfeita = True
                except Exception:  # noqa: BLE001 - reported below
                    pass
                raise Exception(
                    f"User '{username}' NOT created - enabling or forcing the password change "
                    f"failed ({passo_erro}); "
                    + ("the account was rolled back (desfeita), nothing is left behind" if desfeita
                       else "WARNING: the account could not be rolled back and exists DISABLED; "
                            "remove it or finish it by hand"))

            grupos_ok: List[str] = []
            grupos_falha: List[Dict[str, str]] = []
            grupos_privilegiados: List[Dict[str, Any]] = []
            if modelo is not None:
                dns_do_modelo = self._get_attr_list(modelo['attributes'], 'memberOf')
                protegidos = (self._privilegios_por_dn(dns_do_modelo)
                              if self._protecao_de_privilegiados_ativa() else {})
                for grupo_dn in dns_do_modelo:
                    if normalizar_dn(grupo_dn) in protegidos:
                        # Was copied and only warned about afterwards; a new
                        # hire never inherits administrative rights by copy.
                        grupos_privilegiados.append(protegidos[normalizar_dn(grupo_dn)])
                        continue
                    try:
                        self.ldap.modify(grupo_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                        grupos_ok.append(self._nome_do_dn(grupo_dn))
                    except Exception as exc:  # noqa: BLE001 - reported per group
                        grupos_falha.append({"grupo": self._nome_do_dn(grupo_dn),
                                             "erro": str(exc)[:200]})

            relido = self.ldap.search(
                search_base=user_dn, search_filter="(objectClass=*)",
                attributes=['userAccountControl', 'pwdLastSet', 'memberOf', 'primaryGroupID',
                            'objectSid'],
                search_scope=ldap3.BASE)
            attrs = relido[0]['attributes'] if relido else {}
            uac = int(self._get_attr(attrs, 'userAccountControl', 0) or 0)

            log_ldap_operation("create_user", user_dn, True, f"Created user: {username}")
            dados: Dict[str, Any] = {
                "username": username,
                "dn": user_dn,
                "upn": base['userPrincipalName'],
                "ou": self._caminho_da_ou(user_dn),
                "verified": bool(relido),
                "account_enabled": not bool(uac & _UAC_ACCOUNTDISABLE) if relido else habilitar,
                "must_change_password": self._is_password_expired(attrs) if relido
                else bool(must_change_password),
            }
            if modelo is not None:
                dados["copied_from"] = {
                    "login": copy_from_user, "dn": modelo['dn'],
                    "groups_joined": grupos_ok,
                    "groups_of_model": len(self._get_attr_list(modelo['attributes'],
                                                               'memberOf')),
                }
                uac_modelo = int(self._get_attr(modelo['attributes'], 'userAccountControl', 0) or 0)
                if uac_modelo & _UAC_ACCOUNTDISABLE:
                    dados["copied_from"]["aviso"] = (
                        f"A conta modelo esta desativada; a OU herdada foi "
                        f"{self._caminho_da_ou(user_dn)}. Confira se e o setor certo.")
                if grupos_privilegiados:
                    dados["copied_from"]["grupos_privilegiados_recusados"] = grupos_privilegiados
                    dados["copied_from"]["aviso_privilegiado"] = (
                        "Estes grupos da conta modelo sao privilegiados e NAO foram copiados: "
                        f"{', '.join(g['nome'] for g in grupos_privilegiados)}. Se a pessoa "
                        "precisa mesmo deles, a inclusao e feita pelo console do AD.")
                elif not self._protecao_de_privilegiados_ativa():
                    copiados = [g for g in grupos_ok
                                if self._motivo_privilegiado({}, g) is not None]
                    if copiados:
                        dados["aviso_privilegiado"] = (
                            f"Grupos administrativos copiados: {', '.join(copiados)} (protecao "
                            "de alvos privilegiados desligada neste AD).")
                if not grupos_ok and not grupos_falha:
                    dados["copied_from"]["nota"] = (
                        "A conta modelo so tem o grupo primario (Domain Users), que toda "
                        "conta nova ja recebe. Nao havia outros grupos a copiar.")
                if grupos_falha:
                    dados["copied_from"]["groups_failed"] = grupos_falha
            dados["groups"] = [self._nome_do_dn(g) for g in self._get_attr_list(attrs, 'memberOf')]
            primario = self._grupo_primario(attrs)
            if primario:
                dados["primary_group"] = primario["nome"]
            if recusados:
                dados["attributes_rejected"] = recusados
            dados.update(avisos)

            mensagem = f"User '{username}' created successfully"
            if recusados:
                mensagem += (f"; {len(recusados)} attribute(s) refused by AD and NOT set: "
                             f"{', '.join(recusados)}")
            if grupos_falha:
                mensagem += f"; {len(grupos_falha)} group(s) could not be joined"
            if grupos_privilegiados:
                mensagem += (f"; ATTENTION: {len(grupos_privilegiados)} privileged group(s) of the "
                             "model were NOT copied (see copied_from.grupos_privilegiados_recusados)")
            if dados.get("aviso_privilegiado"):
                mensagem += "; ATTENTION: administrative groups were copied (see aviso_privilegiado)"
            return self._success_response(mensagem, dados)

        except Exception as e:
            return self._handle_ldap_error(e, "create_user", user_dn)

    # Compared against the OU names with case, accents and punctuation removed
    # ("Ex-Funcionarios" -> "exfuncionarios"). Audit 2026-09-19: the first list
    # missed Desabilitados, Inactive Users, Old Users, Leavers, Encerradas.
    _PALAVRAS_DE_DESLIGADOS = ("desativ", "desabilit", "desligad", "disabled", "inativ",
                               "inactiv", "excluid", "demitid", "bloquead", "deleted",
                               "terminated", "exfuncion", "excolab", "oldusers", "leaver",
                               "encerrad", "revogad", "arquivad", "archive", "offboard",
                               "desconectad", "suspens", "afastad", "arquivomorto")

    # sAMAccountName: no spaces and none of these (Microsoft's list), max 20.
    _PROIBIDOS_NO_LOGIN = set('"/\\[]:;|=,+*?<>@')

    def _login_invalido(self, login: str) -> Optional[str]:
        texto = str(login or "")
        if not texto.strip():
            return "vazio"
        if any(c.isspace() for c in texto):
            return "tem espaco (veio um nome, nao um login?)"
        proibidos = sorted({c for c in texto if c in self._PROIBIDOS_NO_LOGIN})
        if proibidos:
            dica = (" (parece e-mail/UPN, DOMINIO\\login ou DN -- de outro cliente?)"
                    if set(proibidos) & set("@\\=,") else "")
            return f"tem caracteres invalidos {''.join(proibidos)}{dica}"
        if len(texto) > 20:
            return f"tem {len(texto)} caracteres; o limite do AD e 20"
        return None

    def _parece_ou_de_desligados(self, dn: str) -> bool:
        """Whether an OU path reads like a parking place for disabled accounts."""
        nomes = [self._chave_simples(p.split("=", 1)[1]) for p in dividir_dn(dn)
                 if p.lower().startswith("ou=")]
        return any(palavra in nome for nome in nomes for palavra in self._PALAVRAS_DE_DESLIGADOS)

    @staticmethod
    def _escapar_rdn(valor: str) -> str:
        """Escape a CN value for use inside a DN (RFC 4514)."""
        texto = str(valor)
        for c in ('\\', ',', '+', '"', '<', '>', ';', '='):
            texto = texto.replace(c, '\\' + c)
        if texto.startswith(('#', ' ')):
            texto = '\\' + texto
        if texto.endswith(' '):
            texto = texto[:-1] + '\\ '
        return texto

    def modify_user(self, username: str, attributes: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Modify user attributes.
        
        Args:
            username: Username to modify
            attributes: Dictionary of attributes to modify
            
        Returns:
            List of MCP content objects with modification result
        """
        try:
            # Find user DN
            recusa = self._recusa_atributo_reservado("modify_user", attributes)
            if recusa is not None:
                return recusa

            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=self._ATRIBUTOS_DE_PRIVILEGIO
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "modify_user")
            
            user_dn = user_results[0]['dn']
            tem_senha = any(str(k).lower() == 'password' for k in attributes)
            if tem_senha and self._protecao_de_privilegiados_ativa():
                motivo = self._motivo_privilegiado(user_results[0]['attributes'], username)
                if motivo:
                    return self._recusa_alvo_privilegiado("modify_user", [
                        {"nome": self._nome_do_dn(user_dn), "dn": user_dn, "motivo": motivo}])
            
            # Prepare modifications. Operator/PowerShell names map to LDAP
            # names, and an empty value CLEARS the attribute: sending "" made
            # AD refuse the whole change with invalidAttributeSyntax.
            modifications = {}
            limpos = []
            nulos = []
            for attr, value in attributes.items():
                if attr.lower() == 'password':
                    # Handle password separately
                    continue
                nome = self._ALIASES_DE_ATRIBUTO.get(self._chave_simples(attr), attr)
                if value is None:
                    # Models fill fields they do not mean to change with null;
                    # clearing them erased data (audit 2026-09-19). Only an
                    # explicit "" clears.
                    nulos.append(nome)
                    continue
                if isinstance(value, str):
                    value = value.strip()
                if isinstance(value, list):
                    value = [v for v in value if v not in (None, "")]
                if value in (None, "", []):
                    modifications[nome] = [(MODIFY_REPLACE, [])]
                    limpos.append(nome)
                elif isinstance(value, list):
                    modifications[nome] = [(MODIFY_REPLACE, value)]
                else:
                    modifications[nome] = [(MODIFY_REPLACE, [value])]
            
            self.logger.info(f"Modifying user: {username} ({user_dn})")
            
            # Apply modifications
            if modifications:
                success = self.ldap.modify(user_dn, modifications)
                if not success:
                    raise Exception("Failed to modify user attributes")
            
            # Handle password change separately
            if 'password' in attributes:
                self._set_user_password(user_dn, attributes['password'])
            
            log_ldap_operation("modify_user", user_dn, True, f"Modified user: {username}")
            
            return self._success_response(
                f"User '{username}' modified successfully",
                {
                    "username": username,
                    "dn": user_dn,
                    "modified_attributes": [a for a in modifications if a not in limpos]
                    + (["password"] if 'password' in attributes else []),
                    **({"cleared_attributes": limpos} if limpos else {}),
                    **({"ignored_null": nulos} if nulos else {}),
                }
            )
            
        except Exception as e:
            return self._handle_ldap_error(e, "modify_user", username)
    
    def delete_user(self, username: str) -> List[Dict[str, Any]]:
        """
        Delete a user from Active Directory.
        
        Args:
            username: Username to delete
            
        Returns:
            List of MCP content objects with deletion result
        """
        try:
            # Find user DN
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "delete_user")
            
            user_dn = user_results[0]['dn']
            
            self.logger.info(f"Deleting user: {username} ({user_dn})")
            
            # Delete user
            success = self.ldap.delete(user_dn)
            
            if success:
                log_ldap_operation("delete_user", user_dn, True, f"Deleted user: {username}")
                
                return self._success_response(
                    f"User '{username}' deleted successfully",
                    {
                        "username": username,
                        "dn": user_dn
                    }
                )
            else:
                raise Exception("Failed to delete user")
            
        except Exception as e:
            return self._handle_ldap_error(e, "delete_user", username)
    
    def enable_user(self, username: str, move_to_ou: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Enable a user account, optionally moving it back to an OU.

        Args:
            username: Username to enable
            move_to_ou: DN of the OU to move the account to (readmission)

        Returns:
            List of MCP content objects with result
        """
        return self._alterar_conta(username, desativar=False, move_to_ou=move_to_ou)

    def disable_user(self, username: str, move_to_ou: Optional[str] = None,
                     remove_from_groups: bool = False) -> List[Dict[str, Any]]:
        """
        Disable a user account -- the whole offboarding in one call.

        Measured 2026-09-19: "disable her and move her to _DESATIVADOS" took a
        model 39 tool calls and still left the account where it was. Disabling,
        moving and (optionally) removing the groups now happen here, and the
        answer is read back from the directory.

        Args:
            username: Username to disable
            move_to_ou: DN of the OU to move the account to (e.g. _DESATIVADOS)
            remove_from_groups: also remove the account from every group it is
                a direct member of (the primary group cannot be removed)

        Returns:
            List of MCP content objects with result
        """
        return self._alterar_conta(username, desativar=True, move_to_ou=move_to_ou,
                                   remove_from_groups=remove_from_groups)

    def reset_password(self, username: str, new_password: Optional[str] = None, 
                      force_change: bool = True,
                      password_never_expires: bool = False) -> List[Dict[str, Any]]:
        """
        Reset user password.
        
        Args:
            username: Username to reset password for
            new_password: New password (if None, generates random password)
            force_change: Force user to change password at next logon
            password_never_expires: Set password to never expire (adds DONT_EXPIRE_PASSWORD flag)
            
        Returns:
            List of MCP content objects with result
            
        Note:
            force_change and password_never_expires are mutually exclusive in practice.
            If password_never_expires is True, force_change will be ignored as the password
            will be set to never expire.
        """
        try:
            # Find user DN and current userAccountControl
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['userAccountControl'] + self._ATRIBUTOS_DE_PRIVILEGIO
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "reset_password")
            
            user_dn = user_results[0]['dn']
            if self._protecao_de_privilegiados_ativa():
                motivo = self._motivo_privilegiado(user_results[0]['attributes'], username)
                if motivo:
                    return self._recusa_alvo_privilegiado("reset_password", [
                        {"nome": self._nome_do_dn(user_dn), "dn": user_dn, "motivo": motivo}])
            current_uac = self._get_attr(user_results[0]['attributes'], 'userAccountControl', 512)
            if isinstance(current_uac, list):
                current_uac = current_uac[0] if current_uac else 512
            current_uac = int(current_uac)

            warnings: List[str] = []
            changes_applied: List[str] = []

            # Read the DACL up front so we can detect (and, when forcing a change,
            # resolve) the "user cannot change password" restriction. Best-effort:
            # if the descriptor cannot be read we degrade to a warning instead of
            # silently claiming a state we did not verify.
            current_sd = None
            cannot_change = None
            try:
                current_sd = self.ldap.get_security_descriptor(user_dn)
                cannot_change = sd_acl.cannot_change_state(current_sd)["cannot_change"]
            except Exception as sd_err:  # noqa: BLE001 - degrade, don't fail the reset
                warnings.append(
                    "Could not read the security descriptor to check 'user cannot "
                    f"change password': {sd_err}"
                )

            # Generate password if not provided
            if new_password is None:
                new_password = self._generate_password()

            self.logger.info(f"Resetting password for user: {username}")

            # Set new password (raises on failure)
            self._set_user_password(user_dn, new_password)
            changes_applied.append("password set")

            if password_never_expires:
                # Add DONT_EXPIRE_PASSWORD, ensure account enabled.
                # force_change is impossible alongside never-expires in AD.
                if force_change:
                    warnings.append(
                        "'force change at next logon' was not applied because "
                        "'password never expires' was requested; the two are "
                        "mutually exclusive in Active Directory."
                    )
                new_uac = (current_uac | _UAC_DONT_EXPIRE_PASSWORD) & ~_UAC_ACCOUNTDISABLE
                self.ldap.modify(user_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                })
                changes_applied.append("set password never expires")
                self.logger.info(
                    f"Set password never expires for user: {username} "
                    f"(UAC: {current_uac} -> {new_uac})"
                )
            elif force_change:
                # Auto-resolve the two settings that make AD refuse (or silently
                # ignore) a forced change, then set pwdLastSet=0.
                if current_uac & _UAC_DONT_EXPIRE_PASSWORD:
                    new_uac = current_uac & ~_UAC_DONT_EXPIRE_PASSWORD
                    self.ldap.modify(user_dn, {
                        'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                    })
                    changes_applied.append("cleared password never expires")
                    warnings.append(
                        "Account had 'password never expires' set; it was cleared "
                        "so the forced change can take effect (mutually exclusive)."
                    )
                if cannot_change and current_sd is not None:
                    cleaned_sd, removed = sd_acl.remove_cannot_change(current_sd)
                    if removed:
                        self.ldap.set_security_descriptor(user_dn, cleaned_sd)
                        changes_applied.append("removed 'user cannot change password'")
                        warnings.append(
                            "Account had 'user cannot change password' set; it was "
                            "removed so the forced change can take effect (otherwise "
                            "the user would be forced to change a password they are "
                            "forbidden to change)."
                        )
                # Force password change at next logon
                self.ldap.modify(user_dn, {
                    'pwdLastSet': [(MODIFY_REPLACE, [0])]
                })
                changes_applied.append("set must change at next logon")

            # Read the resulting state back from AD and report the VERIFIED effect,
            # never the requested inputs.
            effective = self._verify_account_state(user_dn)

            log_ldap_operation("reset_password", user_dn, True, f"Reset password for: {username}")

            return self._success_response(
                f"Password reset successfully for user '{username}'",
                {
                    "username": username,
                    "dn": user_dn,
                    "new_password": new_password,
                    "requested": {
                        "force_change": force_change,
                        "password_never_expires": password_never_expires,
                    },
                    "effective": effective,
                    "changes_applied": changes_applied,
                    "warnings": warnings,
                }
            )

        except Exception as e:
            return self._handle_ldap_error(e, "reset_password", username)

    def _verify_account_state(self, user_dn: str) -> Dict[str, Any]:
        """Re-read an account and report its verified password-related state.

        Values are read back from AD after the operation so the caller sees the
        real effect, not the requested inputs. ``user_cannot_change_password`` is
        None when the security descriptor could not be read.
        """
        result = self.ldap.search(
            search_base=user_dn,
            search_filter="(objectClass=*)",
            attributes=['userAccountControl', 'pwdLastSet'],
        )
        attrs = result[0]['attributes'] if result else {}
        uac = self._get_attr(attrs, 'userAccountControl', 512)
        if isinstance(uac, list):
            uac = uac[0] if uac else 512
        uac = int(uac)
        pwd_last_set = self._get_attr(attrs, 'pwdLastSet', None)
        if isinstance(pwd_last_set, list):
            pwd_last_set = pwd_last_set[0] if pwd_last_set else None

        never_expires = bool(uac & _UAC_DONT_EXPIRE_PASSWORD)
        must_change_raw = str(pwd_last_set) in ("0", "1601-01-01 00:00:00+00:00")
        # A never-expiring password makes "must change" ineffective even if
        # pwdLastSet is 0, so report the effective truth.
        must_change = must_change_raw and not never_expires

        cannot_change: Optional[bool] = None
        try:
            sd = self.ldap.get_security_descriptor(user_dn)
            cannot_change = sd_acl.cannot_change_state(sd)["cannot_change"]
        except Exception:  # noqa: BLE001
            cannot_change = None

        return {
            "account_enabled": not bool(uac & _UAC_ACCOUNTDISABLE),
            "password_never_expires": never_expires,
            "must_change_at_next_logon": must_change,
            "user_cannot_change_password": cannot_change,
        }


    def get_user_groups(self, username: str) -> List[Dict[str, Any]]:
        """
        Get groups that a user is member of.
        
        Args:
            username: Username to get groups for
            
        Returns:
            List of MCP content objects with group information
        """
        try:
            # Get user's memberOf attribute
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['memberOf']
            )
            
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, "get_user_groups")
            
            user_dn = user_results[0]['dn']
            member_of = self._get_attr_list(user_results[0]['attributes'], 'memberOf')

            # Get detailed group information
            groups = []
            for group_dn in member_of:
                try:
                    group_info = self.ldap.search(
                        search_base=group_dn,
                        search_filter="(objectClass=group)",
                        attributes=['sAMAccountName', 'displayName', 'description', 'groupType'],
                        search_scope=ldap3.BASE
                    )
                    
                    if group_info:
                        group_data = group_info[0]['attributes']
                        groups.append({
                            'dn': group_dn,
                            'sAMAccountName': self._get_attr(group_data, 'sAMAccountName', ''),
                            'displayName': self._get_attr(group_data, 'displayName', ''),
                            'description': self._get_attr(group_data, 'description', ''),
                            'groupType': self._get_attr(group_data, 'groupType', 0)
                        })
                except:
                    # Skip if group info cannot be retrieved
                    groups.append({'dn': group_dn, 'error': 'Could not retrieve group details'})
            
            log_ldap_operation("get_user_groups", user_dn, True, f"Retrieved {len(groups)} groups")
            
            return self._format_response({
                "username": username,
                "user_dn": user_dn,
                "groups": groups,
                "group_count": len(groups)
            }, "get_user_groups")
            
        except Exception as e:
            return self._handle_ldap_error(e, "get_user_groups", username)
    
    def _alterar_conta(self, username: str, desativar: bool,
                       move_to_ou: Optional[str] = None,
                       remove_from_groups: bool = False) -> List[Dict[str, Any]]:
        """Flip ACCOUNTDISABLE, then optionally move the account and drop its groups.

        @MX:WARN Only bit 0x2 changes. The previous version REPLACED
        userAccountControl with 512/514 and erased every other flag: a service
        account lost "password never expires", a smart-card account lost
        "smart card required".
        @MX:REASON Each later step runs only after the previous one succeeded,
        and every step reports what it did; a failure in the middle says what
        was already applied instead of a bare error.
        """
        operacao = "disable" if desativar else "enable"
        try:
            user_results = self.ldap.search(
                search_base=self.ldap.ad_config.base_dn,
                search_filter=f"(&(objectCategory=person)(objectClass=user)"
                              f"(sAMAccountName={self._escape_ldap_filter(username)}))",
                attributes=['sAMAccountName', 'userAccountControl', 'memberOf']
            )
            if not user_results:
                return self._format_response({
                    "success": False,
                    "error": f"User '{username}' not found",
                    "username": username
                }, operacao)

            user_dn = user_results[0]['dn']
            attrs = user_results[0]['attributes']
            lido = self._get_attr(attrs, 'userAccountControl', None)
            if lido in (None, "", []):
                # Falling back to 512 would REPLACE the real flags again (the
                # defect this function exists to remove).
                return self._format_response({
                    "success": False,
                    "error": ("userAccountControl could not be read for this account (permission "
                              "or replication); nothing was changed"),
                    "username": username, "dn": user_dn,
                }, operacao)
            uac_antes = int(lido)
            uac_depois = (uac_antes | _UAC_ACCOUNTDISABLE) if desativar \
                else (uac_antes & ~_UAC_ACCOUNTDISABLE)
            aplicado: List[str] = []

            if uac_depois != uac_antes:
                self.ldap.modify(user_dn, {
                    'userAccountControl': [(MODIFY_REPLACE, [uac_depois])]
                })
                aplicado.append("conta desativada" if desativar else "conta ativada")
            else:
                aplicado.append("conta ja estava desativada" if desativar
                                else "conta ja estava ativa")

            # Move first: if it fails, the groups are still where they were
            # and nothing needs reconstructing. Removing groups first and then
            # failing the move lost the list of what had been removed.
            movimento = None
            if move_to_ou:
                try:
                    movimento = self._mover_e_reler(user_dn, move_to_ou)
                except Exception as exc:  # noqa: BLE001 - say what was already applied
                    log_ldap_operation(operacao, user_dn, False, f"move failed: {exc}")
                    return self._format_response({
                        "success": False,
                        "error": (f"Account step done, but the move to '{move_to_ou}' failed: "
                                  f"{exc}. Groups were NOT touched."),
                        "username": username, "dn": user_dn, "applied": aplicado,
                        "failed_step": "move_to_ou",
                    }, operacao)
                if movimento["changed"]:
                    aplicado.append(f"movida para {self._caminho_da_ou(movimento['new_dn'])}")
                    user_dn = movimento["new_dn"]
                else:
                    aplicado.append("ja estava na OU pedida")

            grupos_removidos: List[Dict[str, str]] = []
            falhas_grupos: List[Dict[str, str]] = []
            grupos_privilegiados: List[Dict[str, Any]] = []
            if desativar and remove_from_groups:
                dns_dos_grupos = self._get_attr_list(attrs, 'memberOf')
                protegidos = (self._privilegios_por_dn(dns_dos_grupos)
                              if self._protecao_de_privilegiados_ativa() else {})
                for grupo_dn in dns_dos_grupos:
                    if normalizar_dn(grupo_dn) in protegidos:
                        # Disabling is never blocked (it is the protective half
                        # of offboarding); only the privileged removal is.
                        grupos_privilegiados.append(protegidos[normalizar_dn(grupo_dn)])
                        continue
                    try:
                        self.ldap.modify(grupo_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
                        grupos_removidos.append({"nome": self._nome_do_dn(grupo_dn),
                                                 "dn": grupo_dn})
                        log_ldap_operation("remove_member", grupo_dn, True,
                                           f"Offboarding removed {user_dn}")
                    except Exception as exc:  # noqa: BLE001 - reported per group
                        falhas_grupos.append({"grupo": self._nome_do_dn(grupo_dn),
                                              "dn": grupo_dn, "erro": str(exc)[:200]})
                if grupos_removidos:
                    aplicado.append(f"removida de {len(grupos_removidos)} grupo(s)")
                if grupos_privilegiados:
                    aplicado.append(f"{len(grupos_privilegiados)} grupo(s) privilegiado(s) NAO "
                                    "alterado(s) (ver groups_refused_privileged)")

            relido = self.ldap.search(search_base=user_dn, search_filter="(objectClass=*)",
                                      attributes=['userAccountControl', 'memberOf'],
                                      search_scope=ldap3.BASE)
            attrs_relidos = relido[0]['attributes'] if relido else {}
            uac_relido = int(self._get_attr(attrs_relidos, 'userAccountControl', uac_depois)
                             or uac_depois)

            log_ldap_operation(operacao, user_dn, True,
                               f"{operacao.capitalize()}d user: {username}")
            dados: Dict[str, Any] = {
                "username": username,
                "dn": user_dn,
                "userAccountControl": uac_relido,
                "account_enabled": not bool(uac_relido & _UAC_ACCOUNTDISABLE),
                "applied": aplicado,
                "ou": self._caminho_da_ou(user_dn),
                "verified": bool(relido),
            }
            if movimento is not None and movimento["changed"]:
                dados["previous_dn"] = movimento["old_dn"]
            if desativar and remove_from_groups:
                dados["groups_removed"] = grupos_removidos
                dados["groups_remaining"] = [self._nome_do_dn(g) for g in
                                             self._get_attr_list(attrs_relidos, 'memberOf')]
                if falhas_grupos:
                    dados["groups_failed"] = falhas_grupos
                if grupos_privilegiados:
                    dados["groups_refused_privileged"] = grupos_privilegiados
                    dados["aviso_privilegiado"] = (
                        "A conta foi desativada, mas continua membro destes grupos "
                        "privilegiados, que este servidor nao altera: "
                        f"{', '.join(g['nome'] for g in grupos_privilegiados)}. Retire-a pelo "
                        "console do AD.")
            elif desativar:
                dados["groups_kept"] = len(self._get_attr_list(attrs_relidos, 'memberOf'))
            return self._success_response(
                f"User '{username}' {operacao}d successfully: " + "; ".join(aplicado), dados)

        except Exception as e:
            return self._handle_ldap_error(e, operacao, username)

    def _set_user_password(self, user_dn: str, password: str) -> None:
        """Set user password using LDAP modify operation.

        @MX:NOTE Every user password write passes here (create, reset, update
        with password), so the value is registered for redaction here, before
        ldap3 or the directory can echo it in an error.
        """
        register_secret(password, persistent=False)
        # Encode password for Active Directory
        password_encoded = f'"{password}"'.encode('utf-16-le')
        
        # Set password
        success = self.ldap.modify(user_dn, {
            'unicodePwd': [(MODIFY_REPLACE, [password_encoded])]
        })
        
        if not success:
            raise Exception("Failed to set user password")
    
    def _generate_password(self, length: int = 12) -> str:
        """Generate a random password."""
        # Ensure password meets complexity requirements
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*"
        
        # Ensure at least one character from each category
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def _is_user_enabled(self, uac_value: int) -> bool:
        """Check if user account is enabled based on userAccountControl."""
        return not bool(uac_value & 0x0002)  # Check ACCOUNTDISABLE flag
    
    def _is_user_locked(self, uac_value: int, attributes: Optional[Dict[str, Any]] = None) -> bool:
        """Whether the account is locked out.

        AD does not keep the LOCKOUT bit of userAccountControl up to date; the
        truth is lockoutTime > 0. The bit is still honoured when set.
        """
        if uac_value & 0x0010:
            return True
        if attributes is not None:
            return self._as_filetime(self._get_attr(attributes, 'lockoutTime', 0)) > 0
        return False
    
    def _is_password_expired(self, attributes: Dict[str, Any]) -> bool:
        """Check whether the user must change the password at next logon.

        AD encodes that as pwdLastSet = 0. ldap3 surfaces it either as the int 0
        or as datetime(1601, 1, 1); comparing the raw value against 0 answered
        False for the datetime form, contradicting
        ad_get_password_policy_violations about the very same user.
        """
        return self._as_filetime(self._get_attr(attributes, 'pwdLastSet', 0)) == 0

    def _is_account_expired(self, attributes: Dict[str, Any]) -> bool:
        """Check whether the account expiry date is in the past.

        The previous version divided the raw value by 10, which raises TypeError
        for the datetime form ldap3 actually returns; a bare except then turned
        every expired account into "not expired". Measured on production: an
        account expired in 2018 reported account_expired=False.
        """
        account_expires = self._as_filetime(
            self._get_attr(attributes, 'accountExpires', 0))
        if account_expires == 0 or account_expires >= self._never_expires_floor():
            return False
        return account_expires < self._now_filetime()
    
    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information for user operations."""
        return {
            "operations": [
                "list_users", "get_user", "create_user", "modify_user", 
                "delete_user", "enable_user", "disable_user", "reset_password",
                "get_user_groups"
            ],
            "user_attributes": [
                "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn",
                "mail", "telephoneNumber", "department", "title", "manager", "description",
                "physicalDeliveryOfficeName", "company", "userAccountControl"
            ],
            "required_permissions": [
                "Create User Objects", "Delete User Objects", "Reset Password",
                "Enable/Disable User Account", "Modify User Attributes"
            ]
        }
