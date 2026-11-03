"""Findings of the adversarial write audit of 2026-09-19, one test each.

Every input here is something a model actually sends: text where a boolean
goes ("não", "null"), a list where one value goes, null for "unchanged", the
manager under another name. Each test failed before its fix. The directory
is the stateful fake, so the assertions read what was WRITTEN.
"""

import asyncio
import json

import pytest

from .diretorio_falso import BASE, DESATIVADOS, FILIAL, FIN_FILIAL, TI, unidade
from .test_fluxos_de_uma_chamada import G_FIN, G_TI, SABRINA, _entrada, chamar


def _grupos_de(servidor, dn):
    entrada = _entrada(servidor, dn)
    return sorted(entrada.valores("memberOf")) if entrada else None


# ------------------------------------------------ 1. text booleans (CRITICAL)

@pytest.mark.parametrize("valor", ["não", "nao", "off", "n", "false", "False", "0", "falso"])
def test_booleano_em_texto_negativo_nao_remove_grupos(srv, valor):
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               remove_from_groups=valor)
    assert r.get("success") is True, r
    assert len(_grupos_de(srv, SABRINA)) == 2


@pytest.mark.parametrize("valor", ["null", "None", ""])
def test_booleano_nulo_vale_o_padrao(srv, valor):
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               remove_from_groups=valor)
    assert r.get("success") is True, r
    assert len(_grupos_de(srv, SABRINA)) == 2


@pytest.mark.parametrize("valor", ["talvez", "2", "yes please"])
def test_booleano_irreconhecivel_e_recusado_sem_executar(srv, valor):
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               remove_from_groups=valor)
    assert r["erro"] == "PARAMETRO_INVALIDO" and "remove_from_groups" in r["mensagem"]
    assert _entrada(srv, SABRINA).atributos["userAccountControl"] == 512


def test_force_nao_nao_apaga_a_ou_com_conteudo(srv):
    r = chamar(srv, "ad_delete_organizational_unit_forced", ou_dn="Filial/TI", force="não")
    assert r.get("success") is not True
    assert _entrada(srv, TI) is not None


def test_must_change_password_off_e_respeitado(srv):
    r = chamar(srv, "ad_create_user_account", username="svc.x", password="Mudar@12345",
               first_name="Svc", last_name="X", ou="TI", must_change_password="off")
    assert r["must_change_password"] is False


# ------------------------------------------ 2. offboarding keeps what it removed

def test_lista_em_parametro_de_valor_unico_e_recusada_antes_de_escrever(srv):
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               move_to_ou=["_DESATIVADOS", "Users"], remove_from_groups=True)
    assert r["erro"] == "PARAMETRO_INVALIDO" and "move_to_ou" in r["mensagem"]
    assert _entrada(srv, SABRINA).atributos["userAccountControl"] == 512
    assert len(_grupos_de(srv, SABRINA)) == 2


def test_grupos_removidos_voltam_com_dn(srv):
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               move_to_ou="_DESATIVADOS", remove_from_groups=True)
    assert sorted(g["dn"] for g in r["groups_removed"]) == sorted([G_FIN, G_TI])


def test_mover_antes_de_tirar_os_grupos(srv):
    """If the move fails, the groups must still be there to be recovered."""
    falso = srv.falso

    def move_quebrado(dn, novo):
        raise Exception("LDAPInsufficientAccessRightsResult - 50")
    falso.move = move_quebrado
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               move_to_ou="_DESATIVADOS", remove_from_groups=True)
    assert r["success"] is False and r["failed_step"] == "move_to_ou"
    assert len(_grupos_de(srv, SABRINA)) == 2


# ------------------------------------------------ 3. list items that are not text

@pytest.mark.parametrize("item", [["CN=Chefe,OU=TI,DC=beta,DC=local"], {"nome": "João"}, ""])
def test_item_de_lista_que_nao_e_texto_recusa_a_chamada(srv, item):
    antes = _entrada(srv, G_TI).valores("member")
    r = chamar(srv, "ad_add_member_to_group", group_name="TI Suporte",
               member_dn=["mariana.souza", item])
    assert r.get("sucesso") is False and r["erro"] == "PARAMETRO_INVALIDO", r
    assert _entrada(srv, G_TI).valores("member") == antes


# ------------------------------------------------------ 4. manager aliases resolve

@pytest.mark.parametrize("attrs", [
    {"gestor": "CN=Chefe,OU=TI,DC=beta,DC=local"},
    {"Gestor": "João"},
    {"OtherAttributes": {"manager": "João"}},
])
def test_gestor_com_outro_nome_passa_pelo_resolvedor(srv, attrs):
    r = chamar(srv, "ad_create_user_account", username="novo.x", password="Mudar@12345",
               first_name="Novo", last_name="X", ou="TI", additional_attributes=attrs)
    assert r.get("sucesso") is False
    assert r["erro"] in ("OBJETO_FORA_DO_DOMINIO", "IDENTIFICACAO_AMBIGUA")
    assert _entrada(srv, f"CN=Novo X,{TI}") is None


def test_gestor_no_topo_da_criacao_passa_pelo_resolvedor(srv):
    r = chamar(srv, "ad_create_user_account", username="novo.x", password="Mudar@12345",
               first_name="Novo", last_name="X", ou="TI", manager="Mariana Souza")
    assert r["success"] is True, r
    criada = _entrada(srv, f"CN=Novo X,{TI}").atributos
    assert criada["manager"].startswith("CN=Mariana Souza,")


# ----------------------------------------------------- 5. no half-made account

def test_falha_depois_da_senha_desfaz_a_conta(srv):
    falso = srv.falso
    original = falso.modify

    def modify_quebrado(dn, changes):
        if "userAccountControl" in changes:
            raise Exception("TEMPO_ESGOTADO simulado")
        return original(dn, changes)
    falso.modify = modify_quebrado
    r = chamar(srv, "ad_create_user_account", username="meio.feito", password="Mudar@12345",
               first_name="Meio", last_name="Feito", ou="TI")
    assert r.get("success") is False
    assert _entrada(srv, f"CN=Meio Feito,{TI}") is None
    assert "desfeita" in r["error"] or "rolled back" in r["error"]


# ------------------------------------------------ 6. offboarded OU names

@pytest.mark.parametrize("nome", ["Desabilitados", "Inactive Users", "Ex-Funcionarios",
                                  "Old Users", "Leavers", "Contas Encerradas", "Revogados"])
def test_ou_de_desligados_com_outros_nomes(srv, nome):
    srv.falso.entradas.append(type(srv.falso.entradas[0])(*unidade(nome, BASE)))
    chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
           move_to_ou=f"OU={nome},{BASE}")
    r = chamar(srv, "ad_create_user_account", username="nova.y", password="Mudar@12345",
               first_name="Nova", last_name="Y", copy_from_user="sabrina.rocha")
    assert r["success"] is False and "desligados" in r["error"]


def test_modelo_desativado_avisa_na_resposta(srv):
    chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha")
    r = chamar(srv, "ad_create_user_account", username="nova.y", password="Mudar@12345",
               first_name="Nova", last_name="Y", copy_from_user="sabrina.rocha")
    assert r["success"] is True
    assert "desativada" in r["copied_from"]["aviso"]


# ------------------------------------------------------- 7. null is "unchanged"

def test_null_na_alteracao_nao_apaga_o_campo(srv):
    _entrada(srv, SABRINA).atributos["department"] = "Financeiro"
    r = chamar(srv, "ad_modify_user_attributes", username="sabrina.rocha",
               attributes={"title": "Analista", "department": None, "mail": None})
    assert r["success"] is True
    attrs = _entrada(srv, SABRINA).atributos
    assert attrs["department"] == "Financeiro" and attrs["mail"] == "sabrina.rocha@alfa.com"
    assert sorted(r["ignored_null"]) == ["department", "mail"]


def test_texto_vazio_na_alteracao_limpa_o_campo(srv):
    _entrada(srv, SABRINA).atributos["department"] = "Financeiro"
    r = chamar(srv, "ad_modify_user_attributes", username="sabrina.rocha",
               attributes={"department": ""})
    assert r["cleared_attributes"] == ["department"]
    assert "department" not in _entrada(srv, SABRINA).atributos


# ---------------------------------------------------------- 8. computer reset

def test_reset_de_computador_nao_usa_senha_adivinhavel(srv):
    r = chamar(srv, "ad_reset_computer_password_trust", computer_name="FIN-PC01")
    assert r["success"] is True
    gravada = _entrada(srv, f"CN=FIN-PC01,{FIN_FILIAL}").atributos["unicodePwd"]
    assert gravada != '"fin-pc01"'.encode("utf-16-le")
    assert "new_password" not in r


@pytest.mark.parametrize("tool", ["ad_reset_computer_password_trust",
                                  "ad_disable_computer_account_trust",
                                  "ad_delete_computer_account_permanently"])
def test_controlador_de_dominio_e_recusado(srv, tool):
    dc = _entrada(srv, f"CN=FIN-PC01,{FIN_FILIAL}")
    dc.atributos["userAccountControl"] = 532480      # SERVER_TRUST_ACCOUNT | delegation
    r = chamar(srv, tool, computer_name="FIN-PC01")
    assert r.get("success") is False and "controlador de dom" in r["error"].lower()
    assert _entrada(srv, f"CN=FIN-PC01,{FIN_FILIAL}").atributos["userAccountControl"] == 532480


# ------------------------------------------------------ 9. unread UAC refuses

def test_uac_ilegivel_nao_sobrescreve(srv):
    _entrada(srv, SABRINA).atributos.pop("userAccountControl")
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha")
    assert r.get("success") is False
    assert "userAccountControl" not in _entrada(srv, SABRINA).atributos


# ------------------------------------------ 10-13. duplicates, primary, privileged

def test_mesmo_membro_duas_vezes_na_lista_nao_e_falha(srv):
    r = chamar(srv, "ad_add_member_to_group", group_name="Financeiro - Matriz",
               member_dn=["joao.pereira", "João Pereira"])
    assert r["success"] is True and r["resumo"] == {"adicionado": 1}


def test_tirar_do_grupo_primario_explica(srv):
    r = chamar(srv, "ad_remove_member_from_group", group_name="Domain Users",
               member_dn="sabrina.rocha")
    item = r["resultados"][0]
    assert item["status"] == "grupo_primario"
    assert r["success"] is False


def test_campos_de_topo_pais_e_other_attributes_nao_somem(srv):
    r = chamar(srv, "ad_create_user_account", username="pais.x", password="Mudar@12345",
               first_name="Pais", last_name="X", ou="TI", Country="Brasil",
               OtherAttributes={"ipPhone": "123"})
    assert r["success"] is True
    criada = _entrada(srv, f"CN=Pais X,{TI}").atributos
    assert criada["c"] == "BR" and criada["ipPhone"] == "123"


def test_copiar_grupo_privilegiado_recusa_so_esse_grupo(srv):
    """Was a warning after the fact (aviso_privilegiado); now the privileged
    group is not copied at all and the answer names it (upstream 48a965d).
    This group has neither objectSid nor adminCount: the built-in name alone
    must be enough."""
    falso = srv.falso
    dn_adm = f"CN=Domain Admins,CN=Users,{BASE}"
    from .diretorio_falso import grupo
    falso.entradas.append(type(falso.entradas[0])(*grupo("Domain Admins", "Domain Admins",
                                                        f"CN=Users,{BASE}")))
    falso.incluir_membro(dn_adm, SABRINA)
    r = chamar(srv, "ad_create_user_account", username="nova.z", password="Mudar@12345",
               first_name="Nova", last_name="Z", copy_from_user="sabrina.rocha")
    assert r["success"] is True
    nomes = [g["nome"] for g in r["copied_from"]["grupos_privilegiados_recusados"]]
    assert nomes == ["Domain Admins"]
    assert "Domain Admins" not in r["groups"]
    assert "NOT copied" in r["message"]


# ----------------------------------------- 14. new login from another format

@pytest.mark.parametrize("login", ["CN=Joao Pedro,OU=TI,DC=beta,DC=local", "BETA\\joao.pedro",
                                   "joao.pedro@beta.local", "joao pedro"])
def test_login_novo_em_outro_formato_e_recusado(srv, login):
    antes = len(srv.falso.entradas)
    r = chamar(srv, "ad_create_user_account", username=login, password="Mudar@12345",
               first_name="Joao", last_name="Pedro", ou="TI")
    assert r.get("success") is False and "login" in r["error"].lower()
    assert len(srv.falso.entradas) == antes


def test_desligar_para_desativados_e_religar(srv):
    """Control: the sane path still works after all the guards."""
    r = chamar(srv, "ad_disable_user_account_access", username="sabrina.rocha",
               move_to_ou="_DESATIVADOS", remove_from_groups="sim")
    assert r["success"] is True and r["dn"].endswith(DESATIVADOS)
    assert r["groups_remaining"] == []
    r = chamar(srv, "ad_enable_user_account_access", username="sabrina.rocha",
               move_to_ou=FIN_FILIAL)
    assert r["account_enabled"] is True and FILIAL in r["dn"]


# ------------------------------ auditoria da consolidacao (21/09): confirmacao

def test_mover_exige_confirmacao_como_qualquer_escrita(srv):
    """The action=move shortcut skipped _check_write_permission entirely."""
    r = asyncio.run(srv.handle_tools_call({"name": "ad_manage_directory_users", "arguments": {
        "ad_server": "alfa", "action": "move", "username": "sabrina.rocha",
        "move_to_ou": "_DESATIVADOS"}}))
    corpo = json.loads(r["content"][0]["text"])
    assert corpo.get("permitted") is False, corpo
    assert _entrada(srv, SABRINA) is not None


@pytest.mark.parametrize("tool,args", [
    ("ad_manage_directory_groups", {"action": "move", "group_name": "TI Suporte",
                                    "move_to_ou": "_DESATIVADOS"}),
    ("ad_manage_directory_computers", {"action": "move", "computer_name": "FIN-PC01",
                                       "move_to_ou": "_DESATIVADOS"}),
    ("ad_manage_organizational_units", {"action": "move", "ou_dn": "Filial/TI",
                                        "move_to_ou": "_DESATIVADOS"}),
])
def test_toda_acao_de_escrita_passa_pelo_portao(srv, tool, args):
    r = asyncio.run(srv.handle_tools_call({"name": tool,
                                           "arguments": {"ad_server": "alfa", **args}}))
    corpo = json.loads(r["content"][0]["text"])
    assert corpo.get("permitted") is False, corpo
    assert srv.falso.movimentos == []


def test_recusa_de_permissao_nao_vira_sucesso_no_update(srv):
    """The refusal payload has no 'success' key; the guard only looked at that,
    so the move ran and the answer claimed success."""
    r = asyncio.run(srv.handle_tools_call({"name": "ad_manage_directory_users", "arguments": {
        "ad_server": "alfa", "action": "update", "username": "sabrina.rocha",
        "attributes": {"title": "Chefe"}, "move_to_ou": "_DESATIVADOS"}}))
    corpo = json.loads(r["content"][0]["text"])
    assert corpo.get("success") is not True, corpo
    assert srv.falso.movimentos == []
    assert _entrada(srv, SABRINA).atributos.get("title") is None


def test_recusa_de_confirmacao_se_identifica_como_falha(srv):
    """A payload with neither success nor erro reads as "no opinion" to a
    client, and that ambiguity already caused one wrong move."""
    r = asyncio.run(srv.handle_tools_call({"name": "ad_manage_directory_users", "arguments": {
        "ad_server": "alfa", "action": "delete", "username": "sabrina.rocha"}}))
    corpo = json.loads(r["content"][0]["text"])
    assert corpo["success"] is False and corpo["permitted"] is False
    assert corpo["erro"] == "CONFIRMACAO_NECESSARIA"


# ------------------------- invariante: nenhuma action escapa do portao de escrita

@pytest.mark.parametrize("tool,acao", sorted(
    (t, a) for t, acoes in
    __import__("active_directory_mcp.server_fastapi", fromlist=["x"])
    .ActiveDirectoryMCPFastAPI.ACOES.items() for a in acoes))
def test_nenhuma_action_de_escrita_escapa_do_portao(srv, tool, acao):
    """The dispatch is the place a new shortcut would slip through: action=move
    did exactly that (audit 2026-09-21). Every (tool, action) pair, without
    client_confirmation, must refuse and change nothing."""
    identificador = {"ad_manage_directory_users": {"username": "sabrina.rocha"},
                     "ad_manage_directory_groups": {"group_name": "TI Suporte",
                                                    "members": "joao.silva"},
                     "ad_manage_directory_computers": {"computer_name": "FIN-PC01"},
                     "ad_manage_organizational_units": {"ou_dn": "Filial/TI",
                                                        "name": "Nova"}}[tool]
    args = {"ad_server": "alfa", "action": acao, **identificador,
            "move_to_ou": "_DESATIVADOS", "password": "Mudar@12345",
            "first_name": "Novo", "last_name": "Objeto",
            "attributes": {"description": "x"}}
    antes = json.dumps([e.atributos for e in srv.falso.entradas], sort_keys=True, default=str)
    r = json.loads(asyncio.run(srv.handle_tools_call(
        {"name": tool, "arguments": args}))["content"][0]["text"])
    assert r.get("permitted") is False and r.get("success") is False, (tool, acao, r)
    assert json.dumps([e.atributos for e in srv.falso.entradas],
                      sort_keys=True, default=str) == antes
    assert srv.falso.movimentos == [] and srv.falso.escritas == []
