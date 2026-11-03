"""Membership and password changes on privileged targets are refused, not warned.

Ported by hand from upstream alpadalar/ActiveDirectoryMCP 48a965d and closed on
every path this fork has for the same effect. Before the fix (2026-11-02):

* add/remove members on Domain Admins (or any adminCount=1 group) executed;
* reset_password on Administrator, krbtgt or an adminCount=1 account executed;
* create with copy_from_user copied Domain Admins and only WARNED afterwards;
* offboarding (disable + remove_from_groups) and a generic update carrying
  ``member`` or a password were further doors to the same writes.

Privilege is read from the directory (well-known RID in objectSid, adminCount),
so a localized name -- "Admins. do domínio" on a pt-BR DC -- is caught as well
as the English one. The directory is the stateful fake: assertions read what
was WRITTEN, never what was sent.
"""

from types import SimpleNamespace

import pytest

from .diretorio_falso import BASE, TI, grupo, usuario
from .test_fluxos_de_uma_chamada import G_FIN, G_TI, SABRINA, SID, _entrada, chamar

USERS = f"CN=Users,{BASE}"
DA = f"CN=Domain Admins,{USERS}"
DA_PT = f"CN=Admins. do domínio,{USERS}"
SUPORTE_N3 = f"CN=Suporte N3,{TI}"
ADMIN = f"CN=Administrator,{USERS}"
KRBTGT = f"CN=krbtgt,{USERS}"
EX_ADMIN = f"CN=Ex Admin,{TI}"


def _incluir(falso, dn_attrs, **extra):
    dn, attrs = dn_attrs
    attrs.update(extra)
    falso.entradas.append(type(falso.entradas[0])(dn, attrs))
    return dn


@pytest.fixture
def priv(srv):
    falso = srv.falso
    _incluir(falso, grupo("Domain Admins", "Domain Admins", USERS),
             objectSid=f"{SID}-512", adminCount=1)
    # Same RID with the pt-BR name and NO adminCount: the SID alone decides.
    _incluir(falso, grupo("Admins. do domínio", "Admins. do domínio", USERS),
             objectSid=f"{SID}-512")
    _incluir(falso, grupo("Suporte N3", "suporte-n3", TI),
             objectSid=f"{SID}-3101", adminCount=1)
    _incluir(falso, usuario("Administrator", "Administrator", USERS),
             objectSid=f"{SID}-500", adminCount=1, primaryGroupID=513)
    _incluir(falso, usuario("krbtgt", "krbtgt", USERS, ativo=False),
             objectSid=f"{SID}-502", adminCount=1, primaryGroupID=513)
    _incluir(falso, usuario("Ex Admin", "ex.admin", TI),
             objectSid=f"{SID}-3102", adminCount=1, primaryGroupID=513)
    falso.incluir_membro(DA, ADMIN)
    return srv


def _membros(srv, dn):
    return sorted(_entrada(srv, dn).valores("member"))


def _escritas_em(srv, dn):
    alvo = dn.lower()
    return [e for e in srv.falso.escritas if str(e[1]).lower() == alvo]


# -------------------------------------------------------------- group members

@pytest.mark.parametrize("grupo_alvo,dn", [("Domain Admins", DA),
                                           ("Admins. do domínio", DA_PT),
                                           ("suporte-n3", SUPORTE_N3)])
def test_incluir_em_grupo_privilegiado_e_recusado(priv, grupo_alvo, dn):
    antes = _membros(priv, dn)
    r = chamar(priv, "ad_manage_directory_groups", action="add_members",
               group_name=grupo_alvo, members=["sabrina.rocha"])
    assert r.get("erro") == "ALVO_PRIVILEGIADO", r
    assert r["success"] is False
    assert _membros(priv, dn) == antes
    assert _escritas_em(priv, dn) == []


def test_remover_de_domain_admins_e_recusado(priv):
    r = chamar(priv, "ad_manage_directory_groups", action="remove_members",
               group_name="Domain Admins", members=["Administrator"])
    assert r.get("erro") == "ALVO_PRIVILEGIADO", r
    assert ADMIN in _membros(priv, DA)


def test_lote_com_um_grupo_privilegiado_nao_escreve_nada(priv):
    """One refused group refuses the whole call, as an unresolved one does."""
    antes_ti = _membros(priv, G_TI)
    r = chamar(priv, "ad_manage_directory_groups", action="add_members",
               group_name=["ti-suporte", "Domain Admins"], members=["joao.silva"])
    assert r.get("erro") == "ALVO_PRIVILEGIADO", r
    assert _membros(priv, G_TI) == antes_ti
    assert "Domain Admins" in r["mensagem"]


def test_grupo_comum_continua_funcionando(priv):
    r = chamar(priv, "ad_manage_directory_groups", action="add_members",
               group_name="ti-suporte", members=["joao.silva"])
    assert r.get("success") is True, r


def test_update_com_member_e_recusado_em_qualquer_grupo(priv):
    """A generic update replacing 'member' bypassed the membership gate."""
    antes = _membros(priv, G_TI)
    r = chamar(priv, "ad_manage_directory_groups", action="update", group_name="ti-suporte",
               attributes={"member": [SABRINA]})
    assert r.get("success") is False, r
    assert "add_members" in (r.get("mensagem") or r.get("error") or "")
    assert _membros(priv, G_TI) == antes


def test_opt_out_explicito_na_configuracao_libera(priv):
    priv.falso.security_config = SimpleNamespace(protect_privileged_targets=False,
                                                 validate_certificate=True)
    r = chamar(priv, "ad_manage_directory_groups", action="add_members",
               group_name="suporte-n3", members=["joao.silva"])
    assert r.get("success") is True, r


# ------------------------------------------------------------------- passwords

@pytest.mark.parametrize("login,dn", [("Administrator", ADMIN), ("krbtgt", KRBTGT),
                                      ("ex.admin", EX_ADMIN)])
def test_reset_de_senha_em_conta_privilegiada_e_recusado(priv, login, dn):
    r = chamar(priv, "ad_manage_directory_users", action="reset_password",
               username=login, password="Nova@Senha12345")
    assert r.get("erro") == "ALVO_PRIVILEGIADO", r
    assert _escritas_em(priv, dn) == []
    assert "Nova@Senha12345" not in str(r)


def test_update_com_senha_em_conta_privilegiada_e_recusado(priv):
    r = chamar(priv, "ad_manage_directory_users", action="update", username="Administrator",
               attributes={"password": "Nova@Senha12345", "description": "x"})
    assert r.get("erro") == "ALVO_PRIVILEGIADO", r
    assert _escritas_em(priv, ADMIN) == []


@pytest.mark.parametrize("atributo", ["unicodePwd", "userPassword", "UNICODEPWD"])
def test_update_com_atributo_de_senha_e_recusado(priv, atributo):
    """The raw attribute skipped every password check; reset_password is the way."""
    r = chamar(priv, "ad_manage_directory_users", action="update", username="joao.silva",
               attributes={atributo: "Nova@Senha12345"})
    assert r.get("success") is False, r
    assert "reset_password" in (r.get("mensagem") or r.get("error") or "")
    assert not any(e[0] == "modify" for e in _escritas_em(priv, f"CN=João da Silva,{TI}"))


def test_reset_em_conta_comum_continua_funcionando(priv):
    r = chamar(priv, "ad_manage_directory_users", action="reset_password",
               username="joao.silva", password="Nova@Senha12345")
    assert r.get("success") is True, r


# ------------------------------------------------- the paths that only warned

def test_copiar_de_modelo_admin_nao_copia_grupo_privilegiado(priv):
    priv.falso.incluir_membro(DA, SABRINA)
    r = chamar(priv, "ad_manage_directory_users", action="create", username="nova.z",
               password="Mudar@12345", first_name="Nova", last_name="Z",
               copy_from_user="sabrina.rocha")
    assert r.get("success") is True, r
    nova = _entrada(priv, f"CN=Nova Z,{FIN_DA_SABRINA(priv)}")
    grupos = {g.lower() for g in nova.valores("memberOf")}
    assert DA.lower() not in grupos
    assert {G_FIN.lower(), G_TI.lower()} <= grupos
    recusados = r["copied_from"]["grupos_privilegiados_recusados"]
    assert [g["nome"] for g in recusados] == ["Domain Admins"]
    assert "aviso_privilegiado" not in r


def FIN_DA_SABRINA(srv):
    return SABRINA.split(",", 1)[1]


def test_desligamento_de_admin_nao_mexe_em_grupo_privilegiado(priv):
    priv.falso.incluir_membro(DA, SABRINA)
    r = chamar(priv, "ad_manage_directory_users", action="disable", username="sabrina.rocha",
               remove_from_groups=True)
    # Disabling is never blocked: it is the protective half of offboarding.
    assert r.get("success") is True, r
    assert _entrada(priv, SABRINA).atributos["userAccountControl"] == 514
    assert SABRINA in _membros(priv, DA)
    assert SABRINA not in _membros(priv, G_TI)
    assert [g["nome"] for g in r["groups_refused_privileged"]] == ["Domain Admins"]
