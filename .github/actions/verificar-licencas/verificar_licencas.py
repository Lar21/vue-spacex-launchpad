#!/usr/bin/env python3
"""Verifica as licenças das dependências declaradas nos lockfiles de um repositório.

Não instala nada: lê os arquivos de dependência de cada ecossistema e consulta a
licença de cada pacote no deps.dev (PyPI, npm, Cargo, Go, Maven e NuGet), no
hex.pm (Elixir) e no CDN do CocoaPods (iOS). Só usa a biblioteca padrão
(Python 3.11+).

Ecossistemas e arquivos lidos:

- Python: uv.lock, poetry.lock, Pipfile.lock, requirements*.txt e, sem lockfile
  no diretório, pyproject.toml (transitivas resolvidas pelo deps.dev)
- Node: package-lock.json, npm-shrinkwrap.json, yarn.lock (v1 e berry),
  pnpm-lock.yaml e bun.lock
- Rust: Cargo.lock
- Go: go.mod
- Java/Kotlin: pom.xml e build.gradle(.kts) (transitivas pelo deps.dev)
- .NET: packages.lock.json ou, sem ele, *.csproj/*.fsproj (transitivas pelo
  .nuspec de cada pacote)
- Elixir: mix.lock
- iOS: Podfile.lock

Dependências que não vêm do registro público (git, caminho local, workspace,
registro privado) são tratadas como internas e não são consultadas.

Falha (exit 1) quando alguma dependência tem licença proibida sem exceção
aprovada. Licença desconhecida gera aviso, não falha.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

import tomllib

PYPI = "pypi"
NPM = "npm"
CARGO = "cargo"
GO = "go"
MAVEN = "maven"
NUGET = "nuget"
HEX = "hex"
COCOAPODS = "cocoapods"

NOMES_DOS_ECOSSISTEMAS = {
    PYPI: "Python",
    NPM: "Node",
    CARGO: "Rust",
    GO: "Go",
    MAVEN: "Java/Kotlin (Maven)",
    NUGET: ".NET (NuGet)",
    HEX: "Elixir (Hex)",
    COCOAPODS: "iOS (CocoaPods)",
}

DIRETORIOS_IGNORADOS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "Pods",
    ".gradle",
    "__pycache__",
    ".tox",
    "_build",
    "deps",
}

REGISTROS_NPM = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
REGISTROS_CARGO = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)

USER_AGENT = "Lar21-verificar-licencas/1.0 (+https://github.com/Lar21/pontotel)"
TENTATIVAS = 4
TIMEOUT = 20


@dataclass(frozen=True, kw_only=True)
class Dependencia:
    ecossistema: str
    nome: str
    versao: str | None
    arquivo: str
    licenca: str | None = None
    expandir: bool = False


@dataclass(kw_only=True)
class Resultado:
    ecossistema: str
    nome: str
    versao: str | None
    arquivos: set[str] = field(default_factory=set)
    licenca: str | None = None
    observacao: str = ""


@dataclass(kw_only=True)
class Leitura:
    dependencias: list[Dependencia] = field(default_factory=list)
    internas: int = 0
    avisos: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- HTTP


class ErroDeRede(Exception):
    pass


_cache_http: dict[str, object] = {}


def _buscar(url: str, *, json_: bool = True) -> object | None:
    """GET com retentativa. Devolve None em 404 e levanta ErroDeRede no resto."""
    if url in _cache_http:
        return _cache_http[url]
    ultimo_erro: Exception | None = None
    for tentativa in range(TENTATIVAS):
        requisicao = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(requisicao, timeout=TIMEOUT) as resposta:
                corpo = resposta.read().decode("utf-8", errors="replace")
            valor: object = json.loads(corpo) if json_ else corpo
            _cache_http[url] = valor
            return valor
        except urllib.error.HTTPError as erro:
            if 400 <= erro.code < 500 and erro.code not in (408, 429):
                _cache_http[url] = None
                return None
            ultimo_erro = erro
        except (urllib.error.URLError, TimeoutError, ConnectionError) as erro:
            ultimo_erro = erro
        except json.JSONDecodeError:
            _cache_http[url] = None
            return None
        if tentativa < TENTATIVAS - 1:
            time.sleep(2**tentativa)
    raise ErroDeRede(f"{url}: {ultimo_erro}")


def _q(texto: str) -> str:
    return urllib.parse.quote(texto, safe="")


# ----------------------------------------------------------------- normalização


def normalizar_nome(ecossistema: str, nome: str) -> str:
    if ecossistema == PYPI:
        return re.sub(r"[-_.]+", "-", nome).lower()
    if ecossistema in (NPM, GO, CARGO):
        return nome
    return nome.lower()


# Nomes livres (classifiers do PyPI, campos antigos de package.json) → SPDX.
ALIASES = {
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit/x11": "MIT",
    "expat": "MIT",
    "apache 2.0": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license (2.0)": "Apache-2.0",
    "apache2": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "psfl": "PSF-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "the unlicense (unlicense)": "Unlicense",
    "public domain": "LicenseRef-Public-Domain",
    "gplv3": "GPL-3.0",
    "gpl v3": "GPL-3.0",
    "gpl-3": "GPL-3.0",
    "gplv3+": "GPL-3.0-or-later",
    "gnu gpl v3": "GPL-3.0",
    "gnu general public license v3 (gplv3)": "GPL-3.0",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu general public license version 3": "GPL-3.0",
    "agplv3": "AGPL-3.0",
    "agpl-3": "AGPL-3.0",
    "gnu affero general public license v3": "AGPL-3.0",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "lgplv3": "LGPL-3.0",
    "lgpl-3": "LGPL-3.0",
    "lgplv3+": "LGPL-3.0-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gplv2": "GPL-2.0",
    "gpl-2": "GPL-2.0",
    "gnu general public license v2 (gplv2)": "GPL-2.0",
    "lgplv2": "LGPL-2.1",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.1",
}

SEM_LICENCA = {"", "unknown", "non-standard", "noassertion", "none", "unlicensed", "other"}

_PERMISSIVAS = re.compile(
    r"\b(mit|bsd|apache|isc|mpl|mozilla|python software foundation|psf|unlicense|"
    r"cc0|zlib|boost|wtfpl|0bsd|artistic|eclipse|epl|edl|cddl|historical permission|"
    r"bouncy castle|ms-net-library|indiana university)\b",
    re.IGNORECASE,
)


def _base(identificador: str) -> str:
    base = identificador.strip().upper()
    base = ALIASES.get(base.lower(), base).upper()
    for sufixo in ("+", "-ONLY", "-OR-LATER"):
        base = base.removesuffix(sufixo)
    return base


@dataclass(frozen=True)
class _No:
    operador: str  # "ID", "AND", "OR"
    valor: str = ""
    filhos: tuple[_No, ...] = ()


class _ErroDeExpressao(Exception):
    pass


def _tokens(expressao: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", expressao)


def _analisar(expressao: str) -> _No:
    tokens = _tokens(expressao)
    posicao = 0

    def proximo() -> str | None:
        return tokens[posicao] if posicao < len(tokens) else None

    def consumir() -> str:
        nonlocal posicao
        token = tokens[posicao]
        posicao += 1
        return token

    def atomo() -> _No:
        token = proximo()
        if token is None or token == ")" or token.upper() in ("AND", "OR", "WITH"):
            raise _ErroDeExpressao(expressao)
        consumir()
        if token == "(":
            no = ou()
            if proximo() != ")":
                raise _ErroDeExpressao(expressao)
            consumir()
            return no
        if not re.fullmatch(r"[A-Za-z0-9.+:-]+", token):
            raise _ErroDeExpressao(expressao)
        if (proximo() or "").upper() == "WITH":
            consumir()
            if proximo() is None:
                raise _ErroDeExpressao(expressao)
            consumir()
        return _No("ID", token)

    def e() -> _No:
        filhos = [atomo()]
        while (proximo() or "").upper() == "AND":
            consumir()
            filhos.append(atomo())
        return filhos[0] if len(filhos) == 1 else _No("AND", filhos=tuple(filhos))

    def ou() -> _No:
        filhos = [e()]
        while (proximo() or "").upper() == "OR":
            consumir()
            filhos.append(e())
        return filhos[0] if len(filhos) == 1 else _No("OR", filhos=tuple(filhos))

    no = ou()
    if proximo() is not None:
        raise _ErroDeExpressao(expressao)
    return no


def _viola(no: _No, negadas: set[str]) -> bool:
    if no.operador == "ID":
        return _base(no.valor) in negadas
    resultados = [_viola(filho, negadas) for filho in no.filhos]
    return any(resultados) if no.operador == "AND" else all(resultados)


def _texto_livre_para_spdx(texto: str) -> str | None:
    minusculo = texto.lower()
    if "affero" in minusculo or "agpl" in minusculo:
        return "AGPL-3.0" if re.search(r"(v|version\s*)?3", minusculo) else None
    if "lesser" in minusculo or "lgpl" in minusculo:
        return "LGPL-3.0" if re.search(r"(v|version\s*)3", minusculo) else None
    if "general public" in minusculo or re.search(r"\bgpl", minusculo):
        return "GPL-3.0" if re.search(r"(v|version\s*)3", minusculo) else None
    return None


def classificar(licenca: str | None, negadas: set[str]) -> str:
    """Devolve "negada", "permitida" ou "desconhecida".

    Entradas separadas por ";" são as várias licenças declaradas pelo pacote (o
    deps.dev devolve uma por classifier ou campo de metadado) e valem como
    alternativas: basta uma permitida. "A AND B" explícito exige as duas.
    """
    if licenca is None:
        return "desconhecida"
    partes = [parte.strip() for parte in licenca.split(";") if parte.strip()]
    if not partes:
        return "desconhecida"
    estados = [_classificar_uma(parte, negadas) for parte in partes]
    if "permitida" in estados:
        return "permitida"
    if "negada" in estados:
        return "negada"
    return "desconhecida"


def _classificar_uma(licenca: str, negadas: set[str]) -> str:
    texto = licenca.strip().strip("()").strip() if licenca.count("(") == 1 else licenca
    texto = texto.strip()
    if texto.lower() in SEM_LICENCA or texto.upper().startswith("SEE LICENSE"):
        return "desconhecida"
    expressao = ALIASES.get(texto.lower(), texto)
    try:
        arvore = _analisar(expressao)
    except _ErroDeExpressao:
        if re.search(r"\s+OR\s+", texto):
            alternativas = re.split(r"\s+OR\s+", texto)
            return classificar("; ".join(alternativas), negadas)
        convertido = _texto_livre_para_spdx(texto)
        if convertido is not None:
            return "negada" if _base(convertido) in negadas else "permitida"
        if _PERMISSIVAS.search(texto):
            return "permitida"
        return "desconhecida"
    return "negada" if _viola(arvore, negadas) else "permitida"


@dataclass(frozen=True)
class Excecao:
    """Exceção aprovada: `pacote|licenca`.

    O nome aceita glob (`@img/sharp-*`). A licença aprovada sai da lista de
    proibidas só para esse pacote e a expressão é reavaliada: `pacote|LGPL-3.0`
    cobre `Apache-2.0 AND LGPL-3.0-or-later`, mas não `GPL-3.0`. `*` aprova qualquer
    licença.
    """

    nome: str
    licenca: str

    def cobre(self, resultado: Resultado, negadas: set[str]) -> bool:
        padrao = normalizar_nome(PYPI, self.nome)
        if not fnmatch.fnmatchcase(normalizar_nome(PYPI, resultado.nome), padrao):
            return False
        licenca = resultado.licenca or ""
        if self.licenca == "*" or self.licenca.strip() == licenca.strip():
            return True
        restantes = negadas - _bases_da_licenca(self.licenca)
        return classificar(licenca, restantes) != "negada"


def _bases_da_licenca(licenca: str) -> frozenset[str]:
    convertido = _texto_livre_para_spdx(licenca)
    if licenca.lower() in ALIASES:
        licenca = ALIASES[licenca.lower()]
    elif convertido is not None:
        licenca = convertido
    tokens = [
        token
        for token in _tokens(licenca.replace(";", " AND "))
        if token not in ("(", ")") and token.upper() not in ("AND", "OR", "WITH")
    ]
    return frozenset(_base(token) for token in tokens)


def ler_excecoes(texto: str) -> list[Excecao]:
    excecoes = []
    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        if "|" not in linha:
            raise SystemExit(f"Exceção sem o formato pacote|licenca: {linha!r}")
        nome, licenca = linha.split("|", 1)
        excecoes.append(Excecao(nome.strip(), licenca.strip()))
    return excecoes


# ---------------------------------------------------------------------- leitores


def _ler_texto(caminho: str) -> str:
    with open(caminho, encoding="utf-8", errors="replace") as arquivo:
        return arquivo.read()


def _ler_toml(caminho: str) -> dict:
    with open(caminho, "rb") as arquivo:
        return tomllib.load(arquivo)


_REQUISITO = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _requisito_pep508(texto: str) -> tuple[str, str | None] | None:
    """`nome[extra]==1.0; marker` → (nome, "1.0"); sem pino exato → (nome, None)."""
    texto = texto.split(";", 1)[0].strip()
    if not texto or "://" in texto or texto.startswith(("git+", ".", "/")):
        return None
    if " @ " in texto or re.match(r"^[A-Za-z0-9._-]+\s*@", texto):
        return None
    encontrado = _REQUISITO.match(texto)
    if not encontrado:
        return None
    nome, _, especificador = encontrado.groups()
    especificador = especificador.strip().strip("()")
    exato = re.fullmatch(r"===?\s*([A-Za-z0-9._+!-]+)", especificador)
    return nome, exato.group(1) if exato else None


def ler_requirements(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    texto = _ler_texto(caminho).replace("\\\n", " ")
    for linha in texto.splitlines():
        linha = re.sub(r"(^|\s)#.*$", "", linha).strip()
        linha = re.sub(r"\s--hash[= ]\S+", "", linha).strip()
        if not linha:
            continue
        if linha.startswith("-"):
            if linha.startswith(("-e", "--editable")):
                leitura.internas += 1
            continue
        requisito = _requisito_pep508(linha)
        if requisito is None:
            leitura.internas += 1
            continue
        nome, versao = requisito
        leitura.dependencias.append(
            Dependencia(ecossistema=PYPI, nome=nome, versao=versao, arquivo=relativo, expandir=True)
        )
    return leitura


def ler_pyproject(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    dados = _ler_toml(caminho)
    especificacoes: list[str] = []
    projeto = dados.get("project", {})
    especificacoes += projeto.get("dependencies", [])
    for grupo in projeto.get("optional-dependencies", {}).values():
        especificacoes += grupo
    for grupo in dados.get("dependency-groups", {}).values():
        especificacoes += [item for item in grupo if isinstance(item, str)]
    poetry = dados.get("tool", {}).get("poetry", {})
    secoes = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    secoes += [grupo.get("dependencies", {}) for grupo in poetry.get("group", {}).values()]
    for secao in secoes:
        for nome, especificacao in secao.items():
            if nome.lower() == "python":
                continue
            if isinstance(especificacao, dict) and not especificacao.get("version"):
                leitura.internas += 1
                continue
            versao = (
                especificacao.get("version") if isinstance(especificacao, dict) else especificacao
            )
            especificacoes.append(f"{nome}{_poetry_para_pep440(str(versao))}")
    for especificacao in especificacoes:
        requisito = _requisito_pep508(especificacao)
        if requisito is None:
            leitura.internas += 1
            continue
        nome, versao = requisito
        leitura.dependencias.append(
            Dependencia(ecossistema=PYPI, nome=nome, versao=versao, arquivo=relativo, expandir=True)
        )
    return leitura


def _poetry_para_pep440(versao: str) -> str:
    versao = versao.strip()
    if re.fullmatch(r"[0-9][A-Za-z0-9.+!-]*", versao):
        return f"=={versao}"
    return ""


def ler_uv_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    for pacote in _ler_toml(caminho).get("package", []):
        origem = pacote.get("source", {})
        registro = origem.get("registry", "")
        if "pypi.org" not in registro and "files.pythonhosted.org" not in registro:
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(
                ecossistema=PYPI,
                nome=pacote["name"],
                versao=pacote.get("version"),
                arquivo=relativo,
            )
        )
    return leitura


def ler_poetry_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    for pacote in _ler_toml(caminho).get("package", []):
        origem = pacote.get("source")
        if origem and "pypi.org" not in str(origem.get("url", "")):
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(
                ecossistema=PYPI,
                nome=pacote["name"],
                versao=pacote.get("version"),
                arquivo=relativo,
            )
        )
    return leitura


def ler_pipfile_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    dados = json.loads(_ler_texto(caminho))
    for secao in ("default", "develop"):
        for nome, info in dados.get(secao, {}).items():
            versao = str(info.get("version", "")).lstrip("=")
            if not versao or "git" in info or "path" in info or "file" in info:
                leitura.internas += 1
                continue
            leitura.dependencias.append(
                Dependencia(ecossistema=PYPI, nome=nome, versao=versao, arquivo=relativo)
            )
    return leitura


def _licenca_npm(valor: object) -> str | None:
    if isinstance(valor, str):
        return valor
    if isinstance(valor, dict) and isinstance(valor.get("type"), str):
        return valor["type"]
    if isinstance(valor, list):
        tipos = [_licenca_npm(item) for item in valor]
        tipos = [tipo for tipo in tipos if tipo]
        return " OR ".join(tipos) if tipos else None
    return None


def _versao_semver(versao: str) -> bool:
    return bool(re.match(r"^\d+\.\d+", versao))


def ler_package_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    dados = json.loads(_ler_texto(caminho))
    pacotes = dados.get("packages")
    if isinstance(pacotes, dict) and pacotes:
        for chave, info in pacotes.items():
            if "node_modules/" not in chave or info.get("link"):
                continue
            nome = info.get("name") or chave.rsplit("node_modules/", 1)[1]
            versao = str(info.get("version", ""))
            resolvido = str(info.get("resolved", ""))
            if not _versao_semver(versao) or (
                resolvido and not resolvido.startswith(REGISTROS_NPM)
            ):
                leitura.internas += 1
                continue
            leitura.dependencias.append(
                Dependencia(
                    ecossistema=NPM,
                    nome=nome,
                    versao=versao,
                    arquivo=relativo,
                    licenca=_licenca_npm(info.get("license")),
                )
            )
        return leitura

    def percorrer(dependencias: dict) -> None:
        for nome, info in dependencias.items():
            versao = str(info.get("version", ""))
            resolvido = str(info.get("resolved", ""))
            if not _versao_semver(versao) or (
                resolvido and not resolvido.startswith(REGISTROS_NPM)
            ):
                leitura.internas += 1
            else:
                leitura.dependencias.append(
                    Dependencia(ecossistema=NPM, nome=nome, versao=versao, arquivo=relativo)
                )
            percorrer(info.get("dependencies", {}))

    percorrer(dados.get("dependencies", {}))
    return leitura


def _nome_do_especificador_npm(especificador: str) -> str:
    """`pkg@^1` → pkg; `pkg@npm:1.2.3` → pkg; alias `apelido@npm:@escopo/real@^7` → @escopo/real."""
    especificador = especificador.strip().strip('"')
    if "@npm:" in especificador:
        antes, depois = especificador.split("@npm:", 1)
        posicao = depois.rfind("@")
        return depois[:posicao] if posicao > 0 else antes
    posicao = especificador.rfind("@")
    return especificador[:posicao] if posicao > 0 else especificador


def ler_yarn_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    texto = _ler_texto(caminho)
    berry = "__metadata:" in texto
    for bloco in re.split(r"\n(?=\S)", texto):
        linhas = bloco.splitlines()
        if not linhas or linhas[0].startswith(("#", "__metadata")) or not linhas[0].endswith(":"):
            continue
        cabecalho = linhas[0][:-1]
        campos: dict[str, str] = {}
        for linha in linhas[1:]:
            encontrado = re.match(r'^  ([A-Za-z]+):? "?([^"]*)"?\s*$', linha)
            if encontrado:
                campos.setdefault(encontrado.group(1), encontrado.group(2))
        versao = campos.get("version", "")
        if berry:
            resolucao = campos.get("resolution", "")
            nome = _nome_do_especificador_npm(resolucao)
            if "@npm:" not in resolucao or not _versao_semver(versao):
                leitura.internas += 1
                continue
        else:
            primeiro = cabecalho.split(",")[0].strip().strip('"')
            nome = _nome_do_especificador_npm(primeiro)
            resolvido = campos.get("resolved", "")
            if not _versao_semver(versao) or (
                resolvido and not resolvido.startswith(REGISTROS_NPM)
            ):
                leitura.internas += 1
                continue
        leitura.dependencias.append(
            Dependencia(ecossistema=NPM, nome=nome, versao=versao, arquivo=relativo)
        )
    return leitura


def ler_pnpm_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    dentro = False
    for linha in _ler_texto(caminho).splitlines():
        if not linha.strip():
            continue
        if not linha.startswith(" "):
            dentro = linha.rstrip() == "packages:"
            continue
        if not dentro:
            continue
        encontrado = re.match(r"^  (['\"]?)(/?[^\s'\"]+)\1:\s*$", linha)
        if not encontrado:
            continue
        chave = encontrado.group(2).lstrip("/").split("(", 1)[0]
        par = re.match(r"^(@?[^@]+)@(.+)$", chave)
        if par:
            nome, versao = par.groups()
        elif "/" in chave:
            nome, versao = chave.rsplit("/", 1)
            versao = versao.split("_", 1)[0]
        else:
            continue
        if not _versao_semver(versao):
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(ecossistema=NPM, nome=nome, versao=versao, arquivo=relativo)
        )
    return leitura


def ler_bun_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    texto = re.sub(r",(\s*[}\]])", r"\1", _ler_texto(caminho))
    for identificador in json.loads(texto).get("packages", {}).values():
        if not isinstance(identificador, list) or not identificador:
            continue
        especificador = str(identificador[0])
        nome = _nome_do_especificador_npm(especificador)
        versao = especificador[len(nome) + 1 :]
        if not _versao_semver(versao):
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(ecossistema=NPM, nome=nome, versao=versao, arquivo=relativo)
        )
    return leitura


def ler_package_json(caminho: str, relativo: str) -> Leitura:
    """package.json sem lockfile: dependências diretas; as transitivas vêm do deps.dev."""
    leitura = Leitura()
    dados = json.loads(_ler_texto(caminho))
    for secao in ("dependencies", "devDependencies", "optionalDependencies"):
        secao_dados = dados.get(secao) or {}
        for nome, especificacao in secao_dados.items() if isinstance(secao_dados, dict) else ():
            especificacao = str(especificacao).strip()
            if especificacao.startswith("npm:"):
                nome = _nome_do_especificador_npm(f"{nome}@{especificacao}")
                especificacao = especificacao.rsplit("@", 1)[-1]
            externa = re.match(
                r"^(workspace:|file:|link:|portal:|git|github:|https?:|\.|/)", especificacao
            )
            if externa or re.fullmatch(r"[\w.-]+/[\w.-]+(#.*)?", especificacao):
                leitura.internas += 1
                continue
            exata = re.fullmatch(r"=?v?(\d+\.\d+\.\d+[\w.+-]*)", especificacao)
            leitura.dependencias.append(
                Dependencia(
                    ecossistema=NPM,
                    nome=nome,
                    versao=exata.group(1) if exata else None,
                    arquivo=relativo,
                    expandir=True,
                )
            )
    return leitura


def ler_cargo_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    for pacote in _ler_toml(caminho).get("package", []):
        if not str(pacote.get("source", "")).startswith(REGISTROS_CARGO):
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(
                ecossistema=CARGO,
                nome=pacote["name"],
                versao=pacote.get("version"),
                arquivo=relativo,
            )
        )
    return leitura


def ler_go_mod(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    dentro = False
    for linha in _ler_texto(caminho).splitlines():
        linha = linha.split("//", 1)[0].strip()
        if linha.startswith("require ("):
            dentro = True
            continue
        if dentro and linha == ")":
            dentro = False
            continue
        if linha.startswith("require "):
            linha = linha[len("require ") :].strip()
        elif not dentro:
            continue
        partes = linha.split()
        if len(partes) >= 2:
            leitura.dependencias.append(
                Dependencia(ecossistema=GO, nome=partes[0], versao=partes[1], arquivo=relativo)
            )
    return leitura


def _sem_namespace(raiz: ET.Element) -> ET.Element:
    for elemento in raiz.iter():
        if isinstance(elemento.tag, str) and "}" in elemento.tag:
            elemento.tag = elemento.tag.split("}", 1)[1]
    return raiz


def _pom(caminho: str) -> ET.Element | None:
    try:
        return _sem_namespace(ET.parse(caminho).getroot())
    except ET.ParseError:
        return None


def _modulos_maven(raiz_do_repo: str, poms: list[str]) -> set[tuple[str, str]]:
    modulos = set()
    for caminho in poms:
        pom = _pom(os.path.join(raiz_do_repo, caminho))
        if pom is None:
            continue
        grupo = pom.findtext("groupId") or pom.findtext("parent/groupId") or ""
        modulos.add((grupo.strip(), (pom.findtext("artifactId") or "").strip()))
    return modulos


def ler_pom(caminho: str, relativo: str, modulos: set[tuple[str, str]]) -> Leitura:
    leitura = Leitura()
    cadeia: list[ET.Element] = []
    atual: str | None = caminho
    while atual and os.path.isfile(atual) and len(cadeia) < 10:
        pom = _pom(atual)
        if pom is None:
            break
        cadeia.append(pom)
        relativo_do_pai = pom.findtext("parent/relativePath")
        if pom.find("parent") is None:
            break
        proximo = os.path.normpath(
            os.path.join(os.path.dirname(atual), relativo_do_pai or "../pom.xml")
        )
        if os.path.isdir(proximo):
            proximo = os.path.join(proximo, "pom.xml")
        atual = proximo if proximo != atual else None
    if not cadeia:
        leitura.avisos.append(f"{relativo}: pom.xml inválido")
        return leitura

    propriedades: dict[str, str] = {}
    gerenciadas: dict[tuple[str, str], str] = {}
    for pom in reversed(cadeia):
        for propriedade in pom.findall("properties/*"):
            propriedades[str(propriedade.tag)] = (propriedade.text or "").strip()
        versao = pom.findtext("version") or pom.findtext("parent/version")
        if versao:
            propriedades["project.version"] = versao.strip()
        for dependencia in pom.findall("dependencyManagement/dependencies/dependency"):
            chave = (
                (dependencia.findtext("groupId") or "").strip(),
                (dependencia.findtext("artifactId") or "").strip(),
            )
            if dependencia.findtext("version"):
                gerenciadas[chave] = dependencia.findtext("version", "").strip()

    def resolver(valor: str) -> str:
        for _ in range(5):
            novo = re.sub(
                r"\$\{([^}]+)\}", lambda m: propriedades.get(m.group(1), m.group(0)), valor
            )
            if novo == valor:
                break
            valor = novo
        return valor

    for dependencia in cadeia[0].findall("dependencies/dependency"):
        grupo = resolver((dependencia.findtext("groupId") or "").strip())
        artefato = resolver((dependencia.findtext("artifactId") or "").strip())
        escopo = (dependencia.findtext("scope") or "").strip()
        if escopo in ("system", "import") or (grupo, artefato) in modulos:
            leitura.internas += 1
            continue
        versao = dependencia.findtext("version") or gerenciadas.get((grupo, artefato), "")
        versao = resolver(versao.strip())
        if "${" in versao or not versao or versao.startswith(("[", "(")):
            versao = ""
        leitura.dependencias.append(
            Dependencia(
                ecossistema=MAVEN,
                nome=f"{grupo}:{artefato}",
                versao=versao or None,
                arquivo=relativo,
                expandir=True,
            )
        )
    return leitura


_GRADLE = re.compile(
    r"\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|annotationProcessor|classpath|"
    r"testImplementation|androidTestImplementation|debugImplementation|releaseImplementation|"
    r"coreLibraryDesugaring|compile)\s*\(?\s*[\"']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)"
    r"(?::([^\"'@]+))?(?:@[a-z]+)?[\"']"
)


def ler_gradle(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    for grupo, artefato, versao in _GRADLE.findall(_ler_texto(caminho)):
        versao = versao.strip()
        if "$" in versao or "+" in versao or versao.startswith(("[", "(")) or not versao:
            versao = ""
        leitura.dependencias.append(
            Dependencia(
                ecossistema=MAVEN,
                nome=f"{grupo}:{artefato}",
                versao=versao or None,
                arquivo=relativo,
                expandir=True,
            )
        )
    return leitura


def ler_packages_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    for alvo in json.loads(_ler_texto(caminho)).get("dependencies", {}).values():
        for nome, info in alvo.items():
            if info.get("type") == "Project" or not info.get("resolved"):
                leitura.internas += 1
                continue
            leitura.dependencias.append(
                Dependencia(ecossistema=NUGET, nome=nome, versao=info["resolved"], arquivo=relativo)
            )
    return leitura


def _versoes_centrais(diretorio: str, raiz_do_repo: str) -> dict[str, str]:
    versoes: dict[str, str] = {}
    atual = diretorio
    while True:
        props = os.path.join(atual, "Directory.Packages.props")
        if os.path.isfile(props):
            raiz = _pom(props)
            if raiz is not None:
                for item in raiz.iter("PackageVersion"):
                    if item.get("Include") and item.get("Version"):
                        versoes.setdefault(item.get("Include", "").lower(), item.get("Version", ""))
        if (
            os.path.abspath(atual) == os.path.abspath(raiz_do_repo)
            or os.path.dirname(atual) == atual
        ):
            return versoes
        atual = os.path.dirname(atual)


def ler_csproj(caminho: str, relativo: str, raiz_do_repo: str) -> Leitura:
    leitura = Leitura()
    projeto = _pom(caminho)
    if projeto is None:
        leitura.avisos.append(f"{relativo}: projeto .NET inválido")
        return leitura
    centrais = _versoes_centrais(os.path.dirname(caminho), raiz_do_repo)
    for referencia in projeto.iter("PackageReference"):
        nome = referencia.get("Include") or referencia.get("Update")
        if not nome:
            continue
        versao = (
            referencia.get("Version")
            or referencia.findtext("Version")
            or centrais.get(nome.lower())
        )
        versao = _limite_inferior_nuget(versao or "")
        leitura.dependencias.append(
            Dependencia(
                ecossistema=NUGET, nome=nome, versao=versao, arquivo=relativo, expandir=True
            )
        )
    return leitura


def ler_mix_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    texto = _ler_texto(caminho)
    for nome, versao in re.findall(r'\{:hex,\s*:"?([A-Za-z0-9_]+)"?,\s*"([^"]+)"', texto):
        leitura.dependencias.append(
            Dependencia(ecossistema=HEX, nome=nome, versao=versao, arquivo=relativo)
        )
    leitura.internas += len(re.findall(r"\{:(?:git|path),", texto))
    return leitura


def ler_podfile_lock(caminho: str, relativo: str) -> Leitura:
    leitura = Leitura()
    secao = ""
    pods: dict[str, str] = {}
    externos: set[str] = set()
    for linha in _ler_texto(caminho).splitlines():
        if linha and not linha.startswith(" "):
            secao = linha.rstrip(":")
            continue
        if secao == "PODS":
            encontrado = re.match(r'^  - "?([^\s"(]+)\s*\(([^)]+)\)"?:?\s*$', linha)
            if encontrado:
                pods.setdefault(encontrado.group(1).split("/")[0], encontrado.group(2))
        elif secao in ("EXTERNAL SOURCES", "CHECKOUT OPTIONS"):
            encontrado = re.match(r'^  "?([^\s":]+)"?:\s*$', linha)
            if encontrado:
                externos.add(encontrado.group(1).split("/")[0])
    for nome, versao in sorted(pods.items()):
        if nome in externos:
            leitura.internas += 1
            continue
        leitura.dependencias.append(
            Dependencia(ecossistema=COCOAPODS, nome=nome, versao=versao, arquivo=relativo)
        )
    return leitura


# ----------------------------------------------------------------- descoberta


@dataclass(frozen=True, kw_only=True)
class ArquivoDeDependencia:
    relativo: str
    tipo: str


_PADROES = [
    ("uv.lock", "uv.lock"),
    ("poetry.lock", "poetry.lock"),
    ("Pipfile.lock", "Pipfile.lock"),
    ("pyproject.toml", "pyproject.toml"),
    ("package-lock.json", "package-lock.json"),
    ("npm-shrinkwrap.json", "package-lock.json"),
    ("yarn.lock", "yarn.lock"),
    ("pnpm-lock.yaml", "pnpm-lock.yaml"),
    ("bun.lock", "bun.lock"),
    ("bun.lockb", "bun.lockb"),
    ("Cargo.lock", "Cargo.lock"),
    ("go.mod", "go.mod"),
    ("pom.xml", "pom.xml"),
    ("build.gradle", "build.gradle"),
    ("build.gradle.kts", "build.gradle"),
    ("packages.lock.json", "packages.lock.json"),
    ("mix.lock", "mix.lock"),
    ("Podfile.lock", "Podfile.lock"),
]


LOCKFILES_NODE = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
}


def descobrir(raiz: str, ignorar: list[str]) -> list[ArquivoDeDependencia]:
    encontrados: list[ArquivoDeDependencia] = []
    # Diretórios com lockfile Node: um package.json nele ou abaixo (workspace) já está coberto.
    com_lock_node: set[str] = set()
    for diretorio, subdiretorios, arquivos in os.walk(raiz):
        subdiretorios[:] = sorted(d for d in subdiretorios if d not in DIRETORIOS_IGNORADOS)
        nomes = set(arquivos)
        if LOCKFILES_NODE & nomes:
            com_lock_node.add(os.path.abspath(diretorio))
        coberto_por_lock_node = any(
            os.path.abspath(diretorio) == d or os.path.abspath(diretorio).startswith(d + os.sep)
            for d in com_lock_node
        )
        tem_lock_python = bool({"uv.lock", "poetry.lock", "Pipfile.lock"} & nomes)
        tem_lock_nuget = "packages.lock.json" in nomes
        for nome in sorted(arquivos):
            relativo = os.path.relpath(os.path.join(diretorio, nome), raiz)
            if _ignorado(relativo, ignorar):
                continue
            tipo = dict(_PADROES).get(nome)
            if tipo is None and re.fullmatch(r"requirements[^/]*\.txt", nome):
                tipo = "requirements"
            if tipo is None and nome.endswith((".csproj", ".fsproj")) and not tem_lock_nuget:
                tipo = "csproj"
            if tipo == "pyproject.toml" and tem_lock_python:
                continue
            if nome == "package.json" and not coberto_por_lock_node:
                tipo = "package.json"
            if tipo is not None:
                encontrados.append(ArquivoDeDependencia(relativo=relativo, tipo=tipo))
    return encontrados


def _ignorado(relativo: str, padroes: list[str]) -> bool:
    for padrao in padroes:
        padrao = padrao.strip().strip("/")
        if not padrao:
            continue
        padrao = os.path.normpath(padrao)
        if (
            fnmatch.fnmatch(relativo, padrao)
            or relativo.startswith(padrao + "/")
            or relativo == padrao
        ):
            return True
    return False


def ler_arquivo(
    raiz: str, arquivo: ArquivoDeDependencia, modulos_maven: set[tuple[str, str]]
) -> Leitura:
    caminho = os.path.join(raiz, arquivo.relativo)
    relativo = arquivo.relativo
    leitores = {
        "uv.lock": ler_uv_lock,
        "poetry.lock": ler_poetry_lock,
        "Pipfile.lock": ler_pipfile_lock,
        "pyproject.toml": ler_pyproject,
        "requirements": ler_requirements,
        "package-lock.json": ler_package_lock,
        "yarn.lock": ler_yarn_lock,
        "pnpm-lock.yaml": ler_pnpm_lock,
        "bun.lock": ler_bun_lock,
        "package.json": ler_package_json,
        "Cargo.lock": ler_cargo_lock,
        "go.mod": ler_go_mod,
        "build.gradle": ler_gradle,
        "packages.lock.json": ler_packages_lock,
        "mix.lock": ler_mix_lock,
        "Podfile.lock": ler_podfile_lock,
    }
    try:
        if arquivo.tipo == "bun.lockb":
            return Leitura(avisos=[f"{relativo}: bun.lockb é binário; gere o bun.lock em texto"])
        if arquivo.tipo == "pom.xml":
            return ler_pom(caminho, relativo, modulos_maven)
        if arquivo.tipo == "csproj":
            return ler_csproj(caminho, relativo, raiz)
        return leitores[arquivo.tipo](caminho, relativo)
    except (ValueError, KeyError, tomllib.TOMLDecodeError, ET.ParseError) as erro:
        return Leitura(avisos=[f"{relativo}: não foi possível ler ({erro})"])


# ------------------------------------------------------------------- consultas

SISTEMAS_DEPS_DEV = {
    PYPI: "pypi",
    NPM: "npm",
    CARGO: "cargo",
    GO: "go",
    MAVEN: "maven",
    NUGET: "nuget",
}


def _deps_dev_pacote(ecossistema: str, nome: str) -> str:
    return f"https://api.deps.dev/v3/systems/{SISTEMAS_DEPS_DEV[ecossistema]}/packages/{_q(nome)}"


def _versao_padrao(ecossistema: str, nome: str) -> str | None:
    if ecossistema not in SISTEMAS_DEPS_DEV:
        return None
    dados = _buscar(_deps_dev_pacote(ecossistema, nome))
    if not isinstance(dados, dict):
        return None
    versoes = dados.get("versions", [])
    for versao in versoes:
        if versao.get("isDefault"):
            return versao["versionKey"]["version"]
    return versoes[-1]["versionKey"]["version"] if versoes else None


def _licenca_deps_dev(ecossistema: str, nome: str, versao: str) -> str | None:
    url = f"{_deps_dev_pacote(ecossistema, nome)}/versions/{_q(versao)}"
    dados = _buscar(url)
    if not isinstance(dados, dict):
        return None
    licencas = [licenca for licenca in dados.get("licenses", []) if licenca]
    return "; ".join(licencas) if licencas else None


def _licenca_pypi(nome: str, versao: str) -> str | None:
    dados = _buscar(f"https://pypi.org/pypi/{_q(nome)}/{_q(versao)}/json")
    if not isinstance(dados, dict):
        return None
    info = dados.get("info", {})
    if info.get("license_expression"):
        return info["license_expression"]
    classificadores = [
        classificador.split("::")[-1].strip()
        for classificador in info.get("classifiers", [])
        if classificador.startswith("License ::") and classificador.count("::") >= 2
    ]
    classificadores = [c for c in classificadores if c.lower() not in ("osi approved",)]
    if classificadores:
        return " OR ".join(ALIASES.get(c.lower(), c) for c in classificadores)
    licenca = (info.get("license") or "").strip()
    return licenca if licenca and len(licenca) < 80 else None


def _licenca_npm_registro(nome: str, versao: str) -> str | None:
    dados = _buscar(f"https://registry.npmjs.org/{nome.replace('/', '%2F')}/{_q(versao)}")
    return (
        _licenca_npm(dados.get("license") or dados.get("licenses"))
        if isinstance(dados, dict)
        else None
    )


def _licenca_crates(nome: str, versao: str) -> str | None:
    dados = _buscar(f"https://crates.io/api/v1/crates/{_q(nome)}/{_q(versao)}")
    return dados.get("version", {}).get("license") if isinstance(dados, dict) else None


def _nuspec(nome: str, versao: str) -> ET.Element | None:
    url = f"https://api.nuget.org/v3-flatcontainer/{nome.lower()}/{versao.lower()}/{nome.lower()}.nuspec"
    texto = _buscar(url, json_=False)
    if not isinstance(texto, str):
        return None
    try:
        return _sem_namespace(ET.fromstring(texto.encode("utf-8")))
    except ET.ParseError:
        return None


def _licenca_nuget(nome: str, versao: str) -> str | None:
    nuspec = _nuspec(nome, _normalizar_versao_nuget(versao))
    if nuspec is None:
        return None
    licenca = nuspec.find("metadata/license")
    if licenca is not None and licenca.get("type") == "expression" and licenca.text:
        return licenca.text.strip()
    url = (nuspec.findtext("metadata/licenseUrl") or "").strip().lower()
    url = re.sub(r"^https?://", "", url).rstrip("/")
    return LICENCAS_POR_URL_NUGET.get(url)


def _licenca_maven(nome: str, versao: str) -> str | None:
    """Licença declarada no POM do Maven Central (sobe até 3 POMs pai)."""
    grupo, _, artefato = nome.partition(":")
    for _ in range(4):
        url = (
            f"https://repo1.maven.org/maven2/{grupo.replace('.', '/')}/{artefato}/{versao}/"
            f"{artefato}-{versao}.pom"
        )
        texto = _buscar(url, json_=False)
        if not isinstance(texto, str):
            return None
        try:
            pom = _sem_namespace(ET.fromstring(texto.encode("utf-8")))
        except ET.ParseError:
            return None
        nomes = [
            (licenca.findtext("name") or licenca.findtext("url") or "").strip()
            for licenca in pom.findall("licenses/license")
        ]
        nomes = [n for n in nomes if n]
        if nomes:
            return " OR ".join(ALIASES.get(n.lower(), n) for n in nomes)
        pai = pom.find("parent")
        if pai is None:
            return None
        grupo = (pai.findtext("groupId") or "").strip()
        artefato = (pai.findtext("artifactId") or "").strip()
        versao = (pai.findtext("version") or "").strip()
    return None


# licenseUrl de pacotes NuGet antigos, sem expressão SPDX.
LICENCAS_POR_URL_NUGET = {
    "go.microsoft.com/fwlink/?linkid=329770": "LicenseRef-MS-NET-Library",
    "dotnet.microsoft.com/en/dotnet_library_license.htm": "LicenseRef-MS-NET-Library",
    "github.com/dotnet/corefx/blob/master/license.txt": "MIT",
    "raw.githubusercontent.com/dotnet/corefx/master/license.txt": "MIT",
    "opensource.org/licenses/mit": "MIT",
    "licenses.nuget.org/mit": "MIT",
    "www.apache.org/licenses/license-2.0": "Apache-2.0",
    "licenses.nuget.org/apache-2.0": "Apache-2.0",
}


def _licenca_hex(nome: str) -> str | None:
    dados = _buscar(f"https://hex.pm/api/packages/{_q(nome)}")
    if not isinstance(dados, dict):
        return None
    licencas = dados.get("meta", {}).get("licenses") or []
    return " OR ".join(licencas) if licencas else None


def _licenca_cocoapods(nome: str, versao: str) -> str | None:
    fragmento = hashlib.md5(nome.encode()).hexdigest()
    url = (
        f"https://cdn.cocoapods.org/Specs/{fragmento[0]}/{fragmento[1]}/{fragmento[2]}/"
        f"{_q(nome)}/{_q(versao)}/{_q(nome)}.podspec.json"
    )
    dados = _buscar(url)
    if not isinstance(dados, dict):
        return None
    licenca = dados.get("license")
    if isinstance(licenca, dict):
        licenca = licenca.get("type")
    return licenca.strip() if isinstance(licenca, str) and licenca.strip() else None


def consultar_licenca(ecossistema: str, nome: str, versao: str | None) -> tuple[str | None, str]:
    """Licença do pacote e uma observação (vazia quando veio da versão exata)."""
    observacao = ""
    if versao is None:
        versao = _versao_padrao(ecossistema, nome)
        observacao = "versão não fixada; usada a versão padrão do registro"
        if versao is None and ecossistema not in (HEX, COCOAPODS):
            return None, "pacote não encontrado no registro"
    licenca: str | None = None
    if ecossistema in SISTEMAS_DEPS_DEV and versao:
        # O registro de origem cobre o deps.dev fora do ar e o pacote sem SPDX lá.
        alternativa = {
            PYPI: _licenca_pypi,
            NPM: _licenca_npm_registro,
            CARGO: _licenca_crates,
            MAVEN: _licenca_maven,
            NUGET: _licenca_nuget,
        }.get(ecossistema)
        try:
            licenca = _licenca_deps_dev(ecossistema, nome, versao)
        except ErroDeRede:
            if alternativa is None:
                raise
        if licenca in (None, "non-standard") and alternativa is not None:
            licenca = alternativa(nome, versao) or licenca
        if licenca is None:
            padrao = _versao_padrao(ecossistema, nome)
            if padrao and padrao != versao:
                licenca = _licenca_deps_dev(ecossistema, nome, padrao)
                if licenca:
                    observacao = f"versão {versao} sem dados; usada a licença da {padrao}"
    elif ecossistema == HEX:
        licenca = _licenca_hex(nome)
    elif ecossistema == COCOAPODS and versao:
        licenca = _licenca_cocoapods(nome, versao)
    return licenca, observacao


# ---------------------------------------------------------- dependências transitivas


def _transitivas_deps_dev(ecossistema: str, nome: str, versao: str) -> list[tuple[str, str]]:
    url = f"{_deps_dev_pacote(ecossistema, nome)}/versions/{_q(versao)}:dependencies"
    dados = _buscar(url)
    if not isinstance(dados, dict):
        return []
    return [
        (no["versionKey"]["name"], no["versionKey"]["version"])
        for no in dados.get("nodes", [])
        if no.get("relation") != "SELF"
    ]


def _normalizar_versao_nuget(versao: str) -> str:
    versao = versao.split("+", 1)[0]
    principal, _, sufixo = versao.partition("-")
    partes = [str(int(parte)) if parte.isdigit() else parte for parte in principal.split(".")]
    while len(partes) < 3:
        partes.append("0")
    if len(partes) == 4 and partes[3] == "0":
        partes = partes[:3]
    return ".".join(partes) + (f"-{sufixo}" if sufixo else "")


def _limite_inferior_nuget(intervalo: str) -> str | None:
    intervalo = intervalo.strip()
    if not intervalo or "$(" in intervalo or "*" in intervalo:
        return None
    if intervalo[0] in "[(":
        inferior = intervalo[1:].split(",", 1)[0].strip().rstrip("])")
        return inferior or None
    return intervalo


def _transitivas_nuget(nome: str, versao: str, limite: int = 400) -> list[tuple[str, str]]:
    vistos: set[tuple[str, str]] = set()
    fila = [(nome, versao)]
    encontrados: list[tuple[str, str]] = []
    while fila and len(vistos) < limite:
        atual = fila.pop()
        chave = (atual[0].lower(), _normalizar_versao_nuget(atual[1]))
        if chave in vistos:
            continue
        vistos.add(chave)
        nuspec = _nuspec(*chave)
        if nuspec is None:
            continue
        for dependencia in nuspec.iter("dependency"):
            filho = dependencia.get("id")
            versao_filho = _limite_inferior_nuget(dependencia.get("version", ""))
            if filho and versao_filho:
                encontrados.append((filho, versao_filho))
                fila.append((filho, versao_filho))
    return encontrados


def expandir(dependencia: Dependencia) -> list[Dependencia]:
    versao = dependencia.versao or _versao_padrao(dependencia.ecossistema, dependencia.nome)
    if not versao:
        return []
    if dependencia.ecossistema == NUGET:
        pares = _transitivas_nuget(dependencia.nome, versao)
    elif dependencia.ecossistema in (PYPI, MAVEN, NPM, CARGO):
        pares = _transitivas_deps_dev(dependencia.ecossistema, dependencia.nome, versao)
    else:
        pares = []
    return [
        Dependencia(
            ecossistema=dependencia.ecossistema,
            nome=nome,
            versao=versao_filho,
            arquivo=f"{dependencia.arquivo} (transitiva de {dependencia.nome})",
        )
        for nome, versao_filho in pares
    ]


# ------------------------------------------------------------------------ main


def _paralelo(funcao, itens, trabalhadores: int):
    with concurrent.futures.ThreadPoolExecutor(max_workers=trabalhadores) as executor:
        return list(executor.map(funcao, itens))


def verificar(
    raiz: str,
    *,
    negadas: set[str],
    excecoes: list[Excecao],
    ignorar: list[str],
    trabalhadores: int = 8,
) -> tuple[list[Resultado], list[str], int, list[str], list[ArquivoDeDependencia]]:
    """Resultados, avisos, nº de internas, falhas de consulta e arquivos lidos.

    Consulta em paralelo e repete em série o que falhou por rede. O que ainda falhar
    volta em `falhas`: dependência não consultada não pode passar como verificada.
    """
    arquivos = descobrir(raiz, ignorar)
    poms = [arquivo.relativo for arquivo in arquivos if arquivo.tipo == "pom.xml"]
    modulos = _modulos_maven(raiz, poms)
    avisos: list[str] = []
    internas = 0
    diretas: list[Dependencia] = []
    for arquivo in arquivos:
        leitura = ler_arquivo(raiz, arquivo, modulos)
        diretas += leitura.dependencias
        internas += leitura.internas
        avisos += leitura.avisos

    falhas: dict[str, str] = {}

    def expandir_seguro(dependencia: Dependencia) -> list[Dependencia] | None:
        try:
            transitivas = expandir(dependencia)
        except ErroDeRede as erro:
            falhas[f"transitivas de {dependencia.nome}"] = str(erro)
            return None
        falhas.pop(f"transitivas de {dependencia.nome}", None)
        return transitivas

    a_expandir = list(
        {
            (d.ecossistema, normalizar_nome(d.ecossistema, d.nome), d.versao): d
            for d in diretas
            if d.expandir
        }.values()
    )
    pendentes = []
    for dependencia, transitivas in zip(
        a_expandir, _paralelo(expandir_seguro, a_expandir, trabalhadores), strict=True
    ):
        if transitivas is None:
            pendentes.append(dependencia)
        else:
            diretas += transitivas
    for transitivas in _paralelo(expandir_seguro, pendentes, 1):
        diretas += transitivas or []

    resultados: dict[tuple[str, str, str | None], Resultado] = {}
    for dependencia in diretas:
        chave = (
            dependencia.ecossistema,
            normalizar_nome(dependencia.ecossistema, dependencia.nome),
            dependencia.versao,
        )
        resultado = resultados.setdefault(
            chave,
            Resultado(
                ecossistema=dependencia.ecossistema,
                nome=dependencia.nome,
                versao=dependencia.versao,
            ),
        )
        resultado.arquivos.add(dependencia.arquivo)
        if dependencia.licenca and not resultado.licenca:
            resultado.licenca = dependencia.licenca

    def consultar(resultado: Resultado) -> bool:
        if resultado.licenca and classificar(resultado.licenca, negadas) != "desconhecida":
            return True
        rotulo = _rotulo(resultado)
        try:
            licenca, observacao = consultar_licenca(
                resultado.ecossistema, resultado.nome, resultado.versao
            )
        except ErroDeRede as erro:
            falhas[rotulo] = str(erro)
            resultado.observacao = "falha ao consultar"
            return False
        falhas.pop(rotulo, None)
        resultado.licenca = licenca or resultado.licenca
        resultado.observacao = observacao
        return True

    todos = list(resultados.values())
    consultados = _paralelo(consultar, todos, trabalhadores)
    _paralelo(consultar, [r for r, ok in zip(todos, consultados, strict=True) if not ok], 1)
    falhas_finais = [f"{chave}: {erro}" for chave, erro in sorted(falhas.items())]
    return todos, avisos, internas, falhas_finais, arquivos


def _rotulo(resultado: Resultado) -> str:
    versao = f"@{resultado.versao}" if resultado.versao else ""
    return f"{resultado.nome}{versao}"


def main(argumentos: list[str] | None = None) -> int:
    analisador = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    analisador.add_argument("--caminho", default=".")
    analisador.add_argument("--negadas", default="GPL-3.0,AGPL-3.0,LGPL-3.0")
    analisador.add_argument("--excecoes", default="", help="uma por linha: pacote|licenca")
    analisador.add_argument(
        "--ignorar", default="", help="globs, um por linha, relativos ao caminho"
    )
    analisador.add_argument("--resumo", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    opcoes = analisador.parse_args(argumentos)

    negadas = {_base(item) for item in opcoes.negadas.split(",") if item.strip()}
    excecoes = ler_excecoes(opcoes.excecoes)
    ignorar = [linha for linha in opcoes.ignorar.splitlines() if linha.strip()]
    anotar = os.environ.get("GITHUB_ACTIONS") == "true"

    resultados, avisos, internas, falhas, arquivos = verificar(
        opcoes.caminho, negadas=negadas, excecoes=excecoes, ignorar=ignorar
    )

    print("📄 Arquivos de dependência encontrados:")
    for arquivo in arquivos:
        print(f"- {arquivo.relativo}")
    if not arquivos:
        print("- nenhum")

    proibidas: list[Resultado] = []
    aprovadas: list[tuple[Resultado, Excecao]] = []
    desconhecidas: list[Resultado] = []
    for ecossistema, nome_do_ecossistema in NOMES_DOS_ECOSSISTEMAS.items():
        do_ecossistema = sorted(
            (r for r in resultados if r.ecossistema == ecossistema), key=lambda r: r.nome.lower()
        )
        if not do_ecossistema:
            continue
        if anotar:
            print(f"::group::📚 Dependências {nome_do_ecossistema} ({len(do_ecossistema)})")
        else:
            print(f"📚 Dependências {nome_do_ecossistema} ({len(do_ecossistema)}):")
        for resultado in do_ecossistema:
            observacao = f" ({resultado.observacao})" if resultado.observacao else ""
            print(f"- {_rotulo(resultado)}: {resultado.licenca or 'desconhecida'}{observacao}")
            estado = classificar(resultado.licenca, negadas)
            if estado == "negada":
                excecao = next((e for e in excecoes if e.cobre(resultado, negadas)), None)
                if excecao:
                    aprovadas.append((resultado, excecao))
                else:
                    proibidas.append(resultado)
            elif estado == "desconhecida":
                desconhecidas.append(resultado)
        if anotar:
            print("::endgroup::")

    print(f"🔒 Dependências internas ou fora do registro público (não consultadas): {internas}")
    for aviso in avisos:
        print(f"::warning::{aviso}" if anotar else f"⚠️ {aviso}")
    if desconhecidas:
        print(f"⚠️ {len(desconhecidas)} dependência(s) com licença desconhecida (não bloqueia):")
        for resultado in desconhecidas:
            print(f"- {_rotulo(resultado)} [{resultado.ecossistema}]")
    for resultado, excecao in aprovadas:
        print(
            f"⚠️ Exceção aprovada aplicada: {excecao.nome}|{excecao.licenca} ({_rotulo(resultado)})"
        )
    for resultado in proibidas:
        origem = ", ".join(sorted(resultado.arquivos))
        mensagem = (
            f"Licença proibida em dependência {NOMES_DOS_ECOSSISTEMAS[resultado.ecossistema]}"
            f" sem exceção aprovada: {resultado.nome}|{resultado.licenca} ({_rotulo(resultado)} em {origem})"
        )
        print(f"::error title=Licença proibida::{mensagem}" if anotar else f"❌ {mensagem}")

    if opcoes.resumo:
        _escrever_resumo(opcoes.resumo, resultados, proibidas, aprovadas, desconhecidas, arquivos)

    if falhas:
        print(f"🚫 {len(falhas)} consulta(s) falharam mesmo depois de repetir; rode o job de novo:")
        for falha in falhas:
            print(f"::error title=Falha ao consultar licença::{falha}" if anotar else f"- {falha}")
    if proibidas:
        print(f"🚫 {len(proibidas)} dependência(s) com licença proibida.")
        print("   Troque a dependência ou registre a exceção aprovada no input")
        print("   allowed_package_licenses, no formato pacote|licenca.")
        return 1
    if falhas:
        return 2
    print("✅ Nenhuma licença proibida encontrada.")
    return 0


def _escrever_resumo(
    caminho: str,
    resultados: list[Resultado],
    proibidas: list[Resultado],
    aprovadas: list[tuple[Resultado, Excecao]],
    desconhecidas: list[Resultado],
    arquivos: list[ArquivoDeDependencia],
) -> None:
    linhas = ["## Licenças das dependências", ""]
    linhas.append("| Ecossistema | Dependências |")
    linhas.append("|---|---|")
    for ecossistema, nome in NOMES_DOS_ECOSSISTEMAS.items():
        quantidade = sum(1 for r in resultados if r.ecossistema == ecossistema)
        if quantidade:
            linhas.append(f"| {nome} | {quantidade} |")
    linhas.append("")
    linhas.append(f"Arquivos lidos: {', '.join(f'`{a.relativo}`' for a in arquivos) or 'nenhum'}")
    linhas.append("")
    if proibidas:
        linhas += [
            "### ❌ Licenças proibidas",
            "",
            "| Pacote | Licença | Arquivo |",
            "|---|---|---|",
        ]
        for resultado in proibidas:
            origem = ", ".join(sorted(resultado.arquivos))
            linhas.append(f"| `{_rotulo(resultado)}` | {resultado.licenca} | {origem} |")
        linhas.append("")
    if aprovadas:
        linhas += ["### ⚠️ Exceções aplicadas", ""]
        linhas += [f"- `{_rotulo(r)}`: {e.nome}\\|{e.licenca}" for r, e in aprovadas]
        linhas.append("")
    if desconhecidas:
        linhas += [f"<details><summary>Licença desconhecida ({len(desconhecidas)})</summary>", ""]
        linhas += [f"- `{_rotulo(r)}` ({r.ecossistema})" for r in desconhecidas]
        linhas += ["", "</details>", ""]
    if not proibidas:
        linhas.append("✅ Nenhuma licença proibida encontrada.")
    with open(caminho, "a", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(linhas) + "\n")


if __name__ == "__main__":
    sys.exit(main())
