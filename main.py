from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from enum import Enum
import hashlib, secrets
import json, os

# =========================
# PAPÉIS / ROLES
# =========================
class Role(str, Enum):
    GERENTE = "gerente"
    SUPERVISOR = "supervisor"
    RH = "rh"                  # RH separado de EMPLOYEE
    EMPLOYEE = "employee"

# =========================
# AUTENTICAÇÃO (HTTP Basic)
# =========================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return secrets.compare_digest(hash_password(plain), hashed)

security = HTTPBasic()

# Usuários de teste (login/senha/role)
_raw_users = [
    {"login": "gerente",     "password": "g1234", "role": Role.GERENTE},
    {"login": "supervisor",  "password": "s1234", "role": Role.SUPERVISOR},
    {"login": "rh",          "password": "r1234", "role": Role.RH},         # RH
    {"login": "funcionario", "password": "f1234", "role": Role.EMPLOYEE},
]

# Mapa: login -> {password_hash, role}
users_db = {
    u["login"]: {"password_hash": hash_password(u["password"]), "role": u["role"]}
    for u in _raw_users
}

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    record = users_db.get(credentials.username)
    if not record or not verify_password(credentials.password, record["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas.",
            headers={"WWW-Authenticate": "Basic"},
        )
    return {"login": credentials.username, "role": record["role"]}

def require_role(*allowed: Role):
    def checker(current = Depends(get_current_user)):
        if current["role"] not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permissão insuficiente."
            )
        return current
    return checker

# =========================
# APP E "BANCO" (JSON)
# =========================
app = FastAPI(title="Cadastro de Funcionários (RBAC)")
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # libera qualquer site (para teste)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ARQUIVO_BANCO = "banco_funcionarios.json"
banco: list[dict] = []
proximo_id: int = 1

def carregar_banco():
    """Carrega o JSON e ajusta proximo_id de forma segura."""
    global banco, proximo_id
    if os.path.exists(ARQUIVO_BANCO):
        with open(ARQUIVO_BANCO, "r", encoding="utf-8") as f:
            banco = json.load(f)
        proximo_id = max((item.get("id", 0) for item in banco), default=0) + 1
    else:
        banco = []
        proximo_id = 1

def salvar_banco():
    with open(ARQUIVO_BANCO, "w", encoding="utf-8") as f:
        json.dump(banco, f, ensure_ascii=False, indent=4)

carregar_banco()

# =========================
# MODELO DE ENTRADA
# =========================
class Funcionario(BaseModel):
    nome: str
    cpf: str
    cargo: str
    setor: str
    data_admissao: str
    salario: float
    endereco: str
    telefone: str
    email: str

# =========================
# ROTAS
# =========================
@app.get("/")
def home():
    return {"ok": True, "msg": "API no ar. Use /docs. Rotas protegidas exigem login (HTTP Basic)."}

@app.get("/sobre")
def sobre():
    return {"info": "Sistema de Testes com autenticação e RBAC (President, Supervisor, HR, Employee)."}

# LISTAR (qualquer autenticado)
@app.get("/funcionarios")
def listar_funcionarios(current = Depends(get_current_user)):
    return banco

# CRIAR (PRESIDENT, HR)
@app.post("/funcionarios/criar", summary="Criar funcionário")
def criar_funcionario(
    dados: Funcionario = Body(...),
    current = Depends(require_role(Role.GERENTE, Role.RH)),
):
    global proximo_id
    # CPF único
    if any(f["cpf"] == dados.cpf for f in banco):
        raise HTTPException(status_code=400, detail="CPF já cadastrado.")

    funcionario = {"id": proximo_id, **dados.model_dump()}
    banco.append(funcionario)
    salvar_banco()
    proximo_id += 1
    return {"ok": True, "mensagem": f"Funcionário {dados.nome} cadastrado com sucesso.", "id": funcionario["id"]}

# ATUALIZAR (PRESIDENT, SUPERVISOR, HR)
@app.put("/funcionarios/{func_id}", summary="Atualizar funcionário")
def atualizar_funcionario(
    func_id: int,
    dados: Funcionario,
    current = Depends(require_role(Role.GERENTE, Role.SUPERVISOR, Role.RH)),
):
    for funcionario in banco:
        if funcionario["id"] == func_id:
            # Se mudar CPF, garantir unicidade
            if dados.cpf != funcionario["cpf"] and any(f["cpf"] == dados.cpf for f in banco):
                raise HTTPException(status_code=400, detail="CPF já cadastrado.")
            funcionario.update(dados.model_dump())
            salvar_banco()
            return {"ok": True, "mensagem": f"Funcionário {func_id} atualizado com sucesso."}
    raise HTTPException(status_code=404, detail="Funcionário não encontrado")

# EXCLUIR (PRESIDENT, HR)
@app.delete("/funcionarios/{func_id}", summary="Excluir funcionário")
def excluir_funcionario(
    func_id: int,
    current = Depends(require_role(Role.GERENTE, Role.RH)),
):
    for i, funcionario in enumerate(banco):
        if funcionario["id"] == func_id:
            banco.pop(i)
            salvar_banco()
            return {"ok": True, "mensagem": f"Funcionário {func_id} excluído com sucesso."}
    raise HTTPException(status_code=404, detail="Funcionário não encontrado")
