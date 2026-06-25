import { FormEvent, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open, save } from "@tauri-apps/plugin-dialog";
import "./App.css";

type VaultItem = {
  id: string;
  systemName: string;
  url: string;
  username: string;
  password: string;
  category: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
};

type VaultFormState = {
  systemName: string;
  url: string;
  username: string;
  password: string;
  category: string;
  notes: string;
};

type VaultResponse = {
  items: VaultItem[];
};

const DEFAULT_AUTO_LOCK_MINUTES = 15;
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30;

function readNumberPreference(key: string, fallback: number) {
  const value = Number(localStorage.getItem(key));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

const emptyForm: VaultFormState = {
  systemName: "",
  url: "",
  username: "",
  password: "",
  category: "",
  notes: "",
};

const appWindow = getCurrentWindow();

function createId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }

  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function generatePassword(length = 24) {
  const charset =
    "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*_-+=?";

  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);

    return Array.from(values, (value) => charset[value % charset.length]).join(
      "",
    );
  }

  return Array.from(
    { length },
    () => charset[Math.floor(Math.random() * charset.length)],
  ).join("");
}

function AppTitlebar() {
  async function minimizeWindow() {
    await appWindow.minimize();
  }

  async function toggleMaximizeWindow() {
    await appWindow.toggleMaximize();
  }

  async function closeWindow() {
    await appWindow.close();
  }

  return (
    <header className="app-titlebar" data-tauri-drag-region>
      <div className="titlebar-brand" data-tauri-drag-region>
        <span className="titlebar-logo" data-tauri-drag-region>
          KP
        </span>
        <span data-tauri-drag-region>KPassword</span>
      </div>

      <div className="window-actions">
        <button type="button" onClick={minimizeWindow} aria-label="Minimizar">
          —
        </button>

        <button
          type="button"
          onClick={toggleMaximizeWindow}
          aria-label="Maximizar ou restaurar"
        >
          □
        </button>

        <button
          type="button"
          className="close-window-button"
          onClick={closeWindow}
          aria-label="Fechar"
        >
          ×
        </button>
      </div>
    </header>
  );
}

export default function App() {
  const [isCheckingVault, setIsCheckingVault] = useState(true);
  const [hasVault, setHasVault] = useState(false);
  const [isUnlocked, setIsUnlocked] = useState(false);

  const [masterPassword, setMasterPassword] = useState("");
  const [confirmMasterPassword, setConfirmMasterPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [appError, setAppError] = useState("");
  const [vaultPath, setVaultPath] = useState("");

  const [items, setItems] = useState<VaultItem[]>([]);
  const [search, setSearch] = useState("");
  const [copiedMessage, setCopiedMessage] = useState("");
  const [visiblePasswords, setVisiblePasswords] = useState<string[]>([]);

  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingItemId, setEditingItemId] = useState<string | null>(null);
  const [form, setForm] = useState<VaultFormState>(emptyForm);

  const [activityVersion, setActivityVersion] = useState(0);

  useEffect(() => {
    async function initializeVaultStatus() {
      try {
        const exists = await invoke<boolean>("vault_exists");
        const path = await invoke<string>("get_vault_path");

        setHasVault(exists);
        setVaultPath(path);
      } catch (error) {
        setAppError(String(error));
      } finally {
        setIsCheckingVault(false);
      }
    }

    initializeVaultStatus();
  }, []);

  async function lockVault() {
    try {
      await invoke("lock_vault");
    } catch {
      // Se já estiver bloqueado no Rust, apenas limpa a interface.
    }

    setIsUnlocked(false);
    setMasterPassword("");
    setConfirmMasterPassword("");
    setAuthError("");
    setVisiblePasswords([]);
    setIsFormOpen(false);
    setEditingItemId(null);
    setCopiedMessage("");
    setItems([]);
  }

  useEffect(() => {
    if (!isUnlocked) return;

    const onActivity = () => {
      setActivityVersion((current) => current + 1);
    };

    const events = ["mousemove", "keydown", "click", "scroll", "touchstart"];

    events.forEach((event) => {
      window.addEventListener(event, onActivity);
    });

    return () => {
      events.forEach((event) => {
        window.removeEventListener(event, onActivity);
      });
    };
  }, [isUnlocked]);

  useEffect(() => {
    if (!isUnlocked) return;

    const timeout = window.setTimeout(() => {
      lockVault();
    }, SESSION_TIMEOUT_MS);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [isUnlocked, activityVersion]);

  const filteredItems = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    if (!normalizedSearch) return items;

    return items.filter((item) => {
      return [
        item.systemName,
        item.url,
        item.username,
        item.category,
        item.notes,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalizedSearch);
    });
  }, [items, search]);

  const categoryCount = useMemo(() => {
    return new Set(items.map((item) => item.category).filter(Boolean)).size;
  }, [items]);

  async function persistItems(nextItems: VaultItem[]) {
    setItems(nextItems);
    await invoke("save_vault", { items: nextItems });
  }

  async function handleExportBackup() {
  setAppError("");

  try {
    const backupPath = await invoke<string>("export_backup");
    setCopiedMessage(`Backup exportado: ${backupPath}`);
  } catch (error) {
    setAppError(String(error));
  }
}

async function handleImportLatestBackup() {
  setAppError("");

  const shouldImport = window.confirm(
    "Deseja restaurar o último backup local? O cofre atual será substituído.",
  );

  if (!shouldImport) return;

  try {
    const backupPath = await invoke<string>("import_latest_backup");
    setCopiedMessage(`Backup restaurado: ${backupPath}`);
    setIsUnlocked(false);
    setItems([]);
    setVisiblePasswords([]);
    setIsFormOpen(false);
  } catch (error) {
    setAppError(String(error));
  }
}

async function handleCopyVaultPath() {
  setAppError("");

  try {
    const path = await invoke<string>("get_vault_path");
    await navigator.clipboard.writeText(path);
    setCopiedMessage("Caminho do cofre copiado.");
  } catch (error) {
    setAppError(String(error));
  }
}

async function handleCopyBackupDir() {
  setAppError("");

  try {
    const path = await invoke<string>("get_backup_dir");
    await navigator.clipboard.writeText(path);
    setCopiedMessage("Pasta de backups copiada.");
  } catch (error) {
    setAppError(String(error));
  }
}

async function handleResetVault() {
  setAppError("");

  const firstConfirm = window.confirm(
    "Isso vai apagar o cofre local deste computador. Faça backup antes. Deseja continuar?",
  );

  if (!firstConfirm) return;

  const secondConfirm = window.confirm(
    "Confirma o reset do cofre? Esta ação não pode ser desfeita sem backup.",
  );

  if (!secondConfirm) return;

  try {
    await invoke("reset_vault");
    setHasVault(false);
    setIsUnlocked(false);
    setItems([]);
    setSearch("");
    setVisiblePasswords([]);
    setMasterPassword("");
    setConfirmMasterPassword("");
    setCopiedMessage("Cofre resetado.");
  } catch (error) {
    setAppError(String(error));
  }
}

  async function handleCreateVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    setAppError("");

    if (masterPassword.trim().length < 8) {
      setAuthError("A senha mestra precisa ter pelo menos 8 caracteres.");
      return;
    }

    if (masterPassword !== confirmMasterPassword) {
      setAuthError("As senhas mestras não conferem.");
      return;
    }

    try {
      const response = await invoke<VaultResponse>("create_vault", {
        masterPassword,
      });

      setItems(response.items);
      setHasVault(true);
      setIsUnlocked(true);
      setMasterPassword("");
      setConfirmMasterPassword("");
    } catch (error) {
      setAuthError(String(error));
    }
  }

  async function handleUnlockVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    setAppError("");

    if (!masterPassword.trim()) {
      setAuthError("Digite a senha mestra para desbloquear o cofre.");
      return;
    }

    try {
      const response = await invoke<VaultResponse>("unlock_vault", {
        masterPassword,
      });

      setItems(response.items);
      setIsUnlocked(true);
      setMasterPassword("");
    } catch (error) {
      setAuthError(String(error));
    }
  }

  function openCreateForm() {
    setForm(emptyForm);
    setEditingItemId(null);
    setIsFormOpen(true);
  }

  function openEditForm(item: VaultItem) {
    setForm({
      systemName: item.systemName,
      url: item.url,
      username: item.username,
      password: item.password,
      category: item.category,
      notes: item.notes,
    });

    setEditingItemId(item.id);
    setIsFormOpen(true);
  }

  function closeForm() {
    setForm(emptyForm);
    setEditingItemId(null);
    setIsFormOpen(false);
  }

  function updateFormField(field: keyof VaultFormState, value: string) {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  }

  async function handleSubmitItem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppError("");

    if (!form.systemName.trim() || !form.username.trim() || !form.password) {
      setAppError("Preencha nome do sistema, usuário e senha.");
      return;
    }

    try {
      if (editingItemId) {
        const nextItems = items.map((item) =>
          item.id === editingItemId
            ? {
                ...item,
                ...form,
                updatedAt: new Date().toISOString(),
              }
            : item,
        );

        await persistItems(nextItems);
        closeForm();
        return;
      }

      const newItem: VaultItem = {
        id: createId(),
        ...form,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      await persistItems([newItem, ...items]);
      closeForm();
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function deleteItem(id: string) {
    const shouldDelete = window.confirm("Deseja excluir esta credencial?");

    if (!shouldDelete) return;

    try {
      const nextItems = items.filter((item) => item.id !== id);
      await persistItems(nextItems);
    } catch (error) {
      setAppError(String(error));
    }
  }

  function togglePasswordVisibility(id: string) {
    setVisiblePasswords((current) =>
      current.includes(id)
        ? current.filter((visibleId) => visibleId !== id)
        : [...current, id],
    );
  }

  async function copyToClipboard(value: string, label: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedMessage(`${label} copiado.`);

      window.setTimeout(() => {
        setCopiedMessage("");
      }, 2500);

      window.setTimeout(async () => {
        try {
          await navigator.clipboard.writeText("");
        } catch {
          // Se o sistema bloquear a limpeza automática, apenas ignora.
        }
      }, CLIPBOARD_CLEAR_MS);
    } catch {
      setCopiedMessage("Não foi possível copiar para a área de transferência.");
    }
  }

  function handleUseGeneratedPassword() {
    setForm((current) => ({
      ...current,
      password: generatePassword(24),
    }));
  }

  if (isCheckingVault) {
    return (
      <div className="app-frame">
        <AppTitlebar />

        <main className="auth-page">
          <section className="auth-card">
            <div className="brand-mark">KP</div>
            <p className="eyebrow">KPassword</p>
            <h1>Verificando cofre</h1>
            <p className="muted">
              Aguarde enquanto o KPassword localiza o cofre deste computador.
            </p>
          </section>
        </main>
      </div>
    );
  }

  if (!hasVault) {
    return (
      <div className="app-frame">
        <AppTitlebar />

        <main className="auth-page">
          <section className="auth-card">
            <div className="brand-mark">KP</div>

            <div>
              <p className="eyebrow">KPassword</p>
              <h1>Criar cofre local</h1>
              <p className="muted">
                O cofre será salvo criptografado neste computador.
              </p>
            </div>

            <form onSubmit={handleCreateVault} className="auth-form">
              <label>
                Senha mestra
                <input
                  type="password"
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  placeholder="Crie uma senha mestra"
                />
              </label>

              <label>
                Confirmar senha mestra
                <input
                  type="password"
                  value={confirmMasterPassword}
                  onChange={(event) =>
                    setConfirmMasterPassword(event.target.value)
                  }
                  placeholder="Repita a senha mestra"
                />
              </label>

              {authError && <p className="error-message">{authError}</p>}
              {appError && <p className="error-message">{appError}</p>}

              <button type="submit" className="primary-button">
                Criar cofre
              </button>
            </form>

            <p className="security-note">
              Arquivo local: {vaultPath || "caminho ainda não localizado"}
            </p>
          </section>
        </main>
      </div>
    );
  }

  if (!isUnlocked) {
    return (
      <div className="app-frame">
        <AppTitlebar />

        <main className="auth-page">
          <section className="auth-card">
            <div className="brand-mark">KP</div>

            <div>
              <p className="eyebrow">KPassword</p>
              <h1>Desbloquear cofre</h1>
              <p className="muted">
                Digite sua senha mestra para descriptografar suas credenciais.
              </p>
            </div>

            <form onSubmit={handleUnlockVault} className="auth-form">
              <label>
                Senha mestra
                <input
                  type="password"
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  placeholder="Digite sua senha mestra"
                />
              </label>

              {authError && <p className="error-message">{authError}</p>}
              {appError && <p className="error-message">{appError}</p>}

              <button type="submit" className="primary-button">
                Desbloquear
              </button>
            </form>

            <p className="security-note">
              Sessão padrão: bloqueio automático após 15 minutos de inatividade.
            </p>
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="app-frame">
      <AppTitlebar />

      <main className="app-shell">
        <aside className="sidebar">
          <div className="sidebar-brand">
            <div className="brand-mark small">KP</div>
            <div>
              <strong>KPassword</strong>
              <span>Cofre local</span>
            </div>
          </div>

          <div className="sidebar-metrics">
            <div className="sidebar-panel">
              <p className="panel-label">Credenciais</p>
              <strong>{items.length}</strong>
            </div>

            <div className="sidebar-panel">
              <p className="panel-label">Categorias</p>
              <strong>{categoryCount}</strong>
            </div>
          </div>

          <div className="sidebar-warning">
            <strong>Cofre ativo</strong>
            <span>Dados salvos localmente em arquivo criptografado.</span>
          </div>

          <div className="sidebar-actions">
            <button type="button" className="ghost-button" onClick={handleExportBackup}>
              Exportar backup
            </button>

            <button
              type="button"
              className="ghost-button"
              onClick={handleImportLatestBackup}
            >
              Restaurar último backup
            </button>

            <button type="button" className="ghost-button" onClick={handleCopyVaultPath}>
              Copiar caminho do cofre
            </button>

            <button type="button" className="ghost-button" onClick={handleCopyBackupDir}>
              Copiar pasta de backups
            </button>

            <button type="button" className="ghost-button" onClick={lockVault}>
              Bloquear cofre
            </button>

            <button type="button" className="danger-sidebar-button" onClick={handleResetVault}>
              Resetar cofre
            </button>
          </div>
        </aside>

        <section className="content">
          <header className="topbar">
            <div>
              <p className="eyebrow">Dashboard</p>
              <h1>Suas credenciais</h1>
            </div>

            <button
              type="button"
              className="primary-button"
              onClick={openCreateForm}
            >
              Adicionar sistema
            </button>
          </header>

          <div className="toolbar">
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Buscar por sistema, usuário, URL ou categoria..."
            />

            {copiedMessage && (
              <span className="copied-message">{copiedMessage}</span>
            )}
          </div>

          {appError && <p className="error-message">{appError}</p>}

          <section className="vault-list">
            {filteredItems.length === 0 ? (
              <div className="empty-state">
                <h2>Nenhuma credencial encontrada</h2>
                <p>Cadastre um sistema ou ajuste sua busca.</p>
              </div>
            ) : (
              filteredItems.map((item) => {
                const isPasswordVisible = visiblePasswords.includes(item.id);

                return (
                  <article className="vault-card" key={item.id}>
                    <div className="vault-card-header">
                      <div>
                        <h2>{item.systemName}</h2>
                        <p>{item.url || "Sem URL cadastrada"}</p>
                      </div>

                      {item.category && (
                        <span className="category-badge">{item.category}</span>
                      )}
                    </div>

                    <div className="credential-grid">
                      <div>
                        <span>Usuário</span>
                        <strong>{item.username}</strong>
                      </div>

                      <div>
                        <span>Senha</span>
                        <strong>
                          {isPasswordVisible ? item.password : "••••••••••••"}
                        </strong>
                      </div>
                    </div>

                    {item.notes && <p className="notes">{item.notes}</p>}

                    <div className="card-actions">
                      <button
                        type="button"
                        onClick={() =>
                          copyToClipboard(item.username, "Usuário")
                        }
                      >
                        Copiar usuário
                      </button>

                      <button
                        type="button"
                        onClick={() => copyToClipboard(item.password, "Senha")}
                      >
                        Copiar senha
                      </button>

                      <button
                        type="button"
                        onClick={() => togglePasswordVisibility(item.id)}
                      >
                        {isPasswordVisible ? "Ocultar" : "Mostrar"}
                      </button>

                      <button type="button" onClick={() => openEditForm(item)}>
                        Editar
                      </button>

                      <button
                        type="button"
                        className="danger-button"
                        onClick={() => deleteItem(item.id)}
                      >
                        Excluir
                      </button>
                    </div>
                  </article>
                );
              })
            )}
          </section>
        </section>

        {isFormOpen && (
          <div className="modal-backdrop">
            <section className="modal">
              <div className="modal-header">
                <div>
                  <p className="eyebrow">
                    {editingItemId ? "Editar" : "Novo sistema"}
                  </p>
                  <h2>
                    {editingItemId
                      ? "Editar credencial"
                      : "Adicionar credencial"}
                  </h2>
                </div>

                <button type="button" className="icon-button" onClick={closeForm}>
                  ×
                </button>
              </div>

              <form onSubmit={handleSubmitItem} className="vault-form">
                <div className="form-grid">
                  <label>
                    Nome do sistema
                    <input
                      value={form.systemName}
                      onChange={(event) =>
                        updateFormField("systemName", event.target.value)
                      }
                      placeholder="Ex: Microsoft 365"
                    />
                  </label>

                  <label>
                    URL
                    <input
                      value={form.url}
                      onChange={(event) =>
                        updateFormField("url", event.target.value)
                      }
                      placeholder="https://..."
                    />
                  </label>

                  <label>
                    Usuário / e-mail
                    <input
                      value={form.username}
                      onChange={(event) =>
                        updateFormField("username", event.target.value)
                      }
                      placeholder="usuario@empresa.com"
                    />
                  </label>

                  <label>
                    Categoria
                    <input
                      value={form.category}
                      onChange={(event) =>
                        updateFormField("category", event.target.value)
                      }
                      placeholder="Ex: Trabalho, Banco, Sistemas"
                    />
                  </label>
                </div>

                <label>
                  Senha
                  <div className="password-row">
                    <input
                      type="text"
                      value={form.password}
                      onChange={(event) =>
                        updateFormField("password", event.target.value)
                      }
                      placeholder="Senha do sistema"
                    />

                    <button
                      type="button"
                      className="secondary-button"
                      onClick={handleUseGeneratedPassword}
                    >
                      Gerar
                    </button>
                  </div>
                </label>

                <label>
                  Observações
                  <textarea
                    value={form.notes}
                    onChange={(event) =>
                      updateFormField("notes", event.target.value)
                    }
                    placeholder="Informações adicionais"
                    rows={3}
                  />
                </label>

                <div className="modal-actions">
                  <button
                    type="button"
                    className="ghost-button"
                    onClick={closeForm}
                  >
                    Cancelar
                  </button>

                  <button type="submit" className="primary-button">
                    {editingItemId ? "Salvar alterações" : "Salvar credencial"}
                  </button>
                </div>
              </form>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}