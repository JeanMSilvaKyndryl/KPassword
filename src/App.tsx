import { FormEvent, MouseEvent, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { open, save } from "@tauri-apps/plugin-dialog";
import appIcon from "./assets/app-icon.png";
import "./App.css";

type VaultHistoryEntry = {
  id: string;
  action: string;
  details: string;
  createdAt: string;
};

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
  isFavorite?: boolean;
  isPinned?: boolean;
  history?: VaultHistoryEntry[];
  passwordExpiresInDays?: number | null;
  passwordUpdatedAt?: string;
};

type VaultFormState = {
  systemName: string;
  url: string;
  username: string;
  password: string;
  category: string;
  notes: string;
  passwordExpiresInDays: string;
};

type VaultResponse = {
  items: VaultItem[];
};

type AppUpdateInfo = {
  version: string;
  currentVersion: string;
  notes?: string | null;
};

type ChangeMasterForm = {
  currentPassword: string;
  newPassword: string;
  confirmNewPassword: string;
  confirmationText: string;
};

type PasswordStrength = {
  label: string;
  score: number;
  description: string;
};

const DEFAULT_AUTO_LOCK_MINUTES = 3;
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30;
const SECURITY_DEFAULTS_VERSION = "0.2.2";
const APP_VERSION = "0.3.1";
const AUTO_UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const AUTO_UPDATE_CHECK_ENABLED_KEY = "kpassword:auto-update-check-enabled";
const LAST_UPDATE_CHECK_KEY = "kpassword:last-update-check-at";
const MASKED_PASSWORD = "••••••••••••";

const emptyForm: VaultFormState = {
  systemName: "",
  url: "",
  username: "",
  password: "",
  category: "",
  notes: "",
  passwordExpiresInDays: "",
};

const emptyChangeMasterForm: ChangeMasterForm = {
  currentPassword: "",
  newPassword: "",
  confirmNewPassword: "",
  confirmationText: "",
};

const appWindow = getCurrentWindow();

function readNumberPreference(key: string, fallback: number) {
  const value = Number(localStorage.getItem(key));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function readBooleanPreference(key: string, fallback: boolean) {
  const value = localStorage.getItem(key);
  if (value === "true") return true;
  if (value === "false") return false;
  return fallback;
}

function formatLastUpdateCheck(value: string) {
  if (!value) return "Nunca";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Nunca";

  return date.toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
  });
}

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

function stopCardClick(event: MouseEvent<HTMLButtonElement>) {
  event.stopPropagation();
}

function normalizeItem(item: VaultItem): VaultItem {
  return {
    ...item,
    isFavorite: Boolean(item.isFavorite),
    isPinned: Boolean(item.isPinned),
    history: Array.isArray(item.history) ? item.history : [],
    passwordExpiresInDays: typeof item.passwordExpiresInDays === "number" && item.passwordExpiresInDays > 0 ? item.passwordExpiresInDays : null,
    passwordUpdatedAt: item.passwordUpdatedAt || item.updatedAt || item.createdAt,
  };
}

function addHistory(
  item: VaultItem,
  action: string,
  details: string,
  when = new Date().toISOString(),
): VaultItem {
  const entry: VaultHistoryEntry = {
    id: createId(),
    action,
    details,
    createdAt: when,
  };

  return {
    ...item,
    history: [entry, ...(item.history ?? [])].slice(0, 50),
  };
}

function getPasswordStrength(password: string): PasswordStrength {
  if (!password) {
    return { label: "Sem senha", score: 0, description: "Digite ou gere uma senha." };
  }

  let score = 0;
  if (password.length >= 10) score += 1;
  if (password.length >= 14) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  if (password.length >= 20) score += 1;

  if (score <= 2) {
    return { label: "Fraca", score, description: "Use mais caracteres, números e símbolos." };
  }

  if (score <= 4) {
    return { label: "Boa", score, description: "Aceitável, mas pode ser mais longa." };
  }

  return { label: "Forte", score, description: "Boa combinação de tamanho e variedade." };
}

function buildChangeSummary(previous: VaultItem, next: VaultFormState) {
  const changes: string[] = [];
  if (previous.systemName !== next.systemName) changes.push("nome do sistema");
  if (previous.url !== next.url) changes.push("URL");
  if (previous.username !== next.username) changes.push("usuário");
  if (previous.password !== next.password) changes.push("senha");
  if (previous.category !== next.category) changes.push("categoria");
  if (previous.notes !== next.notes) changes.push("observações");
  if (String(previous.passwordExpiresInDays ?? "") !== next.passwordExpiresInDays.trim()) changes.push("vencimento da senha");
  return changes.length > 0 ? `Campos alterados: ${changes.join(", ")}.` : "Registro salvo sem alteração de campos.";
}

function parseExpirationDays(value: string): number | null {
  const normalized = value.trim();
  if (!normalized) return null;

  const parsed = Number(normalized);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;

  return Math.floor(parsed);
}

function getMaintenanceStatus(item: VaultItem) {
  const days = item.passwordExpiresInDays;

  if (!days || days <= 0) {
    return {
      label: "Sem vencimento",
      description: "Nenhum prazo de troca definido.",
      tone: "neutral",
      daysRemaining: null as number | null,
      expiresAt: null as Date | null,
      sort: 999999,
    };
  }

  const baseDate = new Date(item.passwordUpdatedAt || item.updatedAt || item.createdAt);
  const expiresAt = new Date(baseDate.getTime() + days * 24 * 60 * 60 * 1000);
  const now = new Date();
  const daysRemaining = Math.ceil((expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

  if (daysRemaining <= 0) {
    return {
      label: "Expirada",
      description: `Venceu em ${expiresAt.toLocaleDateString("pt-BR")}.`,
      tone: "danger",
      daysRemaining,
      expiresAt,
      sort: daysRemaining,
    };
  }

  if (daysRemaining <= 7) {
    return {
      label: `Vence em ${daysRemaining} dia${daysRemaining === 1 ? "" : "s"}`,
      description: `Trocar até ${expiresAt.toLocaleDateString("pt-BR")}.`,
      tone: "warning",
      daysRemaining,
      expiresAt,
      sort: daysRemaining,
    };
  }

  return {
    label: `${daysRemaining} dias restantes`,
    description: `Senha em dia. Vence em ${expiresAt.toLocaleDateString("pt-BR")}.`,
    tone: "ok",
    daysRemaining,
    expiresAt,
    sort: daysRemaining,
  };
}

async function playSecuritySound() {
  if (!readBooleanPreference("kpassword:security-sound-enabled", true)) return;

  try {
    const AudioContextClass = window.AudioContext ||
      (window as typeof window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;

    if (!AudioContextClass) return;

    const context = new AudioContextClass();
    const oscillator = context.createOscillator();
    const gain = context.createGain();

    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(880, context.currentTime);
    oscillator.frequency.exponentialRampToValueAtTime(660, context.currentTime + 0.12);
    gain.gain.setValueAtTime(0.0001, context.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.12, context.currentTime + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, context.currentTime + 0.18);

    oscillator.connect(gain);
    gain.connect(context.destination);
    oscillator.start();
    oscillator.stop(context.currentTime + 0.2);

    window.setTimeout(() => {
      void context.close();
    }, 260);
  } catch {
    // O som é uma camada de alerta. Se o Windows ou o WebView bloquear, a segurança segue funcionando.
  }
}

type AppTitlebarProps = {
  onCloseToTray: () => Promise<void>;
};

function AppTitlebar({ onCloseToTray }: AppTitlebarProps) {
  async function minimizeWindow() {
    await appWindow.minimize();
  }

  async function toggleMaximizeWindow() {
    await appWindow.toggleMaximize();
  }

  return (
    <header className="app-titlebar" data-tauri-drag-region>
      <div className="titlebar-brand" data-tauri-drag-region>
        <span className="titlebar-logo" data-tauri-drag-region>
          <img src={appIcon} alt="" data-tauri-drag-region />
        </span>
        <span data-tauri-drag-region>KPassword</span>
      </div>

      <div className="window-actions">
        <button type="button" onClick={minimizeWindow} aria-label="Minimizar">
          ─
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
          onClick={onCloseToTray}
          aria-label="Enviar para bandeja"
          title="Enviar para a bandeja"
        >
          ×
        </button>
      </div>
    </header>
  );
}

async function showKPasswordNotification(body: string, withSound = true) {
  if (withSound) {
    await playSecuritySound();
  }

  try {
    await invoke("show_kpassword_notification", { body });
  } catch {
    // Notificação é conveniência; se o Windows bloquear, o cofre ainda será protegido.
  }
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
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isMaintenanceOpen, setIsMaintenanceOpen] = useState(false);
  const [isAdvancedSearchOpen, setIsAdvancedSearchOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [settingsMessage, setSettingsMessage] = useState("");
  const [updateMessage, setUpdateMessage] = useState("");
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [isInstallingUpdate, setIsInstallingUpdate] = useState(false);
  const [availableUpdate, setAvailableUpdate] = useState<AppUpdateInfo | null>(null);
  const [automaticUpdateChecksEnabled, setAutomaticUpdateChecksEnabled] = useState(() =>
    readBooleanPreference(AUTO_UPDATE_CHECK_ENABLED_KEY, true),
  );
  const [lastUpdateCheckAt, setLastUpdateCheckAt] = useState(() =>
    localStorage.getItem(LAST_UPDATE_CHECK_KEY) ?? "",
  );
  const [autoLockMinutes, setAutoLockMinutes] = useState(() =>
    readNumberPreference(
      "kpassword:auto-lock-minutes",
      DEFAULT_AUTO_LOCK_MINUTES,
    ),
  );
  const [clipboardClearSeconds, setClipboardClearSeconds] = useState(() =>
    readNumberPreference(
      "kpassword:clipboard-clear-seconds",
      DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    ),
  );
  const [soundEnabled, setSoundEnabled] = useState(() =>
    readBooleanPreference("kpassword:security-sound-enabled", true),
  );
  const [privacyMode, setPrivacyMode] = useState(() =>
    readBooleanPreference("kpassword:privacy-mode", true),
  );
  const [changeMasterForm, setChangeMasterForm] = useState<ChangeMasterForm>(
    emptyChangeMasterForm,
  );
  const [resetConfirmation, setResetConfirmation] = useState("");
  const [activeCategory, setActiveCategory] = useState("Todas");
  const [showOnlyFavorites, setShowOnlyFavorites] = useState(false);
  const [showOnlyPinned, setShowOnlyPinned] = useState(false);
  const [showOnlyWeak, setShowOnlyWeak] = useState(false);
  const [showOnlyDuplicates, setShowOnlyDuplicates] = useState(false);

  const [activityVersion, setActivityVersion] = useState(0);

  function registerSuccessfulUpdateCheck() {
    const checkedAt = new Date().toISOString();
    localStorage.setItem(LAST_UPDATE_CHECK_KEY, checkedAt);
    setLastUpdateCheckAt(checkedAt);
  }

  async function confirmAndInstallUpdate(update: AppUpdateInfo) {
    const notes = update.notes?.trim();
    const confirmation = window.confirm(
      `KPassword ${update.version} disponível.\n\n${notes || "Uma nova versão está pronta para instalação."}\n\nDeseja baixar e instalar agora?`,
    );

    if (!confirmation) {
      setUpdateMessage(`A versão ${update.version} continua disponível para instalar.`);
      return;
    }

    setAppError("");
    setIsInstallingUpdate(true);
    setUpdateMessage("Baixando e validando a atualização assinada...");

    try {
      await invoke("install_kpassword_update");
      setUpdateMessage("Atualização instalada. Reiniciando o KPassword...");
    } catch (error) {
      setAppError(`Não foi possível instalar a atualização: ${String(error)}`);
      setUpdateMessage(`A versão ${update.version} continua disponível.`);
    } finally {
      setIsInstallingUpdate(false);
    }
  }

  async function handleCheckForUpdates() {
    setAppError("");
    setUpdateMessage("Verificando atualizações...");
    setIsCheckingUpdate(true);

    try {
      const update = await invoke<AppUpdateInfo | null>("check_kpassword_update");
      registerSuccessfulUpdateCheck();
      setAvailableUpdate(update);

      if (!update) {
        setUpdateMessage(`O KPassword ${APP_VERSION} já está atualizado.`);
        return;
      }

      setUpdateMessage(`A versão ${update.version} está disponível.`);
      await confirmAndInstallUpdate(update);
    } catch (error) {
      setUpdateMessage("");
      setAppError(`Não foi possível verificar atualizações: ${String(error)}`);
    } finally {
      setIsCheckingUpdate(false);
    }
  }

  useEffect(() => {
    const versionKey = "kpassword:security-defaults-version";

    if (localStorage.getItem(versionKey) !== SECURITY_DEFAULTS_VERSION) {
      localStorage.setItem("kpassword:auto-lock-minutes", String(DEFAULT_AUTO_LOCK_MINUTES));
      localStorage.setItem("kpassword:security-sound-enabled", "true");
      localStorage.setItem("kpassword:privacy-mode", "true");
      localStorage.setItem(versionKey, SECURITY_DEFAULTS_VERSION);
      setAutoLockMinutes(DEFAULT_AUTO_LOCK_MINUTES);
      setSoundEnabled(true);
      setPrivacyMode(true);
    }
  }, []);

  useEffect(() => {
    if (isCheckingVault || !automaticUpdateChecksEnabled) return;

    const previousCheck = Date.parse(lastUpdateCheckAt);
    const checkedRecently = Number.isFinite(previousCheck)
      && Date.now() - previousCheck < AUTO_UPDATE_CHECK_INTERVAL_MS;

    if (checkedRecently) return;

    let cancelled = false;
    const timeout = window.setTimeout(() => {
      void (async () => {
        try {
          const update = await invoke<AppUpdateInfo | null>("check_kpassword_update");
          if (cancelled) return;

          registerSuccessfulUpdateCheck();
          setAvailableUpdate(update);

          if (update) {
            setUpdateMessage(`A versão ${update.version} está disponível para instalar.`);
            void showKPasswordNotification(
              `A versão ${update.version} está disponível. Abra as Configurações para instalar.`,
              false,
            );
          }
        } catch {
          // A verificação automática é silenciosa. A verificação manual continua disponível.
        }
      })();
    }, 1500);

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [isCheckingVault, automaticUpdateChecksEnabled, lastUpdateCheckAt]);

  const selectedItem = useMemo(
    () => items.find((item) => item.id === selectedItemId) ?? null,
    [items, selectedItemId],
  );

  const passwordUsage = useMemo(() => {
    const usage = new Map<string, number>();
    items.forEach((item) => {
      if (!item.password) return;
      usage.set(item.password, (usage.get(item.password) ?? 0) + 1);
    });
    return usage;
  }, [items]);

  const duplicatePasswordCount = useMemo(() => {
    return items.filter((item) => item.password && (passwordUsage.get(item.password) ?? 0) > 1).length;
  }, [items, passwordUsage]);

  const weakPasswordCount = useMemo(() => {
    return items.filter((item) => getPasswordStrength(item.password).score <= 2).length;
  }, [items]);

  const maintenanceItems = useMemo(() => {
    return items
      .map((item) => ({ item, status: getMaintenanceStatus(item) }))
      .sort((a, b) => a.status.sort - b.status.sort || a.item.systemName.localeCompare(b.item.systemName, "pt-BR"));
  }, [items]);

  const expiredCredentialCount = useMemo(() => {
    return maintenanceItems.filter((entry) => entry.status.tone === "danger").length;
  }, [maintenanceItems]);

  const expiringCredentialCount = useMemo(() => {
    return maintenanceItems.filter((entry) => entry.status.tone === "warning").length;
  }, [maintenanceItems]);

  const categories = useMemo(() => {
    return [
      "Todas",
      ...Array.from(new Set(items.map((item) => item.category.trim()).filter(Boolean))).sort((a, b) =>
        a.localeCompare(b, "pt-BR"),
      ),
    ];
  }, [items]);

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

  useEffect(() => {
    if (!privacyMode) return;

    const onBlur = () => {
      setVisiblePasswords([]);
    };

    window.addEventListener("blur", onBlur);
    return () => window.removeEventListener("blur", onBlur);
  }, [privacyMode]);

  async function clearUnlockedState(lockRustSession: boolean) {
    if (lockRustSession) {
      try {
        await invoke("lock_vault");
      } catch {
        // Se o cofre já estiver bloqueado no Rust, apenas limpa a interface.
      }
    }

    setIsUnlocked(false);
    setMasterPassword("");
    setConfirmMasterPassword("");
    setAuthError("");
    setVisiblePasswords([]);
    setIsFormOpen(false);
    setEditingItemId(null);
    setSelectedItemId(null);
    setIsSettingsOpen(false);
    setIsMaintenanceOpen(false);
    setCopiedMessage("");
    setSettingsMessage("");
    setItems([]);
    setForm(emptyForm);
    setChangeMasterForm(emptyChangeMasterForm);
  }

  async function lockVault() {
    await clearUnlockedState(true);
  }

  async function handleCloseToTray() {
    const shouldNotifyLocked = isUnlocked;

    if (isUnlocked) {
      await clearUnlockedState(true);
    }

    await appWindow.hide();
    void showKPasswordNotification(
      shouldNotifyLocked
        ? "O cofre foi bloqueado e o app continua na bandeja."
        : "O KPassword continua em execução na bandeja.",
    );
  }

  async function lockAndHideDueToInactivity() {
    await clearUnlockedState(true);
    await appWindow.hide();
    void showKPasswordNotification(
      "O cofre foi bloqueado por inatividade e enviado para a bandeja.",
    );
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
      lockAndHideDueToInactivity();
    }, autoLockMinutes * 60 * 1000);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [isUnlocked, activityVersion, autoLockMinutes]);

  useEffect(() => {
    if (visiblePasswords.length === 0) return;

    const timeout = window.setTimeout(() => {
      setVisiblePasswords([]);
    }, clipboardClearSeconds * 1000);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [visiblePasswords, clipboardClearSeconds]);

  const filteredItems = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return items
      .filter((item) => {
        if (activeCategory !== "Todas" && item.category !== activeCategory) return false;
        if (showOnlyFavorites && !item.isFavorite) return false;
        if (showOnlyPinned && !item.isPinned) return false;
        if (showOnlyWeak && getPasswordStrength(item.password).score > 2) return false;
        if (showOnlyDuplicates && (passwordUsage.get(item.password) ?? 0) <= 1) return false;

        if (!normalizedSearch) return true;

        return [item.systemName, item.url, item.username, item.category, item.notes]
          .join(" ")
          .toLowerCase()
          .includes(normalizedSearch);
      })
      .sort((a, b) => {
        if (Boolean(a.isPinned) !== Boolean(b.isPinned)) return a.isPinned ? -1 : 1;
        if (Boolean(a.isFavorite) !== Boolean(b.isFavorite)) return a.isFavorite ? -1 : 1;
        return a.systemName.localeCompare(b.systemName, "pt-BR");
      });
  }, [items, activeCategory, showOnlyFavorites, showOnlyPinned, showOnlyWeak, showOnlyDuplicates, passwordUsage, search]);

  async function persistItems(nextItems: VaultItem[], createAutomaticBackup = true) {
    setItems(nextItems);

    if (createAutomaticBackup && hasVault) {
      try {
        await invoke("export_backup");
      } catch {
        // Backup automático não deve impedir salvamento manual do cofre.
      }
    }

    await invoke("save_vault", { items: nextItems });
  }

  function handleSaveSecurityPreferences() {
    localStorage.setItem("kpassword:auto-lock-minutes", String(autoLockMinutes));
    localStorage.setItem(
      "kpassword:clipboard-clear-seconds",
      String(clipboardClearSeconds),
    );
    localStorage.setItem("kpassword:security-sound-enabled", String(soundEnabled));
    localStorage.setItem("kpassword:privacy-mode", String(privacyMode));
    localStorage.setItem(
      AUTO_UPDATE_CHECK_ENABLED_KEY,
      String(automaticUpdateChecksEnabled),
    );
    setSettingsMessage("Configurações de segurança salvas.");
    setAppError("");
  }

  async function handleExportBackupToFile() {
    setAppError("");
    setSettingsMessage("");

    try {
      const selectedPath = await save({
        defaultPath: `kpassword-backup-${new Date().toISOString().slice(0, 10)}.kpass`,
        filters: [
          {
            name: "Backup KPassword",
            extensions: ["kpass"],
          },
        ],
      });

      if (!selectedPath) return;

      const backupPath = await invoke<string>("export_backup_to_path", {
        destinationPath: selectedPath,
      });

      setSettingsMessage(`Backup exportado: ${backupPath}`);
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleImportBackupFromFile() {
    setAppError("");
    setSettingsMessage("");

    try {
      const selectedPath = await open({
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Backup KPassword",
            extensions: ["kpass"],
          },
        ],
      });

      if (!selectedPath || Array.isArray(selectedPath)) return;

      const shouldImport = window.confirm(
        "Deseja restaurar este backup? O cofre atual será substituído e será necessário desbloquear novamente.",
      );

      if (!shouldImport) return;

      try {
        await invoke("export_backup");
      } catch {
        // Backup preventivo antes da importação, se possível.
      }

      const backupPath = await invoke<string>("import_backup_from_path", {
        sourcePath: selectedPath,
      });

      setSettingsMessage(`Backup restaurado: ${backupPath}`);
      await clearUnlockedState(false);
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleExportReport() {
    setAppError("");
    setSettingsMessage("");

    try {
      const selectedPath = await save({
        defaultPath: `kpassword-relatorio-${new Date().toISOString().slice(0, 10)}.json`,
        filters: [
          {
            name: "Relatório KPassword",
            extensions: ["json"],
          },
        ],
      });

      if (!selectedPath) return;

      const report = {
        app: "KPassword",
        version: APP_VERSION,
        generatedAt: new Date().toISOString(),
        summary: {
          credentials: items.length,
          categories: Math.max(categories.length - 1, 0),
          weakPasswords: weakPasswordCount,
          duplicatedPasswords: duplicatePasswordCount,
        },
        items: items.map((item) => ({
          systemName: item.systemName,
          url: item.url,
          username: item.username,
          category: item.category,
          notes: item.notes,
          isFavorite: Boolean(item.isFavorite),
          isPinned: Boolean(item.isPinned),
          strength: getPasswordStrength(item.password).label,
          duplicatedPassword: (passwordUsage.get(item.password) ?? 0) > 1,
          passwordExpiresInDays: item.passwordExpiresInDays ?? null,
          passwordMaintenanceStatus: getMaintenanceStatus(item).label,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt,
        })),
      };

      const savedPath = await invoke<string>("write_report_file", {
        destinationPath: selectedPath,
        content: JSON.stringify(report, null, 2),
      });

      setSettingsMessage(`Relatório exportado sem senhas: ${savedPath}`);
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleChangeMasterPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppError("");
    setSettingsMessage("");

    if (!changeMasterForm.currentPassword.trim()) {
      setAppError("Digite a senha mestra atual.");
      return;
    }

    if (changeMasterForm.newPassword.trim().length < 10) {
      setAppError("A nova senha mestra precisa ter pelo menos 10 caracteres.");
      return;
    }

    if (changeMasterForm.newPassword !== changeMasterForm.confirmNewPassword) {
      setAppError("A confirmação da nova senha mestra não confere.");
      return;
    }

    if (changeMasterForm.confirmationText !== "TROCAR") {
      setAppError("Digite TROCAR no campo de confirmação para alterar a senha mestra.");
      return;
    }

    try {
      try {
        await invoke("export_backup");
      } catch {
        // Backup preventivo antes da troca, se possível.
      }

      await invoke("change_master_password", {
        currentMasterPassword: changeMasterForm.currentPassword,
        newMasterPassword: changeMasterForm.newPassword,
      });

      setChangeMasterForm(emptyChangeMasterForm);
      setSettingsMessage("Senha mestra alterada com sucesso. Um backup preventivo foi tentado antes da troca.");
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleCopyVaultPath() {
    setAppError("");
    setSettingsMessage("");

    try {
      const path = await invoke<string>("get_vault_path");
      await navigator.clipboard.writeText(path);
      setSettingsMessage("Caminho do cofre copiado.");
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleResetVault() {
    setAppError("");
    setSettingsMessage("");

    if (resetConfirmation !== "RESETAR") {
      setAppError("Digite RESETAR no campo de confirmação antes de resetar o cofre.");
      return;
    }

    const confirmed = window.confirm(
      "Confirma resetar o cofre local? Esta ação remove o arquivo do cofre deste computador.",
    );

    if (!confirmed) return;

    try {
      try {
        await invoke("export_backup");
      } catch {
        // Backup preventivo antes do reset, se possível.
      }

      await invoke("reset_vault");
      setHasVault(false);
      await clearUnlockedState(false);
      setSearch("");
      setResetConfirmation("");
      setCopiedMessage("Cofre resetado.");
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function handleCreateVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    setAppError("");

    if (masterPassword.trim().length < 10) {
      setAuthError("A senha mestra precisa ter pelo menos 10 caracteres.");
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

      setItems(response.items.map(normalizeItem));
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

      setItems(response.items.map(normalizeItem));
      setIsUnlocked(true);
      setMasterPassword("");
    } catch (error) {
      setAuthError(String(error));
    }
  }

  function openCreateForm() {
    setForm(emptyForm);
    setEditingItemId(null);
    setSelectedItemId(null);
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
      passwordExpiresInDays: item.passwordExpiresInDays ? String(item.passwordExpiresInDays) : "",
    });

    setEditingItemId(item.id);
    setSelectedItemId(null);
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
        const previousItem = items.find((item) => item.id === editingItemId);
        const now = new Date().toISOString();
        const nextItems = items.map((item) => {
          if (item.id !== editingItemId) return item;

          const expirationDays = parseExpirationDays(form.passwordExpiresInDays);
          const passwordChanged = item.password !== form.password;
          const updatedItem: VaultItem = {
            ...item,
            systemName: form.systemName,
            url: form.url,
            username: form.username,
            password: form.password,
            category: form.category,
            notes: form.notes,
            passwordExpiresInDays: expirationDays,
            passwordUpdatedAt: passwordChanged ? now : item.passwordUpdatedAt || item.updatedAt || item.createdAt,
            updatedAt: now,
          };

          return addHistory(updatedItem, "Editado", previousItem ? buildChangeSummary(previousItem, form) : "Credencial editada.");
        });

        await persistItems(nextItems);
        closeForm();
        return;
      }

      const now = new Date().toISOString();
      const newItem = addHistory(
        {
          id: createId(),
          systemName: form.systemName,
          url: form.url,
          username: form.username,
          password: form.password,
          category: form.category,
          notes: form.notes,
          passwordExpiresInDays: parseExpirationDays(form.passwordExpiresInDays),
          passwordUpdatedAt: now,
          isFavorite: false,
          isPinned: false,
          history: [],
          createdAt: now,
          updatedAt: now,
        },
        "Criado",
        "Credencial criada no cofre.",
        now,
      );

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
      setSelectedItemId(null);
    } catch (error) {
      setAppError(String(error));
    }
  }

  async function toggleFavorite(item: VaultItem) {
    const nextItems = items.map((current) => {
      if (current.id !== item.id) return current;
      const next = { ...current, isFavorite: !current.isFavorite, updatedAt: new Date().toISOString() };
      return addHistory(next, next.isFavorite ? "Favoritado" : "Desfavoritado", next.isFavorite ? "Credencial marcada como favorita." : "Credencial removida dos favoritos.");
    });
    await persistItems(nextItems);
  }

  async function togglePinned(item: VaultItem) {
    const nextItems = items.map((current) => {
      if (current.id !== item.id) return current;
      const next = { ...current, isPinned: !current.isPinned, updatedAt: new Date().toISOString() };
      return addHistory(next, next.isPinned ? "Fixado" : "Desfixado", next.isPinned ? "Credencial fixada no topo." : "Credencial removida do topo.");
    });
    await persistItems(nextItems);
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
      }, clipboardClearSeconds * 1000);
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

  const frame = (content: React.ReactNode) => (
    <div className="app-frame">
      <AppTitlebar onCloseToTray={handleCloseToTray} />
      {content}
    </div>
  );

  if (isCheckingVault) {
    return frame(
      <main className="auth-page">
        <section className="auth-card compact-auth-card">
          <div className="brand-mark">
            <img src={appIcon} alt="KPassword" />
          </div>
          <p className="eyebrow">KPassword</p>
          <h1>Verificando cofre</h1>
          <p className="muted">
            Aguarde enquanto o KPassword localiza o cofre deste computador.
          </p>
        </section>
      </main>,
    );
  }

  if (!hasVault) {
    return frame(
      <main className="auth-page">
        <section className="auth-card">
          <div className="brand-mark">
            <img src={appIcon} alt="KPassword" />
          </div>

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
                autoComplete="off"
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                placeholder="Crie uma senha mestra"
              />
            </label>

            <label>
              Confirmar senha mestra
              <input
                type="password"
                autoComplete="off"
                value={confirmMasterPassword}
                onChange={(event) => setConfirmMasterPassword(event.target.value)}
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
      </main>,
    );
  }

  if (!isUnlocked) {
    return frame(
      <main className="auth-page">
        <section className="auth-card">
          <div className="brand-mark">
            <img src={appIcon} alt="KPassword" />
          </div>

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
                autoComplete="off"
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
            Ao enviar o app para a bandeja, o cofre é bloqueado automaticamente.
          </p>
        </section>
      </main>,
    );
  }

  const formStrength = getPasswordStrength(form.password);

  return (
    <div className="app-frame">
      <AppTitlebar onCloseToTray={handleCloseToTray} />

      <main className={`app-shell ${isSidebarCollapsed ? "sidebar-collapsed" : ""}`}>
        <aside className="sidebar">
          <div className="sidebar-brand">
            <button
              type="button"
              className="brand-mark small sidebar-icon-button"
              onClick={() => setIsSidebarCollapsed((current) => !current)}
              title={isSidebarCollapsed ? "Mostrar menu" : "Ocultar menu"}
            >
              <img src={appIcon} alt="KPassword" />
            </button>
            <div className="sidebar-label">
              <strong>KPassword</strong>
              <span>Cofre local</span>
            </div>
          </div>

          <button
            type="button"
            className="sidebar-toggle-button"
            onClick={() => setIsSidebarCollapsed((current) => !current)}
            title={isSidebarCollapsed ? "Mostrar menu" : "Ocultar menu"}
          >
            {isSidebarCollapsed ? "›" : "‹"}
          </button>

          <div className="sidebar-metrics">
            <div className="sidebar-panel">
              <p className="panel-label">Credenciais</p>
              <strong>{items.length}</strong>
            </div>

            <div className="sidebar-panel compact-panel">
              <p className="panel-label">Alertas</p>
              <strong>{weakPasswordCount + duplicatePasswordCount}</strong>
              <span>{weakPasswordCount} fracas • {duplicatePasswordCount} repetidas</span>
            </div>
          </div>

          <div className="category-filter-list">
            {categories.slice(0, 8).map((category) => (
              <button
                key={category}
                type="button"
                className={category === activeCategory ? "active" : ""}
                onClick={() => setActiveCategory(category)}
              >
                {category}
              </button>
            ))}
          </div>

          <div className="sidebar-warning">
            <strong>Cofre ativo</strong>
            <span>Arquivo local criptografado. Backup automático interno ligado.</span>
          </div>

          <div className="sidebar-actions">
            <button
              type="button"
              className="ghost-button"
              onClick={() => {
                setAppError("");
                setIsMaintenanceOpen(true);
              }}
              title="Manutenção de credenciais"
            >
              <span className="button-icon">⏱</span>
              <span className="sidebar-action-label">Manutenção</span>
            </button>

            <button
              type="button"
              className={`ghost-button ${availableUpdate ? "has-update" : ""}`}
              onClick={() => {
                setSettingsMessage("");
                setAppError("");
                setIsSettingsOpen(true);
              }}
              title="Configurações"
            >
              <span className="button-icon">
                ⚙
                {availableUpdate && <span className="update-available-dot" />}
              </span>
              <span className="sidebar-action-label">Configurações</span>
            </button>

            <button type="button" className="ghost-button" onClick={lockVault} title="Bloquear cofre">
              <span className="button-icon">🔒</span>
              <span className="sidebar-action-label">Bloquear cofre</span>
            </button>
          </div>
        </aside>

        <section className="content">
          <header className="topbar">
            <div>
              <p className="eyebrow">Dashboard</p>
              <h1>Suas credenciais</h1>
            </div>

            <button type="button" className="primary-button" onClick={openCreateForm}>
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

            <button
              type="button"
              className="filter-button"
              onClick={() => setIsAdvancedSearchOpen((current) => !current)}
            >
              Busca avançada
            </button>

            {copiedMessage && <span className="copied-message">{copiedMessage}</span>}
          </div>

          {isAdvancedSearchOpen && (
            <div className="advanced-search-panel">
              <button type="button" className={showOnlyPinned ? "active" : ""} onClick={() => setShowOnlyPinned((current) => !current)}>
                Fixadas
              </button>
              <button type="button" className={showOnlyFavorites ? "active" : ""} onClick={() => setShowOnlyFavorites((current) => !current)}>
                Favoritas
              </button>
              <button type="button" className={showOnlyWeak ? "active" : ""} onClick={() => setShowOnlyWeak((current) => !current)}>
                Senhas fracas
              </button>
              <button type="button" className={showOnlyDuplicates ? "active" : ""} onClick={() => setShowOnlyDuplicates((current) => !current)}>
                Senhas repetidas
              </button>
              <button
                type="button"
                onClick={() => {
                  setActiveCategory("Todas");
                  setShowOnlyFavorites(false);
                  setShowOnlyPinned(false);
                  setShowOnlyWeak(false);
                  setShowOnlyDuplicates(false);
                }}
              >
                Limpar filtros
              </button>
            </div>
          )}

          {appError && <p className="error-message app-error">{appError}</p>}

          <section className="vault-list compact-vault-list">
            {filteredItems.length === 0 ? (
              <div className="empty-state">
                <h2>Nenhuma credencial encontrada</h2>
                <p>Cadastre um sistema ou ajuste sua busca.</p>
              </div>
            ) : (
              filteredItems.map((item) => {
                const strength = getPasswordStrength(item.password);
                const isDuplicate = (passwordUsage.get(item.password) ?? 0) > 1;

                return (
                  <article
                    className="vault-row"
                    key={item.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => setSelectedItemId(item.id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") setSelectedItemId(item.id);
                    }}
                  >
                    <div className="vault-row-main">
                      <h2>
                        {item.isPinned ? "📌 " : ""}{item.isFavorite ? "★ " : ""}{item.systemName}
                      </h2>
                      <p>
                        {item.category || "Sem categoria"}
                        {item.url ? ` • ${item.url}` : ""}
                      </p>
                    </div>

                    <div className="vault-row-secret">
                      <span>Senha</span>
                      <strong>{MASKED_PASSWORD}</strong>
                    </div>

                    <div className="vault-row-security">
                      <span className={`strength-pill strength-${strength.label.toLowerCase()}`}>
                        {strength.label}
                      </span>
                      {isDuplicate && <span className="duplicate-pill">Repetida</span>}
                    </div>

                    <div className="vault-row-actions">
                      <button type="button" onClick={(event) => { stopCardClick(event); void togglePinned(item); }}>
                        {item.isPinned ? "Desfixar" : "Fixar"}
                      </button>
                      <button type="button" onClick={(event) => { stopCardClick(event); void toggleFavorite(item); }}>
                        {item.isFavorite ? "Remover ★" : "Favoritar"}
                      </button>
                      <button type="button" onClick={(event) => { stopCardClick(event); copyToClipboard(item.password, "Senha"); }}>
                        Copiar senha
                      </button>
                      <button type="button" onClick={(event) => { stopCardClick(event); setSelectedItemId(item.id); }}>
                        Detalhes
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
            <section className="modal credential-modal">
              <div className="modal-header">
                <div>
                  <p className="eyebrow">{editingItemId ? "Editar" : "Novo sistema"}</p>
                  <h2>{editingItemId ? "Editar credencial" : "Adicionar credencial"}</h2>
                </div>

                <button type="button" className="icon-button" onClick={closeForm}>×</button>
              </div>

              <form onSubmit={handleSubmitItem} className="vault-form">
                <div className="form-grid">
                  <label>
                    Nome do sistema
                    <input value={form.systemName} onChange={(event) => updateFormField("systemName", event.target.value)} placeholder="Ex: Microsoft 365" />
                  </label>

                  <label>
                    URL
                    <input value={form.url} onChange={(event) => updateFormField("url", event.target.value)} placeholder="https://..." />
                  </label>

                  <label>
                    Usuário / e-mail
                    <input value={form.username} onChange={(event) => updateFormField("username", event.target.value)} placeholder="usuario@empresa.com" />
                  </label>

                  <label>
                    Categoria
                    <input value={form.category} onChange={(event) => updateFormField("category", event.target.value)} placeholder="Ex: Trabalho, Banco, Sistemas" />
                  </label>

                  <label>
                    Em quanto tempo a senha expira?
                    <input
                      type="number"
                      min="1"
                      inputMode="numeric"
                      value={form.passwordExpiresInDays}
                      onChange={(event) => updateFormField("passwordExpiresInDays", event.target.value)}
                      placeholder="Opcional: dias"
                    />
                  </label>
                </div>

                <label>
                  Senha
                  <div className="password-row">
                    <input type="text" value={form.password} onChange={(event) => updateFormField("password", event.target.value)} placeholder="Senha do sistema" />
                    <button type="button" className="secondary-button" onClick={handleUseGeneratedPassword}>Gerar</button>
                  </div>
                </label>

                <div className="password-strength-card">
                  <strong>Força da senha: {formStrength.label}</strong>
                  <span>{formStrength.description}</span>
                </div>

                <label>
                  Observações
                  <textarea value={form.notes} onChange={(event) => updateFormField("notes", event.target.value)} placeholder="Informações adicionais" rows={3} />
                </label>

                <div className="modal-actions">
                  <button type="button" className="ghost-button" onClick={closeForm}>Cancelar</button>
                  <button type="submit" className="primary-button">{editingItemId ? "Salvar alterações" : "Salvar credencial"}</button>
                </div>
              </form>
            </section>
          </div>
        )}

        {selectedItem && (
          <div className="modal-backdrop">
            <section className="modal credential-detail-modal">
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Credencial</p>
                  <h2>{selectedItem.systemName}</h2>
                </div>

                <button type="button" className="icon-button" onClick={() => setSelectedItemId(null)}>×</button>
              </div>

              <div className="credential-detail-body">
                <div className="detail-grid formatted-detail-grid">
                  <div className="detail-field"><span>Sistema</span><strong>{selectedItem.systemName}</strong></div>
                  <div className="detail-field"><span>URL</span><strong>{selectedItem.url || "Sem URL cadastrada"}</strong></div>
                  <div className="detail-field"><span>Usuário</span><strong>{selectedItem.username}</strong></div>
                  <div className="detail-field">
                    <span>Senha</span>
                    <strong>{visiblePasswords.includes(selectedItem.id) ? selectedItem.password : MASKED_PASSWORD}</strong>
                  </div>
                  <div className="detail-field"><span>Categoria</span><strong>{selectedItem.category || "Sem categoria"}</strong></div>
                  <div className="detail-field"><span>Atualizado</span><strong>{new Date(selectedItem.updatedAt).toLocaleString("pt-BR")}</strong></div>
                  <div className="detail-field"><span>Força</span><strong>{getPasswordStrength(selectedItem.password).label}</strong></div>
                  <div className="detail-field"><span>Status</span><strong>{(passwordUsage.get(selectedItem.password) ?? 0) > 1 ? "Senha repetida" : "Senha única neste cofre"}</strong></div>
                  <div className="detail-field wide"><span>Manutenção</span><strong>{getMaintenanceStatus(selectedItem).label}</strong><small>{getMaintenanceStatus(selectedItem).description}</small></div>
                </div>

                <div className="detail-notes detail-card-block">
                  <span>Observações</span>
                  <p>{selectedItem.notes || "Nenhuma observação cadastrada."}</p>
                </div>

              <div className="history-box">
                <span>Histórico local</span>
                {(selectedItem.history ?? []).length === 0 ? (
                  <p>Nenhum histórico registrado para esta credencial.</p>
                ) : (
                  <div className="history-list">
                    {(selectedItem.history ?? []).slice(0, 8).map((entry) => (
                      <div key={entry.id} className="history-entry">
                        <strong>{entry.action}</strong>
                        <span>{new Date(entry.createdAt).toLocaleString("pt-BR")}</span>
                        <p>{entry.details}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              </div>

              <div className="card-actions detail-actions">
                <button type="button" onClick={() => copyToClipboard(selectedItem.username, "Usuário")}>Copiar usuário</button>
                <button type="button" onClick={() => copyToClipboard(selectedItem.password, "Senha")}>Copiar senha</button>
                <button type="button" onClick={() => togglePasswordVisibility(selectedItem.id)}>{visiblePasswords.includes(selectedItem.id) ? "Ocultar" : "Mostrar"}</button>
                <button type="button" onClick={() => togglePinned(selectedItem)}>{selectedItem.isPinned ? "Desfixar" : "Fixar"}</button>
                <button type="button" onClick={() => toggleFavorite(selectedItem)}>{selectedItem.isFavorite ? "Remover favorito" : "Favoritar"}</button>
                <button type="button" onClick={() => openEditForm(selectedItem)}>Editar</button>
                <button type="button" className="danger-button" onClick={() => deleteItem(selectedItem.id)}>Excluir</button>
              </div>
            </section>
          </div>
        )}


        {isMaintenanceOpen && (
          <div className="modal-backdrop maintenance-backdrop">
            <section className="modal maintenance-modal">
              <div className="modal-header">
                <div>
                  <p className="eyebrow">Manutenção</p>
                  <h2>Manutenção de credenciais</h2>
                </div>

                <button type="button" className="icon-button" onClick={() => setIsMaintenanceOpen(false)}>×</button>
              </div>

              <div className="maintenance-summary">
                <div><strong>{expiredCredentialCount}</strong><span>expiradas</span></div>
                <div><strong>{expiringCredentialCount}</strong><span>para expirar</span></div>
                <div><strong>{items.length}</strong><span>credenciais</span></div>
              </div>

              <section className="maintenance-list">
                {maintenanceItems.length === 0 ? (
                  <div className="empty-state compact-empty-state">
                    <h2>Nenhuma credencial cadastrada</h2>
                    <p>Cadastre uma credencial e defina o prazo de expiração quando necessário.</p>
                  </div>
                ) : (
                  maintenanceItems.map(({ item, status }) => (
                    <article className={`maintenance-row maintenance-${status.tone}`} key={item.id}>
                      <div>
                        <h3>{item.systemName}</h3>
                        <p>{item.category || "Sem categoria"}</p>
                      </div>

                      <div className="maintenance-status">
                        <strong>{status.label}</strong>
                        <span>{status.description}</span>
                      </div>

                      <div className="maintenance-actions">
                        <button type="button" onClick={() => { setIsMaintenanceOpen(false); setSelectedItemId(item.id); }}>Detalhes</button>
                        <button type="button" onClick={() => { setIsMaintenanceOpen(false); openEditForm(item); }}>Editar</button>
                      </div>
                    </article>
                  ))
                )}
              </section>
            </section>
          </div>
        )}

        {isSettingsOpen && (
          <div className="modal-backdrop settings-backdrop">
            <section className="modal settings-modal">
              <div className="modal-header">
                <div>
                  <p className="eyebrow">KPassword {APP_VERSION}</p>
                  <h2>Configurações</h2>
                </div>

                <button type="button" className="icon-button" onClick={() => setIsSettingsOpen(false)}>×</button>
              </div>

              <div className="settings-grid">
                <section className="settings-section security-settings-section">
                  <h3>Segurança</h3>

                  <label>
                    Bloquear após inatividade
                    <select value={autoLockMinutes} onChange={(event) => setAutoLockMinutes(Number(event.target.value))}>
                      <option value={3}>3 minutos</option>
                      <option value={5}>5 minutos</option>
                      <option value={10}>10 minutos</option>
                    </select>
                  </label>

                  <label>
                    Limpar área de transferência
                    <select value={clipboardClearSeconds} onChange={(event) => setClipboardClearSeconds(Number(event.target.value))}>
                      <option value={15}>15 segundos</option>
                      <option value={30}>30 segundos</option>
                      <option value={60}>60 segundos</option>
                    </select>
                  </label>

                  <label className="checkbox-label">
                    <input type="checkbox" checked={soundEnabled} onChange={(event) => setSoundEnabled(event.target.checked)} />
                    Tocar som nos alertas de segurança
                  </label>

                  <label className="checkbox-label">
                    <input type="checkbox" checked={privacyMode} onChange={(event) => setPrivacyMode(event.target.checked)} />
                    Modo privacidade: ocultar senhas ao perder foco
                  </label>

                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={automaticUpdateChecksEnabled}
                      onChange={(event) => setAutomaticUpdateChecksEnabled(event.target.checked)}
                    />
                    Verificar atualizações automaticamente
                  </label>

                  <p className="settings-hint">Senhas exibidas voltam a ficar ocultas automaticamente.</p>

                  <button type="button" className="primary-button" onClick={handleSaveSecurityPreferences}>Salvar segurança</button>
                </section>

                <section className="settings-section backup-settings-section">
                  <h3>Backup e relatórios</h3>
                  <button type="button" className="ghost-button" onClick={handleExportBackupToFile}>Exportar backup</button>
                  <button type="button" className="ghost-button" onClick={handleImportBackupFromFile}>Importar backup .kpass</button>
                  <button type="button" className="ghost-button" onClick={handleExportReport}>Exportar relatório sem senhas</button>
                  <button type="button" className="ghost-button" onClick={handleCopyVaultPath}>Copiar caminho do cofre</button>
                  <p className="settings-hint">Alterações no cofre tentam gerar backup interno automaticamente antes de salvar.</p>
                </section>

                <section className="settings-section master-section">
                  <h3>Senha mestra</h3>
                  <form onSubmit={handleChangeMasterPassword} className="change-master-form">
                    <div className="master-password-grid">
                      <label>
                        Senha mestra atual
                        <input type="password" autoComplete="off" value={changeMasterForm.currentPassword} onChange={(event) => setChangeMasterForm((current) => ({ ...current, currentPassword: event.target.value }))} />
                      </label>

                      <label>
                        Nova senha mestra
                        <input type="password" autoComplete="off" value={changeMasterForm.newPassword} onChange={(event) => setChangeMasterForm((current) => ({ ...current, newPassword: event.target.value }))} />
                      </label>

                      <label>
                        Confirmar nova senha mestra
                        <input type="password" autoComplete="off" value={changeMasterForm.confirmNewPassword} onChange={(event) => setChangeMasterForm((current) => ({ ...current, confirmNewPassword: event.target.value }))} />
                      </label>
                    </div>

                    <label>
                      Confirmação de troca
                      <input value={changeMasterForm.confirmationText} onChange={(event) => setChangeMasterForm((current) => ({ ...current, confirmationText: event.target.value }))} placeholder="Digite TROCAR" />
                    </label>

                    <button type="submit" className="primary-button" disabled={changeMasterForm.confirmationText !== "TROCAR"}>Trocar senha mestra</button>
                  </form>
                </section>

                <section className="settings-section danger-zone">
                  <h3>Zona de risco</h3>
                  <p>Resetar o cofre apaga o arquivo local deste computador. Só faça isso depois de exportar um backup externo.</p>

                  <label>
                    Confirmação de reset
                    <input value={resetConfirmation} onChange={(event) => setResetConfirmation(event.target.value)} placeholder="Digite RESETAR" />
                  </label>

                  <button type="button" className="danger-sidebar-button" disabled={resetConfirmation !== "RESETAR"} onClick={handleResetVault}>Resetar cofre local</button>
                </section>

                <section className="settings-section updates-settings-section">
                  <div className="update-heading">
                    <div>
                      <h3>Atualizações do KPassword</h3>
                      <p>Baixe somente versões publicadas e validadas pela assinatura do aplicativo.</p>
                    </div>
                    <span>
                      Versão instalada: {APP_VERSION} • Última verificação: {formatLastUpdateCheck(lastUpdateCheckAt)}
                    </span>
                  </div>

                  <button
                    type="button"
                    className="ghost-button update-check-button"
                    onClick={() => {
                      if (availableUpdate) {
                        void confirmAndInstallUpdate(availableUpdate);
                        return;
                      }

                      void handleCheckForUpdates();
                    }}
                    disabled={isCheckingUpdate || isInstallingUpdate}
                  >
                    {isInstallingUpdate
                      ? "Instalando..."
                      : isCheckingUpdate
                        ? "Verificando..."
                        : availableUpdate
                          ? `Instalar versão ${availableUpdate.version}`
                          : "Verificar atualizações"}
                  </button>

                  {updateMessage && <p className="update-message">{updateMessage}</p>}
                </section>

              </div>

              <div className="settings-footer">
                <p className="about-inline">KPassword {APP_VERSION} • Cofre local sem nuvem. Sem recuperação de senha mestra.</p>
                {settingsMessage && <p className="success-message">{settingsMessage}</p>}
                {appError && <p className="error-message">{appError}</p>}
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}
