use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use zeroize::Zeroize;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_updater::UpdaterExt;

const VAULT_FILE_NAME: &str = "vault.kpass";
const BACKUP_DIR_NAME: &str = "backups";
const VAULT_VERSION: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;

#[derive(Default)]
struct VaultSession {
    key: Mutex<Option<[u8; KEY_LENGTH]>>,
}


#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct VaultHistoryEntry {
    id: String,
    action: String,
    details: String,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct VaultItem {
    id: String,
    system_name: String,
    url: String,
    username: String,
    password: String,
    category: String,
    notes: String,
    created_at: String,
    updated_at: String,
    #[serde(default)]
    is_favorite: bool,
    #[serde(default)]
    is_pinned: bool,
    #[serde(default)]
    history: Vec<VaultHistoryEntry>,
    #[serde(default)]
    password_expires_in_days: Option<u32>,
    #[serde(default)]
    password_updated_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultPayload {
    items: Vec<VaultItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultResponse {
    items: Vec<VaultItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedVaultFile {
    version: u8,
    kdf: KdfParams,
    cipher: String,
    salt: String,
    nonce: String,
    data: String,
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("Não foi possível localizar AppData: {error}"))?;

    fs::create_dir_all(&app_data_dir)
        .map_err(|error| format!("Não foi possível criar a pasta do KPassword: {error}"))?;

    Ok(app_data_dir)
}

fn vault_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app_data_dir(app)?.join(VAULT_FILE_NAME))
}

fn backup_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app_data_dir(app)?.join(BACKUP_DIR_NAME);

    fs::create_dir_all(&dir)
        .map_err(|error| format!("Não foi possível criar a pasta de backups: {error}"))?;

    Ok(dir)
}

fn backup_file_name() -> Result<String, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("Erro ao gerar timestamp do backup: {error}"))?
        .as_secs();

    Ok(format!("kpassword-backup-{timestamp}.kpass"))
}

fn kpass_file_is_structurally_valid(path: &PathBuf) -> bool {
    if !path.exists() || !path.is_file() {
        return false;
    }

    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };

    let Ok(file) = serde_json::from_str::<EncryptedVaultFile>(&content) else {
        return false;
    };

    file.version == VAULT_VERSION
        && file.cipher == "aes-256-gcm"
        && !file.salt.trim().is_empty()
        && !file.nonce.trim().is_empty()
        && !file.data.trim().is_empty()
}

fn collect_kpass_files_from_dir(dir: PathBuf, paths: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_kpass = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("kpass"))
            .unwrap_or(false);

        if is_kpass {
            paths.push(path);
        }
    }
}

fn legacy_kpass_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Ok(current_dir) = app_data_dir(app) {
        collect_kpass_files_from_dir(current_dir.join(BACKUP_DIR_NAME), &mut paths);
    }

    if let Some(app_data) = std::env::var_os("APPDATA") {
        let legacy_dir = PathBuf::from(app_data).join("KPassword");
        paths.push(legacy_dir.join(VAULT_FILE_NAME));
        collect_kpass_files_from_dir(legacy_dir.join(BACKUP_DIR_NAME), &mut paths);
    }

    paths
}

fn migrate_legacy_vault_if_needed(app: &AppHandle) -> Result<Option<String>, String> {
    let active_vault = vault_path(app)?;
    let active_len = active_vault.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    let active_is_valid = kpass_file_is_structurally_valid(&active_vault);

    let mut candidates = legacy_kpass_candidates(app)
        .into_iter()
        .filter(|path| path != &active_vault)
        .filter(|path| kpass_file_is_structurally_valid(path))
        .filter_map(|path| {
            let metadata = path.metadata().ok()?;
            let len = metadata.len();
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            Some((path, len, modified))
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| right.1.cmp(&left.1)));

    let Some((candidate, candidate_len, _)) = candidates.into_iter().next() else {
        return Ok(None);
    };

    let should_migrate = !active_vault.exists()
        || !active_is_valid
        || (active_len < 400 && candidate_len > active_len);

    if !should_migrate {
        return Ok(None);
    }

    let migration_dir = app_data_dir(app)?.join("migration-backups");
    fs::create_dir_all(&migration_dir)
        .map_err(|error| format!("Não foi possível criar backup de migração: {error}"))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("Erro ao registrar migração: {error}"))?
        .as_secs();

    if active_vault.exists() {
        let before_path = migration_dir.join(format!("vault-before-migration-{timestamp}.kpass"));
        let _ = fs::copy(&active_vault, before_path);
    }

    let migrated_copy = migration_dir.join(format!("vault-migrated-from-legacy-{timestamp}.kpass"));
    let _ = fs::copy(&candidate, &migrated_copy);

    fs::copy(&candidate, &active_vault)
        .map_err(|error| format!("Não foi possível migrar o cofre antigo: {error}"))?;

    Ok(Some(candidate.to_string_lossy().to_string()))
}

fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH], String> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LENGTH),
    )
    .map_err(|error| format!("Parâmetros de criptografia inválidos: {error}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LENGTH];

    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|error| format!("Erro ao derivar chave do cofre: {error}"))?;

    Ok(key)
}

fn encrypt_payload(
    payload: &VaultPayload,
    key: &[u8; KEY_LENGTH],
    salt: &[u8],
) -> Result<EncryptedVaultFile, String> {
    let mut plaintext = serde_json::to_vec(payload)
        .map_err(|error| format!("Erro ao preparar dados do cofre: {error}"))?;

    let nonce_bytes = generate_random_bytes::<NONCE_LENGTH>();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| "Erro ao criptografar o cofre.".to_string())?;

    plaintext.zeroize();

    Ok(EncryptedVaultFile {
        version: VAULT_VERSION,
        kdf: KdfParams {
            algorithm: "argon2id".to_string(),
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
        },
        cipher: "aes-256-gcm".to_string(),
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        data: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decrypt_payload(file: &EncryptedVaultFile, key: &[u8; KEY_LENGTH]) -> Result<VaultPayload, String> {
    if file.version != VAULT_VERSION {
        return Err("Versão do cofre incompatível.".to_string());
    }

    if file.cipher != "aes-256-gcm" {
        return Err("Criptografia do cofre incompatível.".to_string());
    }

    let nonce = general_purpose::STANDARD
        .decode(&file.nonce)
        .map_err(|_| "Nonce do cofre inválido.".to_string())?;

    let ciphertext = general_purpose::STANDARD
        .decode(&file.data)
        .map_err(|_| "Dados do cofre inválidos.".to_string())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Senha mestra inválida ou cofre corrompido.".to_string())?;

    let payload = serde_json::from_slice::<VaultPayload>(&plaintext)
        .map_err(|error| format!("Erro ao ler conteúdo do cofre: {error}"));

    plaintext.zeroize();
    payload
}

fn read_vault_file(app: &AppHandle) -> Result<EncryptedVaultFile, String> {
    let _ = migrate_legacy_vault_if_needed(app);
    let path = vault_path(app)?;

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Não foi possível ler o arquivo do cofre: {error}"))?;

    serde_json::from_str::<EncryptedVaultFile>(&content)
        .map_err(|error| format!("Arquivo do cofre inválido: {error}"))
}

fn write_vault_file(app: &AppHandle, file: &EncryptedVaultFile) -> Result<(), String> {
    let path = vault_path(app)?;
    let temp_path = path.with_file_name("vault.kpass.tmp");
    let backup_path = path.with_file_name("vault.kpass.previous");

    let content = serde_json::to_string_pretty(file)
        .map_err(|error| format!("Erro ao preparar arquivo do cofre: {error}"))?;

    fs::write(&temp_path, content)
        .map_err(|error| format!("Não foi possível preparar o arquivo temporário do cofre: {error}"))?;

    if path.exists() {
        let _ = fs::copy(&path, &backup_path);
        fs::remove_file(&path)
            .map_err(|error| format!("Não foi possível substituir o cofre anterior: {error}"))?;
    }

    fs::rename(&temp_path, &path)
        .map_err(|error| format!("Não foi possível salvar o cofre: {error}"))
}

fn clear_session_state(session: &VaultSession) -> Result<(), String> {
    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    if let Some(mut key) = guard.take() {
        key.zeroize();
    }

    Ok(())
}

fn clear_session(session: State<VaultSession>) -> Result<(), String> {
    clear_session_state(&session)
}

#[tauri::command]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    let _ = migrate_legacy_vault_if_needed(&app);
    Ok(vault_path(&app)?.exists())
}

#[tauri::command]
fn create_vault(
    app: AppHandle,
    session: State<VaultSession>,
    mut master_password: String,
) -> Result<VaultResponse, String> {
    if master_password.trim().len() < 10 {
        master_password.zeroize();
        return Err("A senha mestra precisa ter pelo menos 10 caracteres.".to_string());
    }

    let path = vault_path(&app)?;

    if path.exists() {
        master_password.zeroize();
        return Err("Já existe um cofre criado neste computador.".to_string());
    }

    let salt = generate_random_bytes::<SALT_LENGTH>();
    let key_result = derive_key(&master_password, &salt);
    master_password.zeroize();
    let key = key_result?;

    let payload = VaultPayload { items: vec![] };
    let encrypted_file = encrypt_payload(&payload, &key, &salt)?;

    write_vault_file(&app, &encrypted_file)?;

    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    *guard = Some(key);

    Ok(VaultResponse { items: payload.items })
}

#[tauri::command]
fn unlock_vault(
    app: AppHandle,
    session: State<VaultSession>,
    mut master_password: String,
) -> Result<VaultResponse, String> {
    let encrypted_file = read_vault_file(&app)?;

    let salt = general_purpose::STANDARD
        .decode(&encrypted_file.salt)
        .map_err(|_| "Salt do cofre inválido.".to_string())?;

    let key_result = derive_key(&master_password, &salt);
    master_password.zeroize();
    let key = key_result?;
    let payload = decrypt_payload(&encrypted_file, &key)?;

    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    *guard = Some(key);

    Ok(VaultResponse { items: payload.items })
}

#[tauri::command]
fn save_vault(
    app: AppHandle,
    session: State<VaultSession>,
    items: Vec<VaultItem>,
) -> Result<(), String> {
    let encrypted_file = read_vault_file(&app)?;

    let salt = general_purpose::STANDARD
        .decode(&encrypted_file.salt)
        .map_err(|_| "Salt do cofre inválido.".to_string())?;

    let guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    let key = guard
        .as_ref()
        .ok_or_else(|| "Cofre bloqueado. Desbloqueie novamente.".to_string())?;

    let payload = VaultPayload { items };
    let updated_file = encrypt_payload(&payload, key, &salt)?;

    write_vault_file(&app, &updated_file)
}

#[tauri::command]
fn lock_vault(session: State<VaultSession>) -> Result<(), String> {
    clear_session(session)
}

#[tauri::command]
fn get_vault_path(app: AppHandle) -> Result<String, String> {
    Ok(vault_path(&app)?.to_string_lossy().to_string())
}

#[tauri::command]
fn get_backup_dir(app: AppHandle) -> Result<String, String> {
    Ok(backup_dir(&app)?.to_string_lossy().to_string())
}

#[tauri::command]
fn export_backup(app: AppHandle) -> Result<String, String> {
    let source = vault_path(&app)?;

    if !source.exists() {
        return Err("Nenhum cofre encontrado para exportar.".to_string());
    }

    let destination = backup_dir(&app)?.join(backup_file_name()?);

    fs::copy(&source, &destination)
        .map_err(|error| format!("Não foi possível exportar o backup: {error}"))?;

    Ok(destination.to_string_lossy().to_string())
}

#[tauri::command]
fn import_latest_backup(app: AppHandle, session: State<VaultSession>) -> Result<String, String> {
    let dir = backup_dir(&app)?;

    let mut backups = fs::read_dir(&dir)
        .map_err(|error| format!("Não foi possível ler a pasta de backups: {error}"))?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| extension.eq_ignore_ascii_case("kpass"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    backups.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    });

    let latest = backups
        .last()
        .ok_or_else(|| "Nenhum backup .kpass encontrado.".to_string())?
        .path();

    let destination = vault_path(&app)?;

    fs::copy(&latest, &destination)
        .map_err(|error| format!("Não foi possível restaurar o backup: {error}"))?;

    clear_session(session)?;

    Ok(latest.to_string_lossy().to_string())
}

#[tauri::command]
fn reset_vault(app: AppHandle, session: State<VaultSession>) -> Result<(), String> {
    clear_session(session)?;

    let path = vault_path(&app)?;

    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("Não foi possível resetar o cofre: {error}"))?;
    }

    Ok(())
}

#[tauri::command]
fn export_backup_to_path(app: AppHandle, destination_path: String) -> Result<String, String> {
    let source = vault_path(&app)?;

    if !source.exists() {
        return Err("Nenhum cofre encontrado para exportar.".to_string());
    }

    let mut destination = PathBuf::from(destination_path);

    if destination.extension().is_none() {
        destination.set_extension("kpass");
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Não foi possível criar a pasta do backup: {error}"))?;
    }

    fs::copy(&source, &destination)
        .map_err(|error| format!("Não foi possível exportar o backup: {error}"))?;

    Ok(destination.to_string_lossy().to_string())
}

#[tauri::command]
fn import_backup_from_path(
    app: AppHandle,
    session: State<VaultSession>,
    source_path: String,
) -> Result<String, String> {
    let source = PathBuf::from(source_path);

    if !source.exists() {
        return Err("Arquivo de backup não encontrado.".to_string());
    }

    let content = fs::read_to_string(&source)
        .map_err(|error| format!("Não foi possível ler o backup: {error}"))?;

    serde_json::from_str::<EncryptedVaultFile>(&content)
        .map_err(|error| format!("Arquivo de backup inválido: {error}"))?;

    let destination = vault_path(&app)?;

    fs::copy(&source, &destination)
        .map_err(|error| format!("Não foi possível restaurar o backup: {error}"))?;

    clear_session(session)?;

    Ok(source.to_string_lossy().to_string())
}

#[tauri::command]
fn change_master_password(
    app: AppHandle,
    session: State<VaultSession>,
    mut current_master_password: String,
    mut new_master_password: String,
) -> Result<(), String> {
    if current_master_password.trim().is_empty() {
        current_master_password.zeroize();
        new_master_password.zeroize();
        return Err("Digite a senha mestra atual.".to_string());
    }

    if new_master_password.trim().len() < 10 {
        current_master_password.zeroize();
        new_master_password.zeroize();
        return Err("A nova senha mestra precisa ter pelo menos 10 caracteres.".to_string());
    }

    if current_master_password == new_master_password {
        current_master_password.zeroize();
        new_master_password.zeroize();
        return Err("A nova senha mestra precisa ser diferente da atual.".to_string());
    }

    let encrypted_file = read_vault_file(&app)?;

    let salt = general_purpose::STANDARD
        .decode(&encrypted_file.salt)
        .map_err(|_| "Salt do cofre inválido.".to_string())?;

    let current_key_result = derive_key(&current_master_password, &salt);
    current_master_password.zeroize();
    let mut current_key = current_key_result?;
    let payload = decrypt_payload(&encrypted_file, &current_key)?;

    let new_salt = generate_random_bytes::<SALT_LENGTH>();
    let new_key_result = derive_key(&new_master_password, &new_salt);
    new_master_password.zeroize();
    let new_key = new_key_result?;
    let updated_file = encrypt_payload(&payload, &new_key, &new_salt)?;

    write_vault_file(&app, &updated_file)?;

    current_key.zeroize();

    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    if let Some(mut old_key) = guard.take() {
        old_key.zeroize();
    }

    *guard = Some(new_key);

    Ok(())
}


#[tauri::command]
fn write_report_file(destination_path: String, content: String) -> Result<String, String> {
    let mut destination = PathBuf::from(destination_path);

    if destination.extension().is_none() {
        destination.set_extension("json");
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Não foi possível criar a pasta do relatório: {error}"))?;
    }

    fs::write(&destination, content)
        .map_err(|error| format!("Não foi possível salvar o relatório: {error}"))?;

    Ok(destination.to_string_lossy().to_string())
}

#[cfg(target_os = "windows")]
fn play_native_notification_sound() {
    use std::os::windows::process::CommandExt;

    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "[System.Media.SystemSounds]::Asterisk.Play()",
        ])
        .creation_flags(0x08000000)
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn play_native_notification_sound() {}

#[tauri::command]
fn play_kpassword_notification_sound() -> Result<(), String> {
    play_native_notification_sound();
    Ok(())
}

#[tauri::command]
fn show_kpassword_notification(app: AppHandle, body: String) -> Result<(), String> {
    show_tray_notification(&app, &body);
    Ok(())
}

fn show_tray_notification(app: &AppHandle, body: &str) {
    let _ = app
        .notification()
        .builder()
        .title("KPassword")
        .body(body)
        .show();
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(target_os = "windows")]
fn windows_session_appears_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenInputDesktop, SwitchDesktop, DESKTOP_SWITCHDESKTOP,
    };

    unsafe {
        let desktop = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);

        if desktop.is_null() {
            return true;
        }

        let can_switch = SwitchDesktop(desktop) != 0;
        let _ = CloseDesktop(desktop);

        !can_switch
    }
}

#[cfg(target_os = "windows")]
fn start_windows_session_watch(app: AppHandle) {
    std::thread::spawn(move || {
        let mut was_locked = false;

        loop {
            let is_locked = windows_session_appears_locked();

            if is_locked && !was_locked {
                let session = app.state::<VaultSession>();
                let _ = clear_session_state(&session);

                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }

                let _ = app.emit("kpassword-system-lock", ());
            }

            was_locked = is_locked;
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn start_windows_session_watch(_app: AppHandle) {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppUpdateInfo {
    version: String,
    current_version: String,
    notes: Option<String>,
}

#[tauri::command]
async fn check_kpassword_update(app: AppHandle) -> Result<Option<AppUpdateInfo>, String> {
    let update = app
        .updater()
        .map_err(|error| format!("Falha ao iniciar o atualizador: {error}"))?
        .check()
        .await
        .map_err(|error| format!("Falha ao consultar a versão mais recente: {error}"))?;

    Ok(update.map(|available| AppUpdateInfo {
        version: available.version.clone(),
        current_version: available.current_version.clone(),
        notes: available.body.clone(),
    }))
}

#[tauri::command]
async fn install_kpassword_update(app: AppHandle) -> Result<(), String> {
    let update = app
        .updater()
        .map_err(|error| format!("Falha ao iniciar o atualizador: {error}"))?
        .check()
        .await
        .map_err(|error| format!("Falha ao confirmar a atualização: {error}"))?
        .ok_or_else(|| "Nenhuma atualização está disponível.".to_string())?;

    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| format!("Falha ao instalar a atualização: {error}"))?;

    app.restart();

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(VaultSession::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            start_windows_session_watch(app.handle().clone());

            let open_item = MenuItem::with_id(app, "open", "Abrir KPassword", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Encerrar KPassword", true, None::<&str>)?;
            let tray_menu = Menu::with_items(app, &[&open_item, &quit_item])?;
            let mut tray_builder = TrayIconBuilder::new()
                .tooltip("KPassword")
                .menu(&tray_menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        show_main_window(app);
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }

            tray_builder.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let app = window.app_handle();
                show_tray_notification(app, "O KPassword continua em execução na bandeja.");
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            create_vault,
            unlock_vault,
            save_vault,
            lock_vault,
            get_vault_path,
            get_backup_dir,
            export_backup,
            import_latest_backup,
            reset_vault,
            export_backup_to_path,
            import_backup_from_path,
            change_master_password,
            write_report_file,
            show_kpassword_notification,
            play_kpassword_notification_sound,
            check_kpassword_update,
            install_kpassword_update
        ])
        .run(tauri::generate_context!())
        .expect("Erro ao iniciar o KPassword");
}
