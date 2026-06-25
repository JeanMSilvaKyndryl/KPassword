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
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroize;

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
    let plaintext = serde_json::to_vec(payload)
        .map_err(|error| format!("Erro ao preparar dados do cofre: {error}"))?;

    let nonce_bytes = generate_random_bytes::<NONCE_LENGTH>();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| "Erro ao criptografar o cofre.".to_string())?;

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

fn decrypt_payload(
    file: &EncryptedVaultFile,
    key: &[u8; KEY_LENGTH],
) -> Result<VaultPayload, String> {
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

    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| "Senha mestra inválida ou cofre corrompido.".to_string())?;

    serde_json::from_slice::<VaultPayload>(&plaintext)
        .map_err(|error| format!("Erro ao ler conteúdo do cofre: {error}"))
}

fn read_vault_file(app: &AppHandle) -> Result<EncryptedVaultFile, String> {
    let path = vault_path(app)?;

    let content = fs::read_to_string(&path)
        .map_err(|error| format!("Não foi possível ler o arquivo do cofre: {error}"))?;

    serde_json::from_str::<EncryptedVaultFile>(&content)
        .map_err(|error| format!("Arquivo do cofre inválido: {error}"))
}

fn write_vault_file(app: &AppHandle, file: &EncryptedVaultFile) -> Result<(), String> {
    let path = vault_path(app)?;

    let content = serde_json::to_string_pretty(file)
        .map_err(|error| format!("Erro ao preparar arquivo do cofre: {error}"))?;

    fs::write(&path, content).map_err(|error| format!("Não foi possível salvar o cofre: {error}"))
}

fn clear_session(session: State<VaultSession>) -> Result<(), String> {
    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    if let Some(mut key) = guard.take() {
        key.zeroize();
    }

    Ok(())
}

#[tauri::command]
fn vault_exists(app: AppHandle) -> Result<bool, String> {
    Ok(vault_path(&app)?.exists())
}

#[tauri::command]
fn create_vault(
    app: AppHandle,
    session: State<VaultSession>,
    master_password: String,
) -> Result<VaultResponse, String> {
    if master_password.trim().len() < 8 {
        return Err("A senha mestra precisa ter pelo menos 8 caracteres.".to_string());
    }

    let path = vault_path(&app)?;

    if path.exists() {
        return Err("Já existe um cofre criado neste computador.".to_string());
    }

    let salt = generate_random_bytes::<SALT_LENGTH>();
    let key = derive_key(&master_password, &salt)?;

    let payload = VaultPayload { items: vec![] };
    let encrypted_file = encrypt_payload(&payload, &key, &salt)?;

    write_vault_file(&app, &encrypted_file)?;

    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    *guard = Some(key);

    Ok(VaultResponse {
        items: payload.items,
    })
}

#[tauri::command]
fn unlock_vault(
    app: AppHandle,
    session: State<VaultSession>,
    master_password: String,
) -> Result<VaultResponse, String> {
    let encrypted_file = read_vault_file(&app)?;

    let salt = general_purpose::STANDARD
        .decode(&encrypted_file.salt)
        .map_err(|_| "Salt do cofre inválido.".to_string())?;

    let key = derive_key(&master_password, &salt)?;
    let payload = decrypt_payload(&encrypted_file, &key)?;

    let mut guard = session
        .key
        .lock()
        .map_err(|_| "Erro ao acessar sessão do cofre.".to_string())?;

    *guard = Some(key);

    Ok(VaultResponse {
        items: payload.items,
    })
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
    current_master_password: String,
    new_master_password: String,
) -> Result<(), String> {
    if current_master_password.trim().is_empty() {
        return Err("Digite a senha mestra atual.".to_string());
    }

    if new_master_password.trim().len() < 8 {
        return Err("A nova senha mestra precisa ter pelo menos 8 caracteres.".to_string());
    }

    if current_master_password == new_master_password {
        return Err("A nova senha mestra precisa ser diferente da atual.".to_string());
    }

    let encrypted_file = read_vault_file(&app)?;

    let salt = general_purpose::STANDARD
        .decode(&encrypted_file.salt)
        .map_err(|_| "Salt do cofre inválido.".to_string())?;

    let mut current_key = derive_key(&current_master_password, &salt)?;
    let payload = decrypt_payload(&encrypted_file, &current_key)?;

    let new_salt = generate_random_bytes::<SALT_LENGTH>();
    let new_key = derive_key(&new_master_password, &new_salt)?;
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultSession::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            export_backup_to_path,
            import_backup_from_path,
            change_master_password
            vault_exists,
            create_vault,
            unlock_vault,
            save_vault,
            lock_vault,
            get_vault_path,
            get_backup_dir,
            export_backup,
            import_latest_backup,
            reset_vault
        ])
        .run(tauri::generate_context!())
        .expect("Erro ao iniciar o KPassword");
}
