#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bip39::{Language, Mnemonic};
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    secp256k1::{PublicKey, Secp256k1},
    Address, Network,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use eframe::egui;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sskr::{sskr_combine, sskr_generate, GroupSpec, Secret, Spec};
use tiny_keccak::Hasher;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_BACKUP_FILE: &str = "seed_backup.json.age";
const FORM_LABEL_WIDTH: f32 = 170.0;
const FORM_BUTTON_WIDTH: f32 = 112.0;
const MAX_DERIVE_COUNT: u32 = 100;
const MAX_SSKR_GROUPS: u8 = 16;
const MAX_SSKR_SHARES_PER_GROUP: u8 = 16;
const BACKUP_SCHEMA_VERSION: u32 = 2;
const BIP32_HARDENED_OFFSET: u32 = 1 << 31;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 720.0])
            .with_min_inner_size([740.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BIP39 Tool",
        options,
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::light());
            Ok(Box::new(Bip39Gui::default()))
        }),
    )
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct GuiBackup {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default)]
    backup_type: String,
    #[serde(default)]
    created_at_unix: Option<u64>,
    #[serde(default)]
    tool_version: String,
    language: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed_phrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
    #[serde(default)]
    sskr: GuiSskrBackup,
    #[serde(default)]
    recovery_info: String,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct GuiSskrBackup {
    groups: Vec<Vec<GuiShare>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct GuiShare {
    #[serde(default)]
    share_hex: String,
    #[serde(default)]
    mnemonic: String,
}

impl GuiBackup {
    fn zeroize_sensitive(&mut self) {
        if let Some(seed_phrase) = &mut self.seed_phrase {
            seed_phrase.zeroize();
        }
        if let Some(passphrase) = &mut self.passphrase {
            passphrase.zeroize();
        }
        for group in &mut self.sskr.groups {
            for share in group {
                share.zeroize_sensitive();
            }
        }
    }
}

impl GuiShare {
    fn zeroize_sensitive(&mut self) {
        self.share_hex.zeroize();
        self.mnemonic.zeroize();
    }
}

fn default_schema_version() -> u32 {
    1
}

struct BackupSummary {
    language: String,
    sskr_groups: usize,
    has_seed_phrase: bool,
    recovered_from_sskr: bool,
}

impl BackupSummary {
    fn from_json(value: &serde_json::Value) -> Self {
        let language = json_string_field(value, "language")
            .unwrap_or("English")
            .to_string();
        let sskr_groups = value
            .get("sskr")
            .and_then(|sskr| sskr.get("groups"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        Self {
            language,
            sskr_groups,
            has_seed_phrase: json_string_field(value, "seed_phrase").is_some(),
            recovered_from_sskr: false,
        }
    }

    fn seed_storage_label(&self) -> &'static str {
        if self.has_seed_phrase {
            "Seed storage: mnemonic"
        } else if self.sskr_groups > 0 {
            "Seed storage: SSKR shares"
        } else {
            "Seed storage: missing"
        }
    }
}

struct SensitiveJson {
    value: serde_json::Value,
}

impl SensitiveJson {
    fn new(value: serde_json::Value) -> Self {
        Self { value }
    }

    fn as_value(&self) -> &serde_json::Value {
        &self.value
    }
}

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.value);
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => text.zeroize(),
        serde_json::Value::Array(items) => {
            for item in items {
                zeroize_json_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                zeroize_json_value(value);
            }
        }
        _ => {}
    }
}

#[derive(Clone, Copy)]
struct SskrSettings {
    groups: u8,
    group_threshold: u8,
    shares_per_group: u8,
    required_shares_per_group: u8,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Generate,
    Decrypt,
    Recover,
    Addresses,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum SeedSource {
    #[default]
    Generate,
    Import,
}

impl SeedSource {
    fn phrase<'a>(self, generated: &'a str, imported: &'a str) -> &'a str {
        match self {
            Self::Generate => generated,
            Self::Import => imported,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum MnemonicLanguage {
    #[default]
    English,
    SimplifiedChinese,
    TraditionalChinese,
    Japanese,
    Korean,
    Spanish,
    French,
    Italian,
    Czech,
    Portuguese,
}

impl MnemonicLanguage {
    const ALL: [Self; 10] = [
        Self::English,
        Self::SimplifiedChinese,
        Self::TraditionalChinese,
        Self::Japanese,
        Self::Korean,
        Self::Spanish,
        Self::French,
        Self::Italian,
        Self::Czech,
        Self::Portuguese,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::SimplifiedChinese => "Simplified Chinese",
            Self::TraditionalChinese => "Traditional Chinese",
            Self::Japanese => "Japanese",
            Self::Korean => "Korean",
            Self::Spanish => "Spanish",
            Self::French => "French",
            Self::Italian => "Italian",
            Self::Czech => "Czech",
            Self::Portuguese => "Portuguese",
        }
    }

    fn serialized_name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::SimplifiedChinese => "SimplifiedChinese",
            Self::TraditionalChinese => "TraditionalChinese",
            Self::Japanese => "Japanese",
            Self::Korean => "Korean",
            Self::Spanish => "Spanish",
            Self::French => "French",
            Self::Italian => "Italian",
            Self::Czech => "Czech",
            Self::Portuguese => "Portuguese",
        }
    }

    fn bip39(self) -> Language {
        match self {
            Self::English => Language::English,
            Self::SimplifiedChinese => Language::SimplifiedChinese,
            Self::TraditionalChinese => Language::TraditionalChinese,
            Self::Japanese => Language::Japanese,
            Self::Korean => Language::Korean,
            Self::Spanish => Language::Spanish,
            Self::French => Language::French,
            Self::Italian => Language::Italian,
            Self::Czech => Language::Czech,
            Self::Portuguese => Language::Portuguese,
        }
    }

    fn from_backup_name(name: &str) -> Self {
        match name {
            "SimplifiedChinese" | "Simplified Chinese" => Self::SimplifiedChinese,
            "TraditionalChinese" | "Traditional Chinese" => Self::TraditionalChinese,
            "Japanese" => Self::Japanese,
            "Korean" => Self::Korean,
            "Spanish" => Self::Spanish,
            "French" => Self::French,
            "Italian" => Self::Italian,
            "Czech" => Self::Czech,
            "Portuguese" => Self::Portuguese,
            _ => Self::English,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum AddressKind {
    #[default]
    Bitcoin,
    Ethereum,
    Xrp,
    Solana,
}

impl AddressKind {
    const ALL: [Self; 4] = [Self::Bitcoin, Self::Ethereum, Self::Xrp, Self::Solana];

    fn label(self) -> &'static str {
        match self {
            Self::Bitcoin => "Bitcoin",
            Self::Ethereum => "Ethereum",
            Self::Xrp => "XRP",
            Self::Solana => "Solana",
        }
    }

    fn default_hardened(self) -> bool {
        matches!(self, Self::Solana)
    }
}

#[derive(Default)]
struct AddressRow {
    index: u32,
    path: String,
    address: String,
    public_key: String,
}

struct Bip39Gui {
    tab: Tab,
    show_tips: bool,
    seed_source: SeedSource,
    language: MnemonicLanguage,
    generated_phrase: Zeroizing<String>,
    imported_phrase: Zeroizing<String>,
    backup_passphrase: Zeroizing<String>,
    reveal_backup_passphrase: bool,
    store_passphrase: bool,
    reveal_generated: bool,
    sskr_enabled: bool,
    sskr_group_count: u8,
    sskr_group_threshold: u8,
    sskr_shares_per_group: u8,
    sskr_required_shares_per_group: u8,
    recipient_input: String,
    save_path: String,
    generate_status: String,
    decrypt_path: String,
    identity_input: Zeroizing<String>,
    reveal_identity_input: bool,
    decrypted_backup: Option<BackupSummary>,
    decrypted_backup_json: Option<SensitiveJson>,
    reveal_decrypted: bool,
    decrypt_status: String,
    recover_language: MnemonicLanguage,
    recover_shares_input: Zeroizing<String>,
    recover_passphrase: Zeroizing<String>,
    recover_status: String,
    derive_language: MnemonicLanguage,
    derive_phrase: Zeroizing<String>,
    derive_passphrase: Zeroizing<String>,
    derive_kind: AddressKind,
    derive_start: String,
    derive_end: String,
    derive_hardened: bool,
    address_rows: Vec<AddressRow>,
    derive_status: String,
}

impl Bip39Gui {
    fn new_seed(&mut self) {
        self.generated_phrase.zeroize();
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        match Mnemonic::from_entropy_in(self.language.bip39(), &entropy) {
            Ok(mnemonic) => {
                self.generated_phrase = Zeroizing::new(mnemonic.to_string());
                self.generate_status = "Generated a new 24-word seed.".to_string();
                self.derive_language = self.language;
                self.derive_phrase = self.generated_phrase.clone();
                self.derive_passphrase = self.backup_passphrase.clone();
                self.address_rows.clear();
                self.derive_status = "Address inputs loaded from the new seed.".to_string();
            }
            Err(err) => {
                self.generate_status = format!("Seed generation failed: {err}");
            }
        }
        entropy.zeroize();
    }

    fn save_seed_backup(&mut self) {
        let phrase = self.seed_source.phrase(
            self.generated_phrase.as_str(),
            self.imported_phrase.as_str(),
        );
        if phrase.trim().is_empty() {
            self.generate_status = match self.seed_source {
                SeedSource::Generate => "Generate a seed before saving.".to_string(),
                SeedSource::Import => "Enter a seed phrase before saving.".to_string(),
            };
            return;
        }

        let mnemonic = match parse_backup_mnemonic(self.language, phrase) {
            Ok(mnemonic) => mnemonic,
            Err(err) => {
                self.generate_status = err;
                return;
            }
        };
        let canonical_phrase = Zeroizing::new(mnemonic.to_string());

        let backup = GuiBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            backup_type: "mnemonic".to_string(),
            created_at_unix: current_unix_timestamp(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            language: self.language.serialized_name().to_string(),
            seed_phrase: Some(canonical_phrase.to_string()),
            passphrase: self
                .store_passphrase
                .then(|| self.backup_passphrase.to_string())
                .filter(|value| !value.is_empty()),
            sskr: GuiSskrBackup::default(),
            recovery_info: "Mnemonic seed phrase backup".to_string(),
        };
        let mut backup = if self.sskr_enabled {
            match self.backup_with_sskr(backup, &mnemonic) {
                Ok(backup) => backup,
                Err(err) => {
                    self.generate_status = err;
                    return;
                }
            }
        } else {
            backup
        };

        let recipients = match age_recipients_from_input(&self.recipient_input) {
            Ok(recipients) => recipients,
            Err(err) => {
                self.generate_status = err;
                return;
            }
        };

        let save_path = backup_save_path_from_input(&self.save_path);
        if let Err(err) = validate_save_path(&save_path) {
            self.generate_status = err;
            return;
        }

        let json = match serde_json::to_string_pretty(&backup) {
            Ok(json) => json,
            Err(err) => {
                backup.zeroize_sensitive();
                self.generate_status = format!("Backup serialization failed: {err}");
                return;
            }
        };
        backup.zeroize_sensitive();
        let json = Zeroizing::new(json);

        match encrypt_data(json.as_bytes(), &recipients)
            .and_then(|ciphertext| persist_noclobber(&save_path, &ciphertext))
        {
            Ok(()) => {
                let backup_kind = if self.sskr_enabled {
                    "encrypted SSKR backup"
                } else {
                    "encrypted mnemonic backup"
                };
                self.generate_status = format!("Saved {backup_kind} to {}.", save_path.display());
            }
            Err(err) => {
                self.generate_status = err;
            }
        }
    }

    fn decrypt_backup(&mut self) {
        let path = backup_save_path_from_input(&self.decrypt_path);
        let ciphertext = match std::fs::read(&path) {
            Ok(ciphertext) => ciphertext,
            Err(err) => {
                self.decrypt_status = format!("Failed to read {}: {err}", path.display());
                return;
            }
        };

        let plaintext = match decrypt_data(&ciphertext, self.identity_input.as_str()) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                self.decrypt_status = err;
                return;
            }
        };

        let backup_json = match serde_json::from_slice::<serde_json::Value>(plaintext.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                self.decrypt_status = format!("Backup JSON parse failed: {err}");
                return;
            }
        };

        let language = MnemonicLanguage::from_backup_name(
            json_string_field(&backup_json, "language").unwrap_or("English"),
        );
        let mut backup_summary = BackupSummary::from_json(&backup_json);
        self.derive_language = language;
        if let Some(seed_phrase) = json_string_field(&backup_json, "seed_phrase") {
            self.derive_phrase = Zeroizing::new(seed_phrase.to_string());
            self.derive_passphrase = Zeroizing::new(
                json_string_field(&backup_json, "passphrase")
                    .unwrap_or("")
                    .to_string(),
            );
            self.derive_status = "Address inputs loaded from the decrypted backup.".to_string();
            self.decrypt_status =
                "Backup decrypted and seed loaded into address derivation.".to_string();
        } else if backup_summary.sskr_groups > 0 {
            self.derive_passphrase = Zeroizing::new(
                json_string_field(&backup_json, "passphrase")
                    .unwrap_or("")
                    .to_string(),
            );
            match recover_mnemonic_from_backup_json(&backup_json, language) {
                Ok(mnemonic_phrase) => {
                    self.derive_phrase = mnemonic_phrase;
                    self.derive_status = "Recovered SSKR seed loaded.".to_string();
                    self.decrypt_status =
                        "Backup decrypted, and the SSKR seed was recovered automatically."
                            .to_string();
                    backup_summary.recovered_from_sskr = true;
                }
                Err(err) => {
                    self.derive_phrase.zeroize();
                    self.derive_passphrase.zeroize();
                    self.derive_status = format!("Automatic SSKR recovery failed: {err}");
                    self.decrypt_status =
                        format!("Backup decrypted, but automatic SSKR recovery failed: {err}");
                }
            }
        } else {
            self.derive_phrase.zeroize();
            self.derive_passphrase.zeroize();
            self.derive_status =
                "Backup decrypted, but it does not contain a seed phrase.".to_string();
            self.decrypt_status =
                "Backup decrypted, but it does not contain seed material.".to_string();
        }
        self.decrypted_backup = Some(backup_summary);
        self.decrypted_backup_json = Some(SensitiveJson::new(backup_json));
        self.address_rows.clear();
    }

    fn derive_addresses(&mut self) {
        let phrase = self.derive_phrase.trim();
        if phrase.is_empty() {
            self.derive_status = "Enter or load a seed phrase first.".to_string();
            return;
        }

        let start = match self.derive_start.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                self.derive_status = "Start index must be a number.".to_string();
                return;
            }
        };
        let end = match self.derive_end.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                self.derive_status = "End index must be a number.".to_string();
                return;
            }
        };
        if start > end {
            self.derive_status = "Start index cannot be greater than end index.".to_string();
            return;
        }
        if end - start + 1 > MAX_DERIVE_COUNT {
            self.derive_status = format!("Derive at most {MAX_DERIVE_COUNT} addresses at once.");
            return;
        }

        let mnemonic = match Mnemonic::parse_in_normalized(self.derive_language.bip39(), phrase) {
            Ok(mnemonic) => mnemonic,
            Err(err) => {
                self.derive_status = format!("Seed phrase is invalid: {err}");
                return;
            }
        };

        let seed = Zeroizing::new(mnemonic.to_seed(self.derive_passphrase.as_str()));
        match derive_address_rows(
            seed.as_slice(),
            self.derive_kind,
            start,
            end,
            self.derive_hardened,
        ) {
            Ok(rows) => {
                self.address_rows = rows;
                self.derive_status = format!("Derived {} address rows.", self.address_rows.len());
            }
            Err(err) => {
                self.derive_status = err;
            }
        }
    }

    fn recover_from_manual_shares(&mut self) {
        let mut shares =
            match shares_from_text(self.recover_shares_input.as_str(), self.recover_language) {
                Ok(shares) => shares,
                Err(err) => {
                    self.recover_status = err;
                    return;
                }
            };

        match recover_mnemonic_from_shares(shares.as_slice(), self.recover_language) {
            Ok(mnemonic_phrase) => {
                self.derive_language = self.recover_language;
                self.derive_phrase = mnemonic_phrase;
                self.derive_passphrase = self.recover_passphrase.clone();
                self.address_rows.clear();
                self.recover_status =
                    "Seed recovered and loaded into address derivation.".to_string();
                self.derive_status = "Recovered SSKR seed loaded.".to_string();
                self.tab = Tab::Addresses;
            }
            Err(err) => {
                self.recover_status = err;
            }
        }
        shares.zeroize();
    }

    fn clear_sensitive_state(&mut self) {
        self.generated_phrase.zeroize();
        self.imported_phrase.zeroize();
        self.backup_passphrase.zeroize();
        self.identity_input.zeroize();
        self.decrypted_backup = None;
        self.decrypted_backup_json = None;
        self.recover_shares_input.zeroize();
        self.recover_passphrase.zeroize();
        self.derive_phrase.zeroize();
        self.derive_passphrase.zeroize();
        self.address_rows.clear();
        self.generate_status = "Sensitive GUI state cleared.".to_string();
        self.decrypt_status.clear();
        self.recover_status.clear();
        self.derive_status.clear();
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        if ui.selectable_label(self.tab == tab, label).clicked() {
            self.tab = tab;
        }
    }

    fn normalize_sskr_settings(&mut self) {
        self.sskr_group_count = self.sskr_group_count.clamp(1, MAX_SSKR_GROUPS);
        self.sskr_group_threshold = self.sskr_group_threshold.clamp(1, self.sskr_group_count);
        self.sskr_shares_per_group = self
            .sskr_shares_per_group
            .clamp(1, MAX_SSKR_SHARES_PER_GROUP);
        self.sskr_required_shares_per_group = self
            .sskr_required_shares_per_group
            .clamp(1, self.sskr_shares_per_group);
    }

    fn sskr_settings(&self) -> SskrSettings {
        SskrSettings {
            groups: self.sskr_group_count,
            group_threshold: self.sskr_group_threshold,
            shares_per_group: self.sskr_shares_per_group,
            required_shares_per_group: self.sskr_required_shares_per_group,
        }
    }

    fn backup_with_sskr(
        &mut self,
        mut backup: GuiBackup,
        mnemonic: &Mnemonic,
    ) -> Result<GuiBackup, String> {
        self.normalize_sskr_settings();
        let mut entropy = mnemonic.to_entropy();
        let (sskr, recovery_info) =
            sskr_backup_from_entropy(&entropy, self.language, self.sskr_settings())?;
        entropy.zeroize();

        backup.seed_phrase = None;
        backup.backup_type = "sskr".to_string();
        backup.sskr = sskr;
        backup.recovery_info = recovery_info;
        Ok(backup)
    }
}

impl Default for Bip39Gui {
    fn default() -> Self {
        Self {
            tab: Tab::Generate,
            show_tips: true,
            seed_source: SeedSource::Generate,
            language: MnemonicLanguage::English,
            generated_phrase: Zeroizing::new(String::new()),
            imported_phrase: Zeroizing::new(String::new()),
            backup_passphrase: Zeroizing::new(String::new()),
            reveal_backup_passphrase: false,
            store_passphrase: false,
            reveal_generated: false,
            sskr_enabled: false,
            sskr_group_count: 2,
            sskr_group_threshold: 1,
            sskr_shares_per_group: 3,
            sskr_required_shares_per_group: 2,
            recipient_input: String::new(),
            save_path: format!("./{DEFAULT_BACKUP_FILE}"),
            generate_status: String::new(),
            decrypt_path: format!("./{DEFAULT_BACKUP_FILE}"),
            identity_input: Zeroizing::new(String::new()),
            reveal_identity_input: false,
            decrypted_backup: None,
            decrypted_backup_json: None,
            reveal_decrypted: false,
            decrypt_status: String::new(),
            recover_language: MnemonicLanguage::English,
            recover_shares_input: Zeroizing::new(String::new()),
            recover_passphrase: Zeroizing::new(String::new()),
            recover_status: String::new(),
            derive_language: MnemonicLanguage::English,
            derive_phrase: Zeroizing::new(String::new()),
            derive_passphrase: Zeroizing::new(String::new()),
            derive_kind: AddressKind::Bitcoin,
            derive_start: "0".to_string(),
            derive_end: "4".to_string(),
            derive_hardened: false,
            address_rows: Vec::new(),
            derive_status: String::new(),
        }
    }
}

impl eframe::App for Bip39Gui {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show_inside(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("BIP39 Tool");
                ui.separator();
                self.tab_button(ui, Tab::Generate, "Create Backup");
                self.tab_button(ui, Tab::Decrypt, "Open Backup");
                self.tab_button(ui, Tab::Recover, "Recover SSKR");
                self.tab_button(ui, Tab::Addresses, "Address Derivation");
                ui.separator();
                ui.checkbox(&mut self.show_tips, "Tips");
                if ui.button("Clear Sensitive Data").clicked() {
                    self.clear_sensitive_state();
                }
            });
        });

        egui::CentralPanel::default_margins().show_inside(ui, |ui| {
            if self.show_tips {
                tips_panel(ui, self.tab);
                ui.separator();
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Generate => self.generate_tab(ui),
                    Tab::Decrypt => self.decrypt_tab(ui),
                    Tab::Recover => self.recover_tab(ui),
                    Tab::Addresses => self.addresses_tab(ui),
                });
        });
    }
}

impl Bip39Gui {
    fn generate_tab(&mut self, ui: &mut egui::Ui) {
        self.normalize_sskr_settings();
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            form_label(ui, "Seed source");
            ui.selectable_value(&mut self.seed_source, SeedSource::Generate, "Generate new");
            ui.selectable_value(&mut self.seed_source, SeedSource::Import, "Import existing");
        });
        ui.horizontal(|ui| {
            form_label(ui, "Seed language");
            language_combo(ui, "generate_language", &mut self.language);
            if self.seed_source == SeedSource::Generate && ui.button("Generate Seed").clicked() {
                self.new_seed();
            }
        });

        ui.separator();
        if self.seed_source == SeedSource::Import {
            multiline_text_row(ui, "Seed phrase", &mut self.imported_phrase, 4);
        }
        ui.horizontal(|ui| {
            form_label(ui, "Passphrase");
            let response = ui.add_sized(
                [320.0, 24.0],
                egui::TextEdit::singleline(&mut *self.backup_passphrase)
                    .password(!self.reveal_backup_passphrase)
                    .desired_width(320.0),
            );
            if self.seed_source == SeedSource::Generate
                && response.changed()
                && !self.generated_phrase.is_empty()
                && self.derive_phrase.as_str() == self.generated_phrase.as_str()
            {
                self.derive_passphrase = self.backup_passphrase.clone();
            }
            ui.checkbox(&mut self.reveal_backup_passphrase, "Reveal passphrase");
            ui.checkbox(&mut self.store_passphrase, "Include in encrypted backup");
        });

        if self.seed_source == SeedSource::Generate {
            ui.horizontal(|ui| {
                form_label(ui, "");
                ui.checkbox(&mut self.reveal_generated, "Reveal seed phrase");
            });
            seed_phrase_box(ui, self.generated_phrase.as_str(), self.reveal_generated);
        }

        ui.separator();
        ui.horizontal(|ui| {
            form_label(ui, "SSKR settings");
            ui.checkbox(&mut self.sskr_enabled, "Enable SSKR backup");
        });
        ui.horizontal(|ui| {
            form_label(ui, "Groups");
            ui.label("Total");
            ui.add(
                egui::DragValue::new(&mut self.sskr_group_count)
                    .range(1..=MAX_SSKR_GROUPS)
                    .speed(1.0),
            );
            ui.label("Required");
            ui.add(
                egui::DragValue::new(&mut self.sskr_group_threshold)
                    .range(1..=self.sskr_group_count)
                    .speed(1.0),
            );
        });
        ui.horizontal(|ui| {
            form_label(ui, "Shares per group");
            ui.label("Total");
            ui.add(
                egui::DragValue::new(&mut self.sskr_shares_per_group)
                    .range(1..=MAX_SSKR_SHARES_PER_GROUP)
                    .speed(1.0),
            );
            ui.label("Required");
            ui.add(
                egui::DragValue::new(&mut self.sskr_required_shares_per_group)
                    .range(1..=self.sskr_shares_per_group)
                    .speed(1.0),
            );
        });
        ui.horizontal(|ui| {
            form_label(ui, "");
            ui.label(sskr_rule_label(self.sskr_settings()));
        });

        ui.separator();
        if text_field_row(
            ui,
            "Recipient key or file",
            &mut self.recipient_input,
            false,
            Some("Choose File"),
        ) {
            choose_existing_file(
                "Choose age recipient file",
                &mut self.recipient_input,
                &["txt", "pub", "toml"],
            );
        }
        if text_field_row(
            ui,
            "Encrypted backup file",
            &mut self.save_path,
            false,
            Some("Save As"),
        ) {
            choose_save_file(&mut self.save_path);
        }
        ui.horizontal(|ui| {
            form_label(ui, "");
            if ui.button("Encrypt and Save").clicked() {
                self.save_seed_backup();
            }
            status_label(ui, &self.generate_status);
        });
    }

    fn decrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        if text_field_row(
            ui,
            "Encrypted backup file",
            &mut self.decrypt_path,
            false,
            Some("Open File"),
        ) {
            choose_existing_file("Open encrypted backup", &mut self.decrypt_path, &["age"]);
        }
        if text_field_row(
            ui,
            "Identity file or key",
            &mut self.identity_input,
            !self.reveal_identity_input,
            Some("Choose File"),
        ) {
            choose_existing_file(
                "Choose age identity file",
                &mut self.identity_input,
                &["txt", "key"],
            );
        }
        ui.horizontal(|ui| {
            form_label(ui, "");
            ui.checkbox(&mut self.reveal_identity_input, "Reveal identity field");
        });
        ui.horizontal(|ui| {
            form_label(ui, "");
            if ui.button("Decrypt").clicked() {
                self.decrypt_backup();
            }
            status_label(ui, &self.decrypt_status);
        });

        ui.separator();
        let recovered_from_sskr = self
            .decrypted_backup
            .as_ref()
            .is_some_and(|backup| backup.recovered_from_sskr);
        let seed_loaded = self
            .decrypted_backup
            .as_ref()
            .is_some_and(|backup| backup.has_seed_phrase || backup.recovered_from_sskr);
        if self.decrypted_backup_json.is_some() {
            ui.horizontal(|ui| {
                if let Some(backup) = &self.decrypted_backup {
                    ui.label(format!("Language: {}", backup.language));
                    ui.separator();
                    ui.label(format!("SSKR groups: {}", backup.sskr_groups));
                    ui.separator();
                    ui.label(backup.seed_storage_label());
                    if backup.recovered_from_sskr {
                        ui.separator();
                        ui.label("Recovery: complete");
                    }
                    ui.separator();
                }
                ui.checkbox(&mut self.reveal_decrypted, "Reveal sensitive values");
            });
            if seed_loaded {
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    if ui.button("Open Address Derivation").clicked() {
                        self.tab = Tab::Addresses;
                    }
                });
            }

            if let Some(backup_json) = &self.decrypted_backup_json {
                let recovered_phrase = recovered_from_sskr.then_some(self.derive_phrase.as_str());
                render_backup_view(
                    ui,
                    backup_json.as_value(),
                    recovered_phrase,
                    self.reveal_decrypted,
                );
            }
        }
    }

    fn recover_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            form_label(ui, "Share language");
            language_combo(ui, "recover_language", &mut self.recover_language);
        });
        multiline_text_row(ui, "SSKR shares", &mut self.recover_shares_input, 8);
        ui.horizontal(|ui| {
            form_label(ui, "Passphrase");
            ui.add_sized(
                [280.0, 24.0],
                egui::TextEdit::singleline(&mut *self.recover_passphrase)
                    .password(true)
                    .desired_width(280.0),
            );
        });
        ui.horizontal(|ui| {
            form_label(ui, "");
            if ui.button("Recover Seed").clicked() {
                self.recover_from_manual_shares();
            }
            status_label(ui, &self.recover_status);
        });
    }

    fn addresses_tab(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            form_label(ui, "Seed language");
            language_combo(ui, "derive_language", &mut self.derive_language);
            ui.label("Network");
            egui::ComboBox::from_id_salt("address_kind")
                .selected_text(self.derive_kind.label())
                .show_ui(ui, |ui| {
                    for kind in AddressKind::ALL {
                        if ui
                            .selectable_value(&mut self.derive_kind, kind, kind.label())
                            .clicked()
                        {
                            self.derive_hardened = kind.default_hardened();
                        }
                    }
                });
        });

        multiline_text_row(ui, "Seed phrase", &mut self.derive_phrase, 3);

        ui.horizontal(|ui| {
            form_label(ui, "Passphrase");
            ui.add_sized(
                [280.0, 24.0],
                egui::TextEdit::singleline(&mut *self.derive_passphrase)
                    .password(true)
                    .desired_width(280.0),
            );
        });

        ui.horizontal(|ui| {
            form_label(ui, "Index range");
            ui.label("Start");
            ui.add(egui::TextEdit::singleline(&mut self.derive_start).desired_width(72.0));
            ui.label("End");
            ui.add(egui::TextEdit::singleline(&mut self.derive_end).desired_width(72.0));
            if matches!(
                self.derive_kind,
                AddressKind::Bitcoin | AddressKind::Ethereum
            ) {
                ui.checkbox(&mut self.derive_hardened, "Harden final index");
            }
        });

        ui.horizontal(|ui| {
            form_label(ui, "");
            if ui.button("Derive Addresses").clicked() {
                self.derive_addresses();
            }
            status_label(ui, &self.derive_status);
        });

        ui.separator();
        egui::Grid::new("addresses_grid")
            .striped(true)
            .min_col_width(80.0)
            .show(ui, |ui| {
                ui.strong("Index");
                ui.strong("Path");
                ui.strong("Address");
                ui.strong("Public key");
                ui.end_row();
                for row in &self.address_rows {
                    ui.label(row.index.to_string());
                    ui.monospace(&row.path);
                    ui.monospace(&row.address);
                    ui.monospace(&row.public_key);
                    ui.end_row();
                }
            });
    }
}

fn language_combo(ui: &mut egui::Ui, id: &str, language: &mut MnemonicLanguage) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(language.label())
        .show_ui(ui, |ui| {
            for value in MnemonicLanguage::ALL {
                ui.selectable_value(language, value, value.label());
            }
        });
}

fn tips_panel(ui: &mut egui::Ui, tab: Tab) {
    ui.vertical(|ui| {
        ui.heading("Tips");
        match tab {
            Tab::Generate => {
                tip_line(ui, "Generate a new seed or import an existing BIP-39 seed phrase to encrypt and save.");
                tip_line(ui, "Seed language selects the BIP-39 wordlist; it does not translate an existing phrase.");
                tip_line(ui, "Enable SSKR backup to split mnemonic entropy into recovery shares instead of saving the raw seed phrase.");
                tip_line(ui, "The passphrase is not stored unless Include in encrypted backup is checked.");
                tip_line(ui, "Backups are encrypted with the installed age binary; paste a public age, age1pq, or SSH recipient, or choose a recipient file.");
            }
            Tab::Decrypt => {
                tip_line(ui, "Use an encrypted .age backup file and a private AGE-SECRET-KEY identity or identity file.");
                tip_line(ui, "A public age1 or age1pq recipient cannot decrypt; it is only used when saving.");
                tip_line(ui, "The JSON viewer shows every decrypted backup field, with sensitive values masked until revealed.");
                tip_line(ui, "Mnemonic and SSKR backups are loaded into address derivation automatically.");
            }
            Tab::Recover => {
                tip_line(ui, "Paste one SSKR share per line, in hex or mnemonic form.");
                tip_line(ui, "Do not paste duplicate shares; recovery needs enough unique valid shares.");
                tip_line(ui, "Select the same BIP-39 language used when the SSKR share mnemonics were created.");
                tip_line(ui, "Recovered seeds load into address derivation without saving a plaintext file.");
            }
            Tab::Addresses => {
                tip_line(ui, "Address derivation uses the selected seed phrase, language, passphrase, network, and index range.");
                tip_line(ui, "Bitcoin and Ethereum support standard or hardened final indexes.");
                tip_line(ui, "XRP uses the standard BIP-44 XRP path; Solana uses hardened Ed25519 derivation.");
                tip_line(ui, "The table shows public addresses and public keys only.");
            }
        }
    });
}

fn tip_line(ui: &mut egui::Ui, text: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label("-");
        ui.label(text);
    });
}

fn form_label(ui: &mut egui::Ui, label: &str) {
    ui.add_sized(
        [FORM_LABEL_WIDTH, 20.0],
        egui::Label::new(label).halign(egui::Align::RIGHT),
    );
}

fn text_field_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    password: bool,
    button_label: Option<&str>,
) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        form_label(ui, label);
        let button_width = button_label.map(|_| FORM_BUTTON_WIDTH).unwrap_or(0.0);
        let field_width =
            (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(240.0);
        let mut edit = egui::TextEdit::singleline(value).desired_width(field_width);
        if password {
            edit = edit.password(true);
        }
        ui.add_sized([field_width, 24.0], edit);
        if let Some(button_label) = button_label {
            clicked = ui
                .add_sized([FORM_BUTTON_WIDTH, 24.0], egui::Button::new(button_label))
                .clicked();
        }
    });
    clicked
}

fn multiline_text_row(ui: &mut egui::Ui, label: &str, value: &mut String, rows: usize) {
    ui.horizontal(|ui| {
        form_label(ui, label);
        let field_width = ui.available_width().max(240.0);
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        ui.add_sized(
            [field_width, row_height * rows as f32],
            egui::TextEdit::multiline(value)
                .desired_rows(rows)
                .lock_focus(true)
                .desired_width(field_width),
        );
    });
}

fn choose_existing_file(title: &str, target: &mut String, extensions: &[&str]) {
    let mut dialog = FileDialog::new().set_title(title);
    if !extensions.is_empty() {
        dialog = dialog.add_filter("Supported files", extensions);
    }
    if let Some(path) = dialog.pick_file() {
        *target = path_to_string(path);
    }
}

fn choose_save_file(target: &mut String) {
    let mut dialog = FileDialog::new()
        .set_title("Save encrypted backup")
        .set_file_name(DEFAULT_BACKUP_FILE)
        .add_filter("age backup", &["age"]);

    let current_path = backup_save_path_from_input(target);
    let parent = save_parent_dir(&current_path);
    if parent.exists() {
        dialog = dialog.set_directory(parent);
    }

    if let Some(path) = dialog.save_file() {
        *target = path_to_string(path);
    }
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

fn current_unix_timestamp() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn json_string_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(serde_json::Value::as_str)
}

fn render_backup_view(
    ui: &mut egui::Ui,
    value: &serde_json::Value,
    recovered_seed_phrase: Option<&str>,
    reveal_sensitive: bool,
) {
    ui.add_space(8.0);
    match value {
        serde_json::Value::Object(map) => {
            render_backup_summary(ui, map, recovered_seed_phrase.is_some());
            if let Some(seed_phrase) = recovered_seed_phrase {
                render_recovered_seed_material(ui, seed_phrase, reveal_sensitive);
            }
            render_seed_material(ui, map, reveal_sensitive);
            render_sskr_material(ui, map, reveal_sensitive);
            render_additional_fields(ui, map, reveal_sensitive);
        }
        _ => {
            section_header(ui, "Decrypted JSON");
            render_json_field(ui, "Value", value, reveal_sensitive);
        }
    }
}

fn render_backup_summary(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    recovered_from_sskr: bool,
) {
    section_header(ui, "Backup Summary");
    field_grid(ui, "backup_summary_grid", |ui| {
        render_field_row(
            ui,
            "Type",
            backup_kind_label(map),
            false,
            egui::Color32::DARK_GRAY,
        );
        if let Some(value) = map.get("language") {
            render_field_row(
                ui,
                "Language",
                display_json_value("language", value, true),
                false,
                egui::Color32::DARK_GRAY,
            );
        }
        for key in [
            "schema_version",
            "backup_type",
            "tool_version",
            "created_at_unix",
        ] {
            if let Some(value) = map.get(key) {
                render_field_row(
                    ui,
                    human_json_key(key),
                    display_json_value(key, value, true),
                    false,
                    egui::Color32::DARK_GRAY,
                );
            }
        }
        if let Some(value) = map.get("recovery_info") {
            render_field_row(
                ui,
                "Recovery Rule",
                display_json_value("recovery_info", value, true),
                false,
                egui::Color32::DARK_GRAY,
            );
        }
        render_field_row(
            ui,
            "Top-Level Fields",
            map.len().to_string(),
            false,
            egui::Color32::DARK_GRAY,
        );
        if recovered_from_sskr {
            render_field_row(
                ui,
                "SSKR Recovery",
                "Recovered automatically".to_string(),
                false,
                egui::Color32::DARK_GRAY,
            );
        }
    });
}

fn render_recovered_seed_material(ui: &mut egui::Ui, seed_phrase: &str, reveal_sensitive: bool) {
    section_header(ui, "Recovered Seed Material");
    field_grid(ui, "recovered_seed_material_grid", |ui| {
        let display = if reveal_sensitive {
            seed_phrase.to_string()
        } else {
            mask_secret_text(seed_phrase)
        };
        render_field_row(
            ui,
            "Seed Phrase",
            display,
            true,
            sensitive_color("seed_phrase", reveal_sensitive),
        );
    });
}

fn render_seed_material(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    reveal_sensitive: bool,
) {
    let seed_keys = [
        "seed_phrase",
        "passphrase",
        "entropy",
        "bip39_seed",
        "bip32_root_key",
    ];
    if !seed_keys.iter().any(|key| map.contains_key(*key)) {
        return;
    }

    section_header(ui, "Seed Material");
    field_grid(ui, "seed_material_grid", |ui| {
        for key in seed_keys {
            if let Some(value) = map.get(key) {
                render_field_row(
                    ui,
                    human_json_key(key),
                    display_json_value(key, value, reveal_sensitive),
                    true,
                    sensitive_color(key, reveal_sensitive),
                );
            }
        }
    });
}

fn render_sskr_material(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    reveal_sensitive: bool,
) {
    let Some(sskr) = map.get("sskr") else {
        return;
    };
    let Some(groups) = sskr.get("groups").and_then(serde_json::Value::as_array) else {
        section_header(ui, "SSKR");
        render_json_field(ui, "sskr", sskr, reveal_sensitive);
        return;
    };

    section_header(ui, "SSKR Shares");
    field_grid(ui, "sskr_summary_grid", |ui| {
        render_field_row(
            ui,
            "Groups",
            groups.len().to_string(),
            false,
            egui::Color32::DARK_GRAY,
        );
        let share_count = groups
            .iter()
            .filter_map(serde_json::Value::as_array)
            .map(Vec::len)
            .sum::<usize>();
        render_field_row(
            ui,
            "Total Shares",
            share_count.to_string(),
            false,
            egui::Color32::DARK_GRAY,
        );
    });

    for (group_index, group) in groups.iter().enumerate() {
        let share_count = group.as_array().map(Vec::len).unwrap_or(0);
        egui::CollapsingHeader::new(
            egui::RichText::new(format!(
                "Group {} - {} share(s)",
                group_index + 1,
                share_count
            ))
            .strong()
            .color(section_color()),
        )
        .default_open(group_index == 0)
        .show(ui, |ui| {
            if let Some(shares) = group.as_array() {
                for (share_index, share) in shares.iter().enumerate() {
                    ui.add_space(4.0);
                    ui.colored_label(
                        subheader_color(),
                        egui::RichText::new(format!("Share {}", share_index + 1)).strong(),
                    );
                    render_share(ui, group_index, share_index, share, reveal_sensitive);
                }
            } else {
                render_json_field(ui, "Group Data", group, reveal_sensitive);
            }
        });
    }

    if let Some(sskr_map) = sskr.as_object() {
        let extra_fields = sskr_map
            .iter()
            .filter(|(key, _)| key.as_str() != "groups")
            .collect::<Vec<_>>();
        if !extra_fields.is_empty() {
            ui.colored_label(
                subheader_color(),
                egui::RichText::new("SSKR Metadata").strong(),
            );
            for (key, value) in extra_fields {
                render_json_field(ui, key, value, reveal_sensitive);
            }
        }
    }
}

fn render_share(
    ui: &mut egui::Ui,
    group_index: usize,
    share_index: usize,
    share: &serde_json::Value,
    reveal_sensitive: bool,
) {
    match share {
        serde_json::Value::Object(map) => {
            field_grid(
                ui,
                &format!("sskr_share_{group_index}_{share_index}_grid"),
                |ui| {
                    for key in ["share_hex", "mnemonic"] {
                        if let Some(value) = map.get(key) {
                            render_field_row(
                                ui,
                                human_json_key(key),
                                display_json_value(key, value, reveal_sensitive),
                                true,
                                sensitive_color(key, reveal_sensitive),
                            );
                        }
                    }
                    for (key, value) in map {
                        if key != "share_hex" && key != "mnemonic" {
                            render_field_row(
                                ui,
                                human_json_key(key),
                                display_json_value(key, value, reveal_sensitive),
                                should_use_monospace(key, value),
                                sensitive_color(key, reveal_sensitive),
                            );
                        }
                    }
                },
            );
        }
        _ => render_json_field(ui, "Share Data", share, reveal_sensitive),
    }
}

fn render_additional_fields(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    reveal_sensitive: bool,
) {
    let additional = map
        .iter()
        .filter(|(key, _)| !is_known_backup_key(key))
        .collect::<Vec<_>>();
    if additional.is_empty() {
        return;
    }

    section_header(ui, "Additional Fields");
    for (key, value) in additional {
        render_json_field(ui, key, value, reveal_sensitive);
    }
}

fn render_json_field(
    ui: &mut egui::Ui,
    key: &str,
    value: &serde_json::Value,
    reveal_sensitive: bool,
) {
    if is_sensitive_json_key(key) {
        field_grid(ui, &format!("json_sensitive_{key}_grid"), |ui| {
            render_field_row(
                ui,
                human_json_key(key),
                display_json_value(key, value, reveal_sensitive),
                true,
                sensitive_color(key, reveal_sensitive),
            );
        });
        return;
    }

    match value {
        serde_json::Value::Object(map) => {
            egui::CollapsingHeader::new(
                egui::RichText::new(format!("{} - {} field(s)", human_json_key(key), map.len()))
                    .strong()
                    .color(section_color()),
            )
            .default_open(true)
            .show(ui, |ui| {
                for (child_key, child_value) in map {
                    render_json_field(ui, child_key, child_value, reveal_sensitive);
                }
            });
        }
        serde_json::Value::Array(items) => {
            egui::CollapsingHeader::new(
                egui::RichText::new(format!("{} - {} item(s)", human_json_key(key), items.len()))
                    .strong()
                    .color(section_color()),
            )
            .default_open(items.len() <= 4)
            .show(ui, |ui| {
                for (index, item) in items.iter().enumerate() {
                    render_json_field(ui, &format!("Item {}", index + 1), item, reveal_sensitive);
                }
            });
        }
        _ => {
            field_grid(ui, &format!("json_scalar_{key}_grid"), |ui| {
                render_field_row(
                    ui,
                    human_json_key(key),
                    display_json_value(key, value, reveal_sensitive),
                    should_use_monospace(key, value),
                    egui::Color32::DARK_GRAY,
                );
            });
        }
    }
}

fn section_header(ui: &mut egui::Ui, title: &str) {
    ui.add_space(8.0);
    ui.colored_label(
        section_color(),
        egui::RichText::new(title).strong().size(16.0),
    );
}

fn field_grid(ui: &mut egui::Ui, id: &str, add_rows: impl FnOnce(&mut egui::Ui)) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([18.0, 6.0])
        .striped(true)
        .show(ui, add_rows);
}

fn render_field_row(
    ui: &mut egui::Ui,
    label: &str,
    value: String,
    monospace: bool,
    color: egui::Color32,
) {
    ui.colored_label(label_color(), egui::RichText::new(label).strong());
    let mut text = egui::RichText::new(value).color(color);
    if monospace {
        text = text.monospace();
    }
    ui.add(egui::Label::new(text).wrap());
    ui.end_row();
}

fn backup_kind_label(map: &serde_json::Map<String, serde_json::Value>) -> String {
    let sskr_groups = map
        .get("sskr")
        .and_then(|value| value.get("groups"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if sskr_groups > 0 {
        "SSKR share backup".to_string()
    } else if map.contains_key("seed_phrase") {
        "Mnemonic backup".to_string()
    } else {
        "JSON backup".to_string()
    }
}

fn display_json_value(key: &str, value: &serde_json::Value, reveal_sensitive: bool) -> String {
    if is_sensitive_json_key(key) && !reveal_sensitive {
        return masked_json_summary(value);
    }

    match value {
        serde_json::Value::Null => "None".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(items) => format!("{} item(s)", items.len()),
        serde_json::Value::Object(map) => format!("{} field(s)", map.len()),
    }
}

fn masked_json_summary(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => mask_secret_text(text),
        serde_json::Value::Array(items) => format!("<hidden: {} item(s)>", items.len()),
        serde_json::Value::Object(map) => format!("<hidden: {} field(s)>", map.len()),
        serde_json::Value::Null => "None".to_string(),
        _ => "<hidden>".to_string(),
    }
}

fn should_use_monospace(key: &str, value: &serde_json::Value) -> bool {
    is_sensitive_json_key(key)
        || matches!(
            value,
            serde_json::Value::String(text)
                if text.len() > 32 || text.starts_with("0x") || text.starts_with("age1")
        )
}

fn is_known_backup_key(key: &str) -> bool {
    matches!(
        key,
        "language"
            | "seed_phrase"
            | "passphrase"
            | "sskr"
            | "recovery_info"
            | "schema_version"
            | "backup_type"
            | "created_at_unix"
            | "tool_version"
            | "entropy"
            | "bip39_seed"
            | "bip32_root_key"
    )
}

fn human_json_key(key: &str) -> &str {
    match key {
        "language" => "Language",
        "seed_phrase" => "Seed Phrase",
        "passphrase" => "Passphrase",
        "sskr" => "SSKR",
        "groups" => "Groups",
        "share_hex" => "Share Hex",
        "mnemonic" => "Share Mnemonic",
        "recovery_info" => "Recovery Rule",
        "schema_version" => "Schema Version",
        "backup_type" => "Backup Type",
        "created_at_unix" => "Created",
        "tool_version" => "Tool Version",
        "entropy" => "Entropy",
        "bip39_seed" => "BIP-39 Seed",
        "bip32_root_key" => "BIP-32 Root Key",
        "private_key" => "Private Key",
        "privkey" => "Private Key",
        "xprv" => "Root XPRV",
        _ => key,
    }
}

fn section_color() -> egui::Color32 {
    egui::Color32::from_rgb(38, 91, 132)
}

fn subheader_color() -> egui::Color32 {
    egui::Color32::from_rgb(76, 116, 52)
}

fn label_color() -> egui::Color32 {
    egui::Color32::from_rgb(82, 82, 82)
}

fn sensitive_color(key: &str, reveal_sensitive: bool) -> egui::Color32 {
    if is_sensitive_json_key(key) && reveal_sensitive {
        egui::Color32::from_rgb(143, 74, 28)
    } else {
        egui::Color32::DARK_GRAY
    }
}

fn sskr_backup_from_entropy(
    entropy: &[u8],
    language: MnemonicLanguage,
    settings: SskrSettings,
) -> Result<(GuiSskrBackup, String), String> {
    validate_sskr_settings(settings)?;
    let secret = Secret::new(entropy).map_err(|err| format!("Invalid SSKR secret: {err:?}"))?;
    let group_specs = (0..settings.groups)
        .map(|_| {
            GroupSpec::new(
                settings.required_shares_per_group as usize,
                settings.shares_per_group as usize,
            )
            .map_err(|err| format!("Invalid SSKR group settings: {err:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let spec = Spec::new(settings.group_threshold as usize, group_specs)
        .map_err(|err| format!("Invalid SSKR settings: {err:?}"))?;
    let shares = sskr_generate(&spec, &secret)
        .map_err(|err| format!("Failed to generate SSKR shares: {err:?}"))?;

    let groups = shares
        .iter()
        .map(|group_shares| {
            group_shares
                .iter()
                .map(|share| GuiShare {
                    share_hex: hex::encode(share),
                    mnemonic: share_to_mnemonic(share, language.bip39()),
                })
                .collect()
        })
        .collect();

    Ok((GuiSskrBackup { groups }, sskr_rule_label(settings)))
}

fn shares_from_text(
    input: &str,
    language: MnemonicLanguage,
) -> Result<Zeroizing<Vec<Vec<u8>>>, String> {
    let mut shares = Zeroizing::new(Vec::new());
    for (line_index, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let share = parse_share(line, language)
            .map_err(|err| format!("Share {} is invalid: {err}", line_index + 1))?;
        push_unique_share(&mut shares, share)?;
    }
    if shares.is_empty() {
        return Err("Enter at least one SSKR share.".to_string());
    }
    Ok(shares)
}

fn shares_from_backup_json(
    value: &serde_json::Value,
    language: MnemonicLanguage,
) -> Result<Zeroizing<Vec<Vec<u8>>>, String> {
    let groups = value
        .get("sskr")
        .and_then(|sskr| sskr.get("groups"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Decrypted backup does not contain SSKR groups.".to_string())?;
    let mut shares = Zeroizing::new(Vec::new());
    for group in groups {
        let group = group
            .as_array()
            .ok_or_else(|| "SSKR group is not an array.".to_string())?;
        for share in group {
            let raw = share
                .get("share_hex")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .or_else(|| share.get("mnemonic").and_then(serde_json::Value::as_str))
                .unwrap_or("")
                .trim();
            if raw.is_empty() {
                continue;
            }
            let share = parse_share(raw, language)?;
            push_unique_share(&mut shares, share)?;
        }
    }
    if shares.is_empty() {
        return Err("Decrypted backup does not contain SSKR shares.".to_string());
    }
    Ok(shares)
}

fn parse_share(input: &str, language: MnemonicLanguage) -> Result<Vec<u8>, String> {
    if input.contains(char::is_whitespace) {
        mnemonic_to_share(input, language.bip39())
            .ok_or_else(|| "mnemonic share failed checksum validation".to_string())
    } else {
        hex::decode(input).map_err(|err| format!("hex decoding failed: {err}"))
    }
}

fn push_unique_share(shares: &mut Vec<Vec<u8>>, mut share: Vec<u8>) -> Result<(), String> {
    if shares.contains(&share) {
        share.zeroize();
        return Err("Duplicate SSKR share detected.".to_string());
    }
    shares.push(share);
    Ok(())
}

fn recover_mnemonic_from_shares(
    shares: &[Vec<u8>],
    language: MnemonicLanguage,
) -> Result<Zeroizing<String>, String> {
    let secret =
        sskr_combine(shares).map_err(|err| format!("Not enough valid SSKR shares yet: {err:?}"))?;
    let mut entropy = Zeroizing::new(secret.as_ref().to_vec());
    let mnemonic = Mnemonic::from_entropy_in(language.bip39(), entropy.as_slice())
        .map_err(|err| format!("Recovered SSKR entropy is not valid BIP-39 entropy: {err}"))?;
    entropy.zeroize();
    Ok(Zeroizing::new(mnemonic.to_string()))
}

fn recover_mnemonic_from_backup_json(
    value: &serde_json::Value,
    language: MnemonicLanguage,
) -> Result<Zeroizing<String>, String> {
    let mut shares = shares_from_backup_json(value, language)?;
    let result = recover_mnemonic_from_shares(shares.as_slice(), language);
    shares.zeroize();
    result
}

fn validate_sskr_settings(settings: SskrSettings) -> Result<(), String> {
    if settings.groups == 0 || settings.groups > MAX_SSKR_GROUPS {
        return Err(format!(
            "SSKR groups must be between 1 and {MAX_SSKR_GROUPS}."
        ));
    }
    if settings.group_threshold == 0 || settings.group_threshold > settings.groups {
        return Err("SSKR groups required must be between 1 and total groups.".to_string());
    }
    if settings.shares_per_group == 0 || settings.shares_per_group > MAX_SSKR_SHARES_PER_GROUP {
        return Err(format!(
            "SSKR shares per group must be between 1 and {MAX_SSKR_SHARES_PER_GROUP}."
        ));
    }
    if settings.required_shares_per_group == 0
        || settings.required_shares_per_group > settings.shares_per_group
    {
        return Err("SSKR shares required must be between 1 and shares per group.".to_string());
    }
    Ok(())
}

fn sskr_rule_label(settings: SskrSettings) -> String {
    format!(
        "Recovery rule: {} of {} group(s), {} of {} share(s) per group",
        settings.group_threshold,
        settings.groups,
        settings.required_shares_per_group,
        settings.shares_per_group
    )
}

fn share_to_mnemonic(share: &[u8], language: Language) -> String {
    let share_len = share.len() as u16;
    let mut payload = Zeroizing::new(Vec::with_capacity(2 + share.len() + 4));
    payload.extend_from_slice(&share_len.to_be_bytes());
    payload.extend_from_slice(share);
    let checksum = Sha256::digest(payload.as_slice());
    payload.extend_from_slice(&checksum[..4]);

    let mut bit_vec = Zeroizing::new(Vec::with_capacity(payload.len() * 8));
    for &byte in payload.iter() {
        for i in (0..8).rev() {
            bit_vec.push((byte >> i) & 1 == 1);
        }
    }
    while bit_vec.len() % 11 != 0 {
        bit_vec.push(false);
    }

    let wordlist = language.word_list();
    bit_vec
        .chunks(11)
        .map(|chunk| wordlist[bits_to_u16(chunk) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

fn bits_to_u16(bits: &[bool]) -> u16 {
    bits.iter()
        .fold(0, |acc, &bit| (acc << 1) | if bit { 1 } else { 0 })
}

fn bits_from_u16(num: u16, bits: usize) -> Vec<bool> {
    let mut bits_vec = Vec::with_capacity(bits);
    for i in (0..bits).rev() {
        bits_vec.push((num >> i) & 1 == 1);
    }
    bits_vec
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for &bit in chunk {
            byte = (byte << 1) | if bit { 1 } else { 0 };
        }
        if chunk.len() < 8 {
            byte <<= 8 - chunk.len();
        }
        bytes.push(byte);
    }
    bytes
}

fn mnemonic_to_share(mnemonic: &str, language: Language) -> Option<Vec<u8>> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let wordlist = language.word_list();
    let mut bits = Zeroizing::new(Vec::new());
    for word in words {
        let index = wordlist.iter().position(|&candidate| candidate == word)?;
        bits.extend(bits_from_u16(index as u16, 11));
    }
    if bits.len() < 16 {
        return None;
    }
    let share_len = bits_to_u16(&bits[0..16]) as usize;
    let required_bytes = 2 + share_len + 4;
    let required_bits = required_bytes * 8;
    if bits.len() < required_bits {
        return None;
    }
    let payload = Zeroizing::new(bits_to_bytes(&bits[..required_bits]));
    let (len_bytes, rest) = payload.split_at(2);
    let expected_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
    if expected_len != share_len {
        return None;
    }
    let (share_bytes, checksum_bytes) = rest.split_at(share_len);
    let mut check_payload = Zeroizing::new(Vec::with_capacity(2 + share_len));
    check_payload.extend_from_slice(len_bytes);
    check_payload.extend_from_slice(share_bytes);
    let checksum = Sha256::digest(check_payload.as_slice());
    if checksum_bytes != &checksum[..4] {
        return None;
    }
    Some(share_bytes.to_vec())
}

fn mask_secret_text(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    let word_count = text.split_whitespace().count();
    if word_count > 1 {
        return format!("<hidden: {word_count} words>");
    }
    let width = text.chars().count().clamp(8, 64);
    "*".repeat(width)
}

fn is_sensitive_json_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "seed_phrase"
            | "passphrase"
            | "entropy"
            | "bip39_seed"
            | "bip32_root_key"
            | "share_hex"
            | "mnemonic"
            | "private_key"
            | "privkey"
            | "xprv"
    ) || normalized.contains("secret")
        || normalized.contains("private")
}

fn status_label(ui: &mut egui::Ui, status: &str) {
    if status.is_empty() {
        return;
    }
    let color = if status.contains("failed")
        || status.contains("Failed")
        || status.contains("must")
        || status.contains("cannot")
        || status.contains("not ")
        || status.contains("requires")
        || status.contains("invalid")
    {
        egui::Color32::from_rgb(176, 38, 38)
    } else {
        egui::Color32::from_rgb(22, 108, 56)
    };
    ui.colored_label(color, status);
}

fn parse_backup_mnemonic(language: MnemonicLanguage, phrase: &str) -> Result<Mnemonic, String> {
    Mnemonic::parse_in_normalized(language.bip39(), phrase.trim())
        .map_err(|err| format!("Seed phrase is invalid for {}: {err}", language.label()))
}

fn seed_phrase_box(ui: &mut egui::Ui, phrase: &str, reveal: bool) {
    let display = Zeroizing::new(if phrase.is_empty() {
        String::new()
    } else if reveal {
        phrase.to_string()
    } else {
        phrase
            .split_whitespace()
            .map(|word| "*".repeat(word.len().max(4)))
            .collect::<Vec<_>>()
            .join(" ")
    });
    let mut readonly = display;
    ui.add(
        egui::TextEdit::multiline(&mut *readonly)
            .desired_rows(4)
            .lock_focus(true)
            .desired_width(f32::INFINITY)
            .interactive(false),
    );
}

fn expand_tilde(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            if path == "~" {
                return home.to_string_lossy().to_string();
            }
            if let Some(rest) = path.strip_prefix("~/") {
                let mut expanded = home;
                expanded.push(rest);
                return expanded.to_string_lossy().to_string();
            }
        }
    }
    path.to_string()
}

fn backup_save_path_from_input(input: &str) -> PathBuf {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return PathBuf::from(DEFAULT_BACKUP_FILE);
    }
    PathBuf::from(expand_tilde(trimmed))
}

fn save_parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn validate_save_path(path: &Path) -> Result<(), String> {
    let parent = save_parent_dir(path);
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!("Refusing to write to symlink: {}", path.display()));
        }
        if metadata.is_file() {
            return Err(format!(
                "Refusing to overwrite existing file: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            return Err(format!("Path is a directory: {}", path.display()));
        }
    }
    if !parent.is_dir() {
        return Err(format!(
            "Parent directory does not exist: {}",
            parent.display()
        ));
    }
    if let Ok(parent_metadata) = std::fs::symlink_metadata(parent) {
        if parent_metadata.file_type().is_symlink() {
            return Err(format!(
                "Parent directory is a symlink: {}",
                parent.display()
            ));
        }
    }
    Ok(())
}

fn is_supported_age_recipient(line: &str) -> bool {
    line.starts_with("age1") || line.starts_with("ssh-ed25519 ") || line.starts_with("ssh-rsa ")
}

fn age_recipient_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut remainder = line;
    while let Some(offset) = remainder.find("age1") {
        let start = offset;
        let token = remainder[start..]
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric())
            .collect::<String>();
        if is_supported_age_recipient(&token) {
            tokens.push(token);
        }
        let next_start = start + "age1".len();
        if next_start >= remainder.len() {
            break;
        }
        remainder = &remainder[next_start..];
    }
    tokens
}

fn push_unique_recipient(recipients: &mut Vec<String>, recipient: String) {
    if !recipients.contains(&recipient) {
        recipients.push(recipient);
    }
}

fn read_age_recipients_from_file(path: &str) -> Result<Vec<String>, String> {
    let contents = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|err| format!("Failed to read recipient file '{path}': {err}"))?,
    );
    let mut recipients = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("AGE-SECRET-KEY-") {
            continue;
        }
        if is_supported_age_recipient(line) {
            push_unique_recipient(&mut recipients, line.to_string());
            continue;
        }
        for token in age_recipient_tokens(line) {
            push_unique_recipient(&mut recipients, token);
        }
    }
    if recipients.is_empty() {
        return Err("No age recipient found in file.".to_string());
    }
    Ok(recipients)
}

fn age_recipients_from_input(input: &str) -> Result<Vec<String>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Recipient cannot be empty.".to_string());
    }

    if is_supported_age_recipient(trimmed) {
        return Ok(vec![trimmed.to_string()]);
    }

    if trimmed.starts_with("AGE-SECRET-KEY-") {
        return Err("That is a private age identity, not a public recipient.".to_string());
    }

    let expanded = expand_tilde(trimmed);
    let path = Path::new(&expanded);
    if path.exists() {
        return read_age_recipients_from_file(&expanded);
    }

    if looks_like_path(trimmed) {
        return Err(format!(
            "Recipient file not found: '{}'. Paste a public recipient directly, or provide an existing recipient file.",
            expanded
        ));
    }

    Err(
        "Recipient must be a public age/SSH recipient, or a path to a file containing one."
            .to_string(),
    )
}

enum AgeIdentityInput {
    File(PathBuf),
    LiteralSecret(Zeroizing<String>),
}

fn looks_like_path(input: &str) -> bool {
    input.starts_with('~')
        || input.starts_with('.')
        || input.starts_with('/')
        || input.contains(std::path::MAIN_SEPARATOR)
}

fn age_identity_from_input(input: &str) -> Result<AgeIdentityInput, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Identity cannot be empty.".to_string());
    }

    let expanded = expand_tilde(trimmed);
    let path = PathBuf::from(&expanded);
    if path.exists() {
        return Ok(AgeIdentityInput::File(path));
    }

    if trimmed.starts_with("AGE-SECRET-KEY-") {
        return Ok(AgeIdentityInput::LiteralSecret(Zeroizing::new(
            trimmed.to_string(),
        )));
    }

    if is_supported_age_recipient(trimmed)
        || trimmed.starts_with("Public key:")
        || trimmed.starts_with("# public key:")
    {
        return Err(
            "That is a public age recipient. Decryption requires a private AGE-SECRET-KEY identity or identity file."
                .to_string(),
        );
    }

    if looks_like_path(trimmed) {
        return Err(format!("Identity file not found: '{expanded}'"));
    }

    Err(
        "Identity must be an existing identity file path or a literal AGE-SECRET-KEY value."
            .to_string(),
    )
}

fn resolve_age_binary(
    override_binary: Option<OsString>,
    current_executable: Option<&Path>,
) -> OsString {
    if let Some(binary) = override_binary {
        return binary;
    }

    if let Some(bundled_binary) = current_executable
        .and_then(Path::parent)
        .map(|directory| directory.join("age"))
        .filter(|path| path.is_file())
    {
        return bundled_binary.into_os_string();
    }

    "age".into()
}

fn age_command() -> Command {
    let current_executable = std::env::current_exe().ok();
    let binary = resolve_age_binary(
        std::env::var_os("BIP39_AGE_BINARY"),
        current_executable.as_deref(),
    );
    Command::new(binary)
}

fn encrypt_data(plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("At least one recipient is required.".to_string());
    }

    let mut command = age_command();
    for recipient in recipients {
        command.arg("-r").arg(recipient);
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                "Failed to spawn age: binary not found in PATH.".to_string()
            } else {
                format!("Failed to spawn age: {err}")
            }
        })?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| "Failed to open stdin for age.".to_string())?
        .write_all(plaintext)
        .map_err(|err| format!("Failed to write to age stdin: {err}"))?;

    let output = child
        .wait_with_output()
        .map_err(|err| format!("Failed to read age output: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(output.stdout)
}

fn decrypt_data(ciphertext: &[u8], identity_input: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let identity = age_identity_from_input(identity_input)?;
    let mut _ciphertext_file = None;
    let mut command = age_command();
    command.arg("-d").arg("-i");

    match &identity {
        AgeIdentityInput::File(path) => {
            command.arg(path);
        }
        AgeIdentityInput::LiteralSecret(_) => {
            let mut temp = tempfile::NamedTempFile::new()
                .map_err(|err| format!("Failed to create temp ciphertext file: {err}"))?;
            temp.write_all(ciphertext)
                .map_err(|err| format!("Failed to write ciphertext: {err}"))?;
            temp.as_file()
                .sync_all()
                .map_err(|err| format!("Failed to sync ciphertext: {err}"))?;
            command.arg("-").arg(temp.path());
            _ciphertext_file = Some(temp);
        }
    }

    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                "Failed to spawn age: binary not found in PATH.".to_string()
            } else {
                format!("Failed to spawn age: {err}")
            }
        })?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| "Failed to open stdin for age.".to_string())?;
    match &identity {
        AgeIdentityInput::File(_) => {
            stdin
                .write_all(ciphertext)
                .map_err(|err| format!("Failed to write to age stdin: {err}"))?;
        }
        AgeIdentityInput::LiteralSecret(secret) => {
            stdin
                .write_all(secret.as_bytes())
                .map_err(|err| format!("Failed to write identity to age stdin: {err}"))?;
            if !secret.ends_with('\n') {
                stdin
                    .write_all(b"\n")
                    .map_err(|err| format!("Failed to finalize identity: {err}"))?;
            }
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|err| format!("Failed to read age output: {err}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(Zeroizing::new(output.stdout))
}

fn persist_noclobber(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|err| format!("Failed to create {}: {err}", path.display()))?;

    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("Failed to write {}: {err}", path.display()))
}

fn derivation_path_for(kind: AddressKind, index: u32, hardened: bool) -> String {
    match kind {
        AddressKind::Bitcoin => {
            if hardened {
                format!("m/84'/0'/0'/0/{}'", index)
            } else {
                format!("m/84'/0'/0'/0/{index}")
            }
        }
        AddressKind::Ethereum => {
            if hardened {
                format!("m/44'/60'/0'/0/{}'", index)
            } else {
                format!("m/44'/60'/0'/0/{index}")
            }
        }
        AddressKind::Xrp => format!("m/44'/144'/0'/0/{index}"),
        AddressKind::Solana => format!("m/44'/501'/{index}'/0'"),
    }
}

fn derive_address_rows(
    seed: &[u8],
    kind: AddressKind,
    start: u32,
    end: u32,
    hardened: bool,
) -> Result<Vec<AddressRow>, String> {
    let mut rows = Vec::with_capacity((end - start + 1) as usize);

    match kind {
        AddressKind::Bitcoin | AddressKind::Ethereum | AddressKind::Xrp => {
            let secp = Secp256k1::new();
            let master_xprv = Xpriv::new_master(Network::Bitcoin, seed)
                .map_err(|err| format!("Failed to derive master key: {err}"))?;
            for index in start..=end {
                let path = derivation_path_for(kind, index, hardened);
                let derivation_path = path
                    .parse::<DerivationPath>()
                    .map_err(|err| format!("Invalid derivation path: {err}"))?;
                let child_xprv = master_xprv
                    .derive_priv(&secp, &derivation_path)
                    .map_err(|err| format!("Failed to derive child key: {err}"))?;
                let public_key = PublicKey::from_secret_key(&secp, &child_xprv.private_key);

                let (address, public_key_hex) = match kind {
                    AddressKind::Bitcoin => {
                        let bitcoin_pubkey = bitcoin::PublicKey {
                            compressed: true,
                            inner: public_key,
                        };
                        let compressed = bitcoin::key::CompressedPublicKey::from_slice(
                            &bitcoin_pubkey.to_bytes(),
                        )
                        .map_err(|err| format!("Invalid compressed public key: {err}"))?;
                        (
                            Address::p2wpkh(&compressed, Network::Bitcoin).to_string(),
                            hex::encode(public_key.serialize()),
                        )
                    }
                    AddressKind::Ethereum => (
                        ethereum_address_from_pubkey(&public_key),
                        format!("0x{}", hex::encode(public_key.serialize_uncompressed())),
                    ),
                    AddressKind::Xrp => (
                        xrp_address_from_pubkey(&public_key),
                        hex::encode(public_key.serialize()),
                    ),
                    AddressKind::Solana => unreachable!(),
                };

                rows.push(AddressRow {
                    index,
                    path,
                    address,
                    public_key: public_key_hex,
                });
            }
        }
        AddressKind::Solana => {
            for index in start..=end {
                let path = derivation_path_for(kind, index, true);
                let derived =
                    Zeroizing::new(derive_slip10_ed25519_key(seed, &[44, 501, index, 0])?);
                let signing_key = SigningKey::from_bytes(&derived.key);
                let verifying_key = VerifyingKey::from(&signing_key);

                rows.push(AddressRow {
                    index,
                    path,
                    address: bs58::encode(verifying_key.to_bytes()).into_string(),
                    public_key: hex::encode(verifying_key.to_bytes()),
                });
            }
        }
    }

    Ok(rows)
}

type HmacSha512 = Hmac<Sha512>;

struct Slip10Ed25519Key {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl Zeroize for Slip10Ed25519Key {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

fn derive_slip10_ed25519_key(seed: &[u8], path: &[u32]) -> Result<Slip10Ed25519Key, String> {
    let mut key = Zeroizing::new(slip10_hmac_key(b"ed25519 seed", seed));

    for index in path {
        key = Zeroizing::new(slip10_child_key(&key, *index)?);
    }

    let mut final_key = Slip10Ed25519Key {
        key: [0u8; 32],
        chain_code: [0u8; 32],
    };
    final_key.key.copy_from_slice(&key.key);
    final_key.chain_code.copy_from_slice(&key.chain_code);
    Ok(final_key)
}

fn slip10_child_key(parent: &Slip10Ed25519Key, index: u32) -> Result<Slip10Ed25519Key, String> {
    if index >= BIP32_HARDENED_OFFSET {
        return Err(format!(
            "Solana derivation index must be below {BIP32_HARDENED_OFFSET}."
        ));
    }

    let hardened_index = index + BIP32_HARDENED_OFFSET;
    let mut data = Zeroizing::new([0u8; 37]);
    data[1..33].copy_from_slice(&parent.key);
    data[33..].copy_from_slice(&hardened_index.to_be_bytes());

    Ok(slip10_hmac_key(&parent.chain_code, &data[..]))
}

fn slip10_hmac_key(key: &[u8], data: &[u8]) -> Slip10Ed25519Key {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let mut output = mac.finalize().into_bytes();

    let mut private_key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    private_key.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);
    output.as_mut_slice().zeroize();

    Slip10Ed25519Key {
        key: private_key,
        chain_code,
    }
}

fn ethereum_address_from_pubkey(pubkey: &PublicKey) -> String {
    let uncompressed = pubkey.serialize_uncompressed();
    let pubkey_bytes = &uncompressed[1..];
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(pubkey_bytes);
    keccak.finalize(&mut hash);
    to_checksum_address(&hex::encode(&hash[12..]))
}

fn to_checksum_address(address: &str) -> String {
    let address_lower = address.to_lowercase();
    let mut keccak = tiny_keccak::Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(address_lower.as_bytes());
    keccak.finalize(&mut hash);
    let mut checksum_address = String::from("0x");
    for (index, ch) in address_lower.chars().enumerate() {
        let hash_byte = hash[index / 2];
        let nibble = if index % 2 == 0 {
            (hash_byte >> 4) & 0x0f
        } else {
            hash_byte & 0x0f
        };
        if nibble >= 8 {
            checksum_address.push(ch.to_ascii_uppercase());
        } else {
            checksum_address.push(ch);
        }
    }
    checksum_address
}

fn xrp_address_from_pubkey(pubkey: &PublicKey) -> String {
    let pubkey_bytes = pubkey.serialize();
    let sha256_hash = Sha256::digest(pubkey_bytes);
    use bitcoin::hashes::{ripemd160, Hash};
    let ripemd_hash = ripemd160::Hash::hash(&sha256_hash);
    let mut payload = Vec::with_capacity(25);
    payload.push(0x00);
    payload.extend_from_slice(&ripemd_hash[..]);
    let checksum_source = Sha256::digest(Sha256::digest(&payload));
    payload.extend_from_slice(&checksum_source[0..4]);
    let alphabet =
        bs58::Alphabet::new(b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")
            .expect("static XRP base58 alphabet is valid");
    bs58::encode(payload).with_alphabet(&alphabet).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_pq_recipient_is_accepted() {
        assert_eq!(
            age_recipients_from_input("age1pq1directexample").unwrap(),
            vec!["age1pq1directexample"]
        );
    }

    #[test]
    fn bundled_age_next_to_application_binary_is_preferred_over_path() {
        let tempdir = tempfile::tempdir().unwrap();
        let executable = tempdir.path().join("bip39");
        let bundled_age = tempdir.path().join("age");
        std::fs::write(&bundled_age, b"bundled age").unwrap();

        assert_eq!(
            resolve_age_binary(None, Some(&executable)),
            bundled_age.into_os_string()
        );
    }

    #[test]
    fn configured_age_binary_overrides_bundled_binary() {
        let tempdir = tempfile::tempdir().unwrap();
        let executable = tempdir.path().join("bip39");
        std::fs::write(tempdir.path().join("age"), b"bundled age").unwrap();
        let configured = OsString::from("/custom/age");

        assert_eq!(
            resolve_age_binary(Some(configured.clone()), Some(&executable)),
            configured
        );
    }

    #[test]
    fn age_binary_falls_back_to_path_lookup() {
        assert_eq!(resolve_age_binary(None, None), OsString::from("age"));
    }

    #[test]
    fn recipient_file_extracts_embedded_age_recipient() {
        let tempdir = tempfile::tempdir().unwrap();
        let recipient_file = tempdir.path().join("config.toml.tmpl");
        std::fs::write(
            &recipient_file,
            r#"
encryption = "age"
recipient = "age1pq1embeddedexample"
# public key: age1secondexample
AGE-SECRET-KEY-should-be-ignored
"#,
        )
        .unwrap();

        assert_eq!(
            age_recipients_from_input(recipient_file.to_str().unwrap()).unwrap(),
            vec![
                "age1pq1embeddedexample".to_string(),
                "age1secondexample".to_string()
            ]
        );
    }

    #[test]
    fn public_recipient_is_rejected_as_identity() {
        let result = age_identity_from_input(
            "age1ezr4w5zvw6utpnjt6htr9a7jg9d8y6gf70lg8hxhzw33fng275mqa0cdu5",
        );
        let Err(err) = result else {
            panic!("public recipient should not be accepted as an age identity");
        };
        assert!(err.contains("public age recipient"));
    }

    #[test]
    fn empty_path_uses_default_backup_file() {
        assert_eq!(
            backup_save_path_from_input(""),
            PathBuf::from(DEFAULT_BACKUP_FILE)
        );
    }

    #[test]
    fn imported_seed_phrase_is_validated_and_canonicalized() {
        let phrase = "  abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        let mnemonic = parse_backup_mnemonic(MnemonicLanguage::English, phrase).unwrap();

        assert_eq!(
            mnemonic.to_string(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn imported_seed_phrase_must_match_selected_language_and_checksum() {
        let err = parse_backup_mnemonic(
            MnemonicLanguage::English,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        )
        .unwrap_err();

        assert!(err.contains("Seed phrase is invalid for English"));
    }

    #[test]
    fn bare_filename_parent_is_current_directory() {
        assert_eq!(save_parent_dir(Path::new("backup.age")), Path::new("."));
    }

    #[test]
    fn backup_display_helpers_classify_and_mask_sensitive_values() {
        let backup_json = serde_json::json!({
            "language": "English",
            "seed_phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "sskr": {
                "groups": [[{
                    "share_hex": "0123456789abcdef",
                    "mnemonic": "alpha beta gamma"
                }]]
            },
            "recovery_info": "SSKR backup"
        });

        let map = backup_json.as_object().unwrap();
        assert_eq!(backup_kind_label(map), "SSKR share backup");
        assert_eq!(
            display_json_value("language", &backup_json["language"], false),
            "English"
        );
        assert_eq!(
            display_json_value("recovery_info", &backup_json["recovery_info"], false),
            "SSKR backup"
        );

        let masked_seed = display_json_value("seed_phrase", &backup_json["seed_phrase"], false);
        assert!(masked_seed.contains("<hidden: 12 words>"));
        assert!(!masked_seed.contains("abandon abandon"));

        let share = &backup_json["sskr"]["groups"][0][0];
        let masked_share_hex = display_json_value("share_hex", &share["share_hex"], false);
        assert!(!masked_share_hex.contains("0123456789abcdef"));
        assert_eq!(
            display_json_value("share_hex", &share["share_hex"], true),
            "0123456789abcdef"
        );

        let summary = BackupSummary::from_json(&backup_json);
        assert_eq!(summary.seed_storage_label(), "Seed storage: mnemonic");
        assert!(!summary.recovered_from_sskr);
    }

    #[test]
    fn slip10_ed25519_derivation_matches_reference_vector() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = derive_slip10_ed25519_key(&seed, &[0, 1]).unwrap();

        assert_eq!(
            hex::encode(key.key),
            "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"
        );
        assert_eq!(
            hex::encode(key.chain_code),
            "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"
        );
    }

    #[test]
    fn sskr_backup_generation_uses_configured_group_and_share_counts() {
        let entropy = [7u8; 32];
        let settings = SskrSettings {
            groups: 2,
            group_threshold: 1,
            shares_per_group: 3,
            required_shares_per_group: 2,
        };

        let (backup, recovery_info) =
            sskr_backup_from_entropy(&entropy, MnemonicLanguage::English, settings).unwrap();
        assert_eq!(backup.groups.len(), 2);
        assert!(backup.groups.iter().all(|group| group.len() == 3));
        assert!(backup.groups[0][0].share_hex.len() > 16);
        assert!(backup.groups[0][0].mnemonic.split_whitespace().count() > 3);
        assert_eq!(
            recovery_info,
            "Recovery rule: 1 of 2 group(s), 2 of 3 share(s) per group"
        );
    }

    #[test]
    fn sskr_backup_shares_recover_original_mnemonic() {
        let entropy = [9u8; 32];
        let expected_mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .unwrap()
            .to_string();
        let settings = SskrSettings {
            groups: 1,
            group_threshold: 1,
            shares_per_group: 3,
            required_shares_per_group: 2,
        };

        let (sskr, _) =
            sskr_backup_from_entropy(&entropy, MnemonicLanguage::English, settings).unwrap();
        let backup_json = serde_json::json!({
            "language": "English",
            "sskr": sskr,
        });
        let summary = BackupSummary::from_json(&backup_json);
        assert_eq!(summary.seed_storage_label(), "Seed storage: SSKR shares");
        let automatically_recovered =
            recover_mnemonic_from_backup_json(&backup_json, MnemonicLanguage::English).unwrap();
        assert_eq!(automatically_recovered.as_str(), expected_mnemonic);

        let mut shares = shares_from_backup_json(&backup_json, MnemonicLanguage::English).unwrap();
        shares.truncate(2);

        let recovered =
            recover_mnemonic_from_shares(shares.as_slice(), MnemonicLanguage::English).unwrap();
        assert_eq!(recovered.as_str(), expected_mnemonic);
        shares.zeroize();
    }

    #[test]
    fn validate_save_path_rejects_existing_files() {
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("backup.age");
        std::fs::write(&path, b"existing").unwrap();

        let err = validate_save_path(&path).unwrap_err();
        assert!(err.contains("overwrite existing file"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_save_path_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let real_dir = tempdir.path().join("real");
        let link_dir = tempdir.path().join("link");
        std::fs::create_dir(&real_dir).unwrap();
        symlink(&real_dir, &link_dir).unwrap();

        let err = validate_save_path(&link_dir.join("backup.age")).unwrap_err();
        assert!(err.contains("Parent directory is a symlink"));
    }

    #[test]
    fn sskr_settings_reject_required_counts_above_totals() {
        let settings = SskrSettings {
            groups: 2,
            group_threshold: 3,
            shares_per_group: 3,
            required_shares_per_group: 2,
        };
        assert!(validate_sskr_settings(settings).is_err());

        let settings = SskrSettings {
            groups: 2,
            group_threshold: 1,
            shares_per_group: 3,
            required_shares_per_group: 4,
        };
        assert!(validate_sskr_settings(settings).is_err());
    }
}
