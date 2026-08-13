#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime},
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
const FORM_LABEL_WIDTH: f32 = 148.0;
const FORM_BUTTON_WIDTH: f32 = 118.0;
const FIELD_HEIGHT: f32 = 34.0;
const MAX_DERIVE_COUNT: u32 = 100;
const MAX_SSKR_GROUPS: u8 = 16;
const MAX_SSKR_SHARES_PER_GROUP: u8 = 16;
const BACKUP_SCHEMA_VERSION: u32 = 2;
const BIP32_HARDENED_OFFSET: u32 = 1 << 31;
const BUNDLED_AGE_VERSION: &str = "1.3.1";
const AGE_RELEASE_API: &str = "https://api.github.com/repos/FiloSottile/age/releases/latest";
const AGE_DOWNLOAD_PREFIX: &str = "https://github.com/FiloSottile/age/releases/download/";
const AGE_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_AGE_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_AGE_EXECUTABLE_BYTES: u64 = 24 * 1024 * 1024;
const MAX_AGE_LICENSE_BYTES: u64 = 2 * 1024 * 1024;

fn embedded_app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/bip39-tool-icon-256.png"))
        .expect("embedded application icon must be a valid PNG")
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 860.0])
            .with_min_inner_size([960.0, 680.0])
            .with_icon(embedded_app_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "BIP39 Tool",
        options,
        Box::new(|cc| {
            configure_ui_style(&cc.egui_ctx);
            spawn_age_auto_update();
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

    fn seed_storage_label(&self, language: GuidanceLanguage) -> &'static str {
        if self.has_seed_phrase {
            match language {
                GuidanceLanguage::English => "Seed storage: mnemonic",
                GuidanceLanguage::SimplifiedChinese => "备份内容：助记词",
                GuidanceLanguage::Japanese => "保存内容：ニーモニック",
                GuidanceLanguage::Korean => "백업 내용: 니모닉",
            }
        } else if self.sskr_groups > 0 {
            match language {
                GuidanceLanguage::English => "Seed storage: SSKR shares",
                GuidanceLanguage::SimplifiedChinese => "备份内容：SSKR 份额",
                GuidanceLanguage::Japanese => "保存内容：SSKR シェア",
                GuidanceLanguage::Korean => "백업 내용: SSKR 조각",
            }
        } else {
            match language {
                GuidanceLanguage::English => "Seed storage: missing",
                GuidanceLanguage::SimplifiedChinese => "备份内容：未找到助记词",
                GuidanceLanguage::Japanese => "保存内容：ニーモニックなし",
                GuidanceLanguage::Korean => "백업 내용: 니모닉 없음",
            }
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

#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
enum Tab {
    #[default]
    Generate,
    Decrypt,
    Recover,
    Addresses,
}

impl Tab {
    const ALL: [Self; 4] = [
        Self::Generate,
        Self::Decrypt,
        Self::Recover,
        Self::Addresses,
    ];

    fn title(self, language: GuidanceLanguage) -> &'static str {
        language.text(match self {
            Self::Generate => "Create encrypted backup",
            Self::Decrypt => "Open encrypted backup",
            Self::Recover => "Recover from SSKR shares",
            Self::Addresses => "Address derivation",
        })
    }

    fn subtitle(self, language: GuidanceLanguage) -> &'static str {
        language.text(match self {
            Self::Generate => "Protect a new or existing BIP-39 seed with age encryption.",
            Self::Decrypt => "Inspect a backup and load its seed material securely.",
            Self::Recover => "Reconstruct a seed from a sufficient set of recovery shares.",
            Self::Addresses => "Derive public wallet data without exposing private keys.",
        })
    }

    fn nav_label(self, language: GuidanceLanguage) -> &'static str {
        language.text(match self {
            Self::Generate => "Create backup",
            Self::Decrypt => "Open backup",
            Self::Recover => "Recover SSKR",
            Self::Addresses => "Addresses",
        })
    }

    fn nav_hint(self, language: GuidanceLanguage) -> &'static str {
        language.text(match self {
            Self::Generate => "Encrypt seed material",
            Self::Decrypt => "Decrypt and inspect",
            Self::Recover => "Combine recovery shares",
            Self::Addresses => "Derive public keys",
        })
    }

    fn icon(self) -> UiIcon {
        match self {
            Self::Generate => UiIcon::Backup,
            Self::Decrypt => UiIcon::Open,
            Self::Recover => UiIcon::Recovery,
            Self::Addresses => UiIcon::Wallet,
        }
    }
}

#[derive(Clone, Copy)]
enum UiIcon {
    Backup,
    Open,
    Recovery,
    Wallet,
    Shield,
    Key,
    Save,
    Spark,
    Info,
    Trash,
    Arrow,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum GuidanceLanguage {
    #[default]
    English,
    SimplifiedChinese,
    Japanese,
    Korean,
}

impl GuidanceLanguage {
    const ALL: [Self; 4] = [
        Self::English,
        Self::SimplifiedChinese,
        Self::Japanese,
        Self::Korean,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::SimplifiedChinese => "简体中文",
            Self::Japanese => "日本語",
            Self::Korean => "한국어",
        }
    }

    fn text(self, english: &'static str) -> &'static str {
        match self {
            Self::English => english,
            Self::SimplifiedChinese => match english {
                "Encrypted recovery" => "助记词备份与恢复",
                "Clear sensitive data" => "清除敏感信息",
                "Secrets: memory only" => "敏感信息仅存内存",
                "Guidance" => "操作提示",
                "Create encrypted backup" => "创建加密备份",
                "Open encrypted backup" => "打开加密备份",
                "Recover from SSKR shares" => "从 SSKR 份额恢复",
                "Address derivation" => "派生地址",
                "Protect a new or existing BIP-39 seed with age encryption." => {
                    "使用 age 加密备份新生成或已有的 BIP-39 助记词。"
                }
                "Inspect a backup and load its seed material securely." => {
                    "解密并检查备份，安全载入其中的助记词。"
                }
                "Reconstruct a seed from a sufficient set of recovery shares." => {
                    "组合满足门限要求的 SSKR 份额，恢复原始种子。"
                }
                "Derive public wallet data without exposing private keys." => {
                    "仅派生钱包的公开地址和公钥，不显示私钥。"
                }
                "Create backup" => "创建备份",
                "Open backup" => "打开备份",
                "Recover SSKR" => "恢复 SSKR",
                "Addresses" => "派生地址",
                "Encrypt seed material" => "加密助记词备份",
                "Decrypt and inspect" => "解密并查看内容",
                "Combine recovery shares" => "组合 SSKR 份额",
                "Derive public keys" => "生成公开地址",
                "Seed material" => "助记词与附加密码",
                "Choose the mnemonic and optional BIP-39 passphrase to protect." => {
                    "选择要备份的助记词，并按需填写 BIP-39 附加密码。"
                }
                "Source" => "输入方式",
                "Generate new" => "新建助记词",
                "Import existing" => "输入已有助记词",
                "Language" => "语言",
                "Generate seed" => "生成助记词",
                "Seed phrase" => "助记词",
                "Reveal generated phrase" => "显示生成的助记词",
                "Passphrase" => "附加密码",
                "Optional BIP-39 passphrase" => "BIP-39 附加密码（可选）",
                "Reveal passphrase" => "显示附加密码",
                "Include passphrase in encrypted backup" => "将附加密码写入加密备份",
                "Recovery format" => "备份方式",
                "Optionally replace the stored mnemonic with threshold recovery shares." => {
                    "可将助记词转换为具有门限保护的 SSKR 份额后再备份。"
                }
                "Split seed into recovery shares" => "改用 SSKR 恢复份额",
                "Groups" => "恢复组",
                "Create" => "总数",
                "Require" => "门限",
                "Shares per group" => "每组份额数",
                "Recovery rule" => "恢复门限",
                "Encrypt and save" => "加密并保存",
                "Select who can decrypt the backup and where the encrypted file is written." => {
                    "指定用于加密的 age 接收公钥，并选择备份文件的保存位置。"
                }
                "Recipient" => "age 接收公钥",
                "Choose file" => "选择文件",
                "Backup file" => "备份文件",
                "Save as" => "另存为",
                "Unlock backup" => "解密备份",
                "Choose the encrypted file and supply a matching private age identity." => {
                    "选择加密备份，并提供与接收公钥匹配的 age 解密私钥。"
                }
                "Open file" => "打开文件",
                "Private identity" => "age 解密私钥",
                "Reveal identity" => "显示解密私钥",
                "Decrypt backup" => "解密备份",
                "Decrypted contents" => "备份内容",
                "Sensitive values remain masked until you explicitly reveal them." => {
                    "敏感值将保持隐藏，直到你明确选择显示。"
                }
                "Recovery complete" => "恢复完成",
                "Reveal sensitive values" => "显示敏感值",
                "Open address derivation" => "打开地址派生",
                "Recovery shares" => "SSKR 恢复份额",
                "Paste one unique hexadecimal or mnemonic SSKR share per line." => {
                    "每行粘贴一份且不要重复；支持十六进制或助记词形式的 SSKR 份额。"
                }
                "Share language" => "份额语言",
                "SSKR shares" => "SSKR 份额",
                "Wallet passphrase" => "BIP-39 附加密码",
                "Enter the original BIP-39 passphrase if this wallet used one." => {
                    "如果创建钱包时使用了 BIP-39 附加密码，请在此输入完全相同的内容。"
                }
                "Recover seed" => "恢复种子",
                "Derivation inputs" => "钱包信息",
                "Use a loaded backup or paste a valid BIP-39 mnemonic manually." => {
                    "使用已载入的备份，或手动粘贴有效的 BIP-39 助记词。"
                }
                "Network" => "网络",
                "Index range" => "索引范围",
                "Start" => "开始",
                "End" => "结束",
                "Harden final index" => "末级索引使用硬化派生",
                "Derive addresses" => "派生地址",
                "Public results" => "派生结果",
                "Addresses and public keys are safe to share; no private keys are displayed." => {
                    "这些地址和公钥可以安全分享；不会显示任何私钥。"
                }
                "Index" => "索引",
                "Path" => "路径",
                "Address" => "地址",
                "Public key" => "公钥",
                "Choose age recipient file" => "选择 age 接收公钥文件",
                "Choose age identity file" => "选择 age 解密私钥文件",
                "Supported files" => "支持的文件",
                "Save encrypted backup" => "保存加密备份",
                "age backup" => "age 备份",
                "Backup Summary" => "备份摘要",
                "Type" => "类型",
                "Recovery Rule" => "恢复门限",
                "Top-Level Fields" => "顶层字段",
                "SSKR Recovery" => "SSKR 恢复",
                "Recovered automatically" => "已自动恢复",
                "Recovered Seed Material" => "已恢复的助记词信息",
                "Seed Material" => "助记词信息",
                "SSKR Shares" => "SSKR 份额",
                "Total Shares" => "份额总数",
                "Additional Fields" => "其他字段",
                "Decrypted JSON" => "已解密 JSON",
                "Value" => "值",
                "Group Data" => "组数据",
                "Share Data" => "份额数据",
                "SSKR Metadata" => "SSKR 元数据",
                "None" => "无",
                "Schema Version" => "架构版本",
                "Backup Type" => "备份类型",
                "Created" => "创建时间",
                "Tool Version" => "工具版本",
                "Share Hex" => "份额十六进制",
                "Share Mnemonic" => "份额助记词",
                "Entropy" => "熵",
                "Private Key" => "私钥",
                "Root XPRV" => "根 XPRV",
                "Scroll for more" => "下方还有内容",
                "Generated a new 24-word seed." => "已生成一组新的 24 词助记词。",
                "Address inputs loaded from the new seed." => "新助记词已同步到地址派生页面。",
                "Generate a seed before saving." => "请先生成助记词，再保存备份。",
                "Enter a seed phrase before saving." => "请先输入助记词再保存。",
                "Address inputs loaded from the decrypted backup." => "备份中的助记词已载入地址派生页面。",
                "Backup decrypted and seed loaded into address derivation." => {
                    "备份已解密，助记词已载入地址派生页面。"
                }
                "Recovered SSKR seed loaded." => "已载入通过 SSKR 恢复的种子。",
                "Backup decrypted, and the SSKR seed was recovered automatically." => {
                    "备份已解密，SSKR 种子已自动恢复。"
                }
                "Backup decrypted, but it does not contain a seed phrase." => {
                    "备份已解密，但其中没有助记词。"
                }
                "Backup decrypted, but it does not contain seed material." => {
                    "备份已解密，但其中没有可用的助记词或 SSKR 份额。"
                }
                "Enter or load a seed phrase first." => "请先输入或载入助记词。",
                "Start index must be a number." => "起始索引必须是数字。",
                "End index must be a number." => "结束索引必须是数字。",
                "Start index cannot be greater than end index." => "起始索引不能大于结束索引。",
                "Seed recovered and loaded into address derivation." => {
                    "种子已恢复，并载入地址派生页面。"
                }
                "Sensitive GUI state cleared." => "已从内存中清除本次操作的敏感信息。",
                "Error" => "错误",
                _ => english,
            },
            Self::Japanese => match english {
                "Encrypted recovery" => "シードのバックアップと復元",
                "Clear sensitive data" => "機密情報を消去",
                "Secrets: memory only" => "機密情報はメモリ内のみ",
                "Guidance" => "操作ガイド",
                "Create encrypted backup" => "暗号化バックアップを作成",
                "Open encrypted backup" => "暗号化バックアップを開く",
                "Recover from SSKR shares" => "SSKR シェアから復元",
                "Address derivation" => "アドレス導出",
                "Protect a new or existing BIP-39 seed with age encryption." => {
                    "新規または既存の BIP-39 ニーモニックを age で暗号化して保存します。"
                }
                "Inspect a backup and load its seed material securely." => {
                    "バックアップを復号して内容を確認し、ニーモニックを安全に読み込みます。"
                }
                "Reconstruct a seed from a sufficient set of recovery shares." => {
                    "しきい値を満たす SSKR シェアを組み合わせて元のシードを復元します。"
                }
                "Derive public wallet data without exposing private keys." => {
                    "秘密鍵を表示せず、ウォレットの公開アドレスと公開鍵だけを導出します。"
                }
                "Create backup" => "バックアップ作成",
                "Open backup" => "バックアップを開く",
                "Recover SSKR" => "SSKR を復元",
                "Addresses" => "アドレス導出",
                "Encrypt seed material" => "ニーモニックを暗号化",
                "Decrypt and inspect" => "復号して内容を確認",
                "Combine recovery shares" => "SSKR シェアを結合",
                "Derive public keys" => "公開アドレスを生成",
                "Seed material" => "ニーモニックとパスフレーズ",
                "Choose the mnemonic and optional BIP-39 passphrase to protect." => {
                    "保護するニーモニックと任意の BIP-39 パスフレーズを選択します。"
                }
                "Source" => "入力方法",
                "Generate new" => "新しく作成",
                "Import existing" => "既存のニーモニックを入力",
                "Language" => "言語",
                "Generate seed" => "ニーモニックを生成",
                "Seed phrase" => "ニーモニック",
                "Reveal generated phrase" => "生成したニーモニックを表示",
                "Passphrase" => "パスフレーズ",
                "Optional BIP-39 passphrase" => "任意の BIP-39 パスフレーズ",
                "Reveal passphrase" => "パスフレーズを表示",
                "Include passphrase in encrypted backup" => "暗号化バックアップに含める",
                "Recovery format" => "バックアップ方式",
                "Optionally replace the stored mnemonic with threshold recovery shares." => {
                    "ニーモニックを、しきい値付きの SSKR シェアに変換して保存できます。"
                }
                "Split seed into recovery shares" => "SSKR リカバリーシェアを使用",
                "Groups" => "リカバリーグループ",
                "Create" => "総数",
                "Require" => "しきい値",
                "Shares per group" => "グループ内のシェア数",
                "Recovery rule" => "復元しきい値",
                "Encrypt and save" => "暗号化して保存",
                "Select who can decrypt the backup and where the encrypted file is written." => {
                    "暗号化先となる age 受信者公開鍵と、バックアップの保存先を指定します。"
                }
                "Recipient" => "age 受信者公開鍵",
                "Choose file" => "ファイルを選択",
                "Backup file" => "バックアップファイル",
                "Save as" => "別名で保存",
                "Unlock backup" => "バックアップを復号",
                "Choose the encrypted file and supply a matching private age identity." => {
                    "暗号化バックアップと、それに対応する age 秘密鍵を指定します。"
                }
                "Open file" => "ファイルを開く",
                "Private identity" => "age 秘密鍵",
                "Reveal identity" => "秘密鍵を表示",
                "Decrypt backup" => "バックアップを復号",
                "Decrypted contents" => "バックアップの内容",
                "Sensitive values remain masked until you explicitly reveal them." => {
                    "機密値は明示的に表示するまでマスクされます。"
                }
                "Recovery complete" => "復元完了",
                "Reveal sensitive values" => "機密値を表示",
                "Open address derivation" => "アドレス導出を開く",
                "Recovery shares" => "SSKR リカバリーシェア",
                "Paste one unique hexadecimal or mnemonic SSKR share per line." => {
                    "重複しない SSKR シェアを 1 行に 1 つ貼り付けます。16 進数形式とニーモニック形式に対応しています。"
                }
                "Share language" => "シェアの言語",
                "SSKR shares" => "SSKR シェア",
                "Wallet passphrase" => "BIP-39 パスフレーズ",
                "Enter the original BIP-39 passphrase if this wallet used one." => {
                    "このウォレットで使用した元の BIP-39 パスフレーズを入力します。"
                }
                "Recover seed" => "シードを復元",
                "Derivation inputs" => "ウォレット情報",
                "Use a loaded backup or paste a valid BIP-39 mnemonic manually." => {
                    "読み込んだバックアップを使うか、有効な BIP-39 ニーモニックを貼り付けます。"
                }
                "Network" => "ネットワーク",
                "Index range" => "インデックス範囲",
                "Start" => "開始",
                "End" => "終了",
                "Harden final index" => "末尾のインデックスを hardened にする",
                "Derive addresses" => "アドレスを導出",
                "Public results" => "導出結果",
                "Addresses and public keys are safe to share; no private keys are displayed." => {
                    "アドレスと公開鍵は共有できます。秘密鍵は表示されません。"
                }
                "Index" => "インデックス",
                "Path" => "パス",
                "Address" => "アドレス",
                "Public key" => "公開鍵",
                "Choose age recipient file" => "age 受信者公開鍵ファイルを選択",
                "Choose age identity file" => "age 秘密鍵ファイルを選択",
                "Supported files" => "対応ファイル",
                "Save encrypted backup" => "暗号化バックアップを保存",
                "age backup" => "age バックアップ",
                "Backup Summary" => "バックアップ概要",
                "Type" => "種類",
                "Recovery Rule" => "復元しきい値",
                "Top-Level Fields" => "最上位フィールド",
                "SSKR Recovery" => "SSKR 復元",
                "Recovered automatically" => "自動復元済み",
                "Recovered Seed Material" => "復元したニーモニック情報",
                "Seed Material" => "ニーモニック情報",
                "SSKR Shares" => "SSKR シェア",
                "Total Shares" => "シェア合計",
                "Additional Fields" => "追加フィールド",
                "Decrypted JSON" => "復号した JSON",
                "Value" => "値",
                "Group Data" => "グループデータ",
                "Share Data" => "シェアデータ",
                "SSKR Metadata" => "SSKR メタデータ",
                "None" => "なし",
                "Schema Version" => "スキーマバージョン",
                "Backup Type" => "バックアップ種類",
                "Created" => "作成日時",
                "Tool Version" => "ツールバージョン",
                "Share Hex" => "シェア16進数",
                "Share Mnemonic" => "シェアニーモニック",
                "Entropy" => "エントロピー",
                "Private Key" => "秘密鍵",
                "Root XPRV" => "ルート XPRV",
                "Scroll for more" => "続きは下へ",
                "Generated a new 24-word seed." => "新しい 24 語のニーモニックを生成しました。",
                "Address inputs loaded from the new seed." => {
                    "新しいニーモニックをアドレス導出画面に反映しました。"
                }
                "Generate a seed before saving." => "保存する前にニーモニックを生成してください。",
                "Enter a seed phrase before saving." => {
                    "保存する前にニーモニックを入力してください。"
                }
                "Address inputs loaded from the decrypted backup." => {
                    "バックアップのニーモニックをアドレス導出画面に読み込みました。"
                }
                "Backup decrypted and seed loaded into address derivation." => {
                    "バックアップを復号し、ニーモニックをアドレス導出画面に読み込みました。"
                }
                "Recovered SSKR seed loaded." => "復元した SSKR シードを読み込みました。",
                "Backup decrypted, and the SSKR seed was recovered automatically." => {
                    "バックアップを復号し、SSKR シードを自動復元しました。"
                }
                "Backup decrypted, but it does not contain a seed phrase." => {
                    "バックアップを復号しましたが、ニーモニックが含まれていません。"
                }
                "Backup decrypted, but it does not contain seed material." => {
                    "バックアップを復号しましたが、ニーモニックも SSKR シェアも含まれていません。"
                }
                "Enter or load a seed phrase first." => {
                    "先にニーモニックを入力するか、バックアップから読み込んでください。"
                }
                "Start index must be a number." => "開始インデックスは数値で指定してください。",
                "End index must be a number." => "終了インデックスは数値で指定してください。",
                "Start index cannot be greater than end index." => {
                    "開始インデックスを終了インデックスより大きくできません。"
                }
                "Seed recovered and loaded into address derivation." => {
                    "シードを復元し、アドレス導出に読み込みました。"
                }
                "Sensitive GUI state cleared." => "この操作で使用した機密情報をメモリから消去しました。",
                "Error" => "エラー",
                _ => english,
            },
            Self::Korean => match english {
                "Encrypted recovery" => "시드 백업 및 복구",
                "Clear sensitive data" => "민감한 정보 지우기",
                "Secrets: memory only" => "민감한 정보는 메모리에만 보관",
                "Guidance" => "사용 도움말",
                "Create encrypted backup" => "암호화 백업 만들기",
                "Open encrypted backup" => "암호화 백업 열기",
                "Recover from SSKR shares" => "SSKR 조각으로 복구",
                "Address derivation" => "주소 파생",
                "Protect a new or existing BIP-39 seed with age encryption." => {
                    "새로 만들거나 기존에 사용하던 BIP-39 니모닉을 age로 암호화해 백업합니다."
                }
                "Inspect a backup and load its seed material securely." => {
                    "백업을 복호화해 내용을 확인하고 니모닉을 안전하게 불러옵니다."
                }
                "Reconstruct a seed from a sufficient set of recovery shares." => {
                    "임계값을 충족하는 SSKR 조각을 조합해 원래 시드를 복구합니다."
                }
                "Derive public wallet data without exposing private keys." => {
                    "개인 키를 표시하지 않고 공개 주소와 공개 키만 파생합니다."
                }
                "Create backup" => "백업 만들기",
                "Open backup" => "백업 열기",
                "Recover SSKR" => "SSKR 복구",
                "Addresses" => "주소 파생",
                "Encrypt seed material" => "니모닉 백업 암호화",
                "Decrypt and inspect" => "복호화 후 내용 확인",
                "Combine recovery shares" => "SSKR 조각 조합",
                "Derive public keys" => "공개 주소 생성",
                "Seed material" => "니모닉 및 패스프레이즈",
                "Choose the mnemonic and optional BIP-39 passphrase to protect." => {
                    "백업할 니모닉을 선택하고 필요한 경우 BIP-39 패스프레이즈를 입력하세요."
                }
                "Source" => "입력 방식",
                "Generate new" => "새로 생성",
                "Import existing" => "기존 니모닉 입력",
                "Language" => "언어",
                "Generate seed" => "니모닉 생성",
                "Seed phrase" => "니모닉",
                "Reveal generated phrase" => "생성된 니모닉 표시",
                "Passphrase" => "패스프레이즈",
                "Optional BIP-39 passphrase" => "BIP-39 패스프레이즈(선택 사항)",
                "Reveal passphrase" => "패스프레이즈 표시",
                "Include passphrase in encrypted backup" => "암호화 백업에 패스프레이즈 포함",
                "Recovery format" => "백업 방식",
                "Optionally replace the stored mnemonic with threshold recovery shares." => {
                    "니모닉을 임계값 방식의 SSKR 복구 조각으로 변환해 저장할 수 있습니다."
                }
                "Split seed into recovery shares" => "SSKR 복구 조각 사용",
                "Groups" => "복구 그룹",
                "Create" => "전체",
                "Require" => "임계값",
                "Shares per group" => "그룹당 조각 수",
                "Recovery rule" => "복구 임계값",
                "Encrypt and save" => "암호화 및 저장",
                "Select who can decrypt the backup and where the encrypted file is written." => {
                    "암호화에 사용할 age 수신자 공개 키와 백업 파일의 저장 위치를 지정하세요."
                }
                "Recipient" => "age 수신자 공개 키",
                "Choose file" => "파일 선택",
                "Backup file" => "백업 파일",
                "Save as" => "다른 이름으로 저장",
                "Unlock backup" => "백업 복호화",
                "Choose the encrypted file and supply a matching private age identity." => {
                    "암호화된 백업과 수신자 공개 키에 대응하는 age 개인 키를 지정하세요."
                }
                "Open file" => "파일 열기",
                "Private identity" => "age 개인 키",
                "Reveal identity" => "개인 키 표시",
                "Decrypt backup" => "백업 복호화",
                "Decrypted contents" => "백업 내용",
                "Sensitive values remain masked until you explicitly reveal them." => {
                    "민감한 값은 명시적으로 표시할 때까지 가려집니다."
                }
                "Recovery complete" => "복구 완료",
                "Reveal sensitive values" => "민감한 값 표시",
                "Open address derivation" => "주소 파생 열기",
                "Recovery shares" => "SSKR 복구 조각",
                "Paste one unique hexadecimal or mnemonic SSKR share per line." => {
                    "중복되지 않은 SSKR 조각을 한 줄에 하나씩 붙여 넣으세요. 16진수 및 니모닉 형식을 지원합니다."
                }
                "Share language" => "조각 언어",
                "SSKR shares" => "SSKR 조각",
                "Wallet passphrase" => "BIP-39 패스프레이즈",
                "Enter the original BIP-39 passphrase if this wallet used one." => {
                    "지갑을 만들 때 사용한 BIP-39 패스프레이즈를 정확히 입력하세요."
                }
                "Recover seed" => "시드 복구",
                "Derivation inputs" => "지갑 정보",
                "Use a loaded backup or paste a valid BIP-39 mnemonic manually." => {
                    "불러온 백업을 사용하거나 유효한 BIP-39 니모닉을 직접 붙여 넣으세요."
                }
                "Network" => "네트워크",
                "Index range" => "인덱스 범위",
                "Start" => "시작",
                "End" => "끝",
                "Harden final index" => "마지막 인덱스 하드닝",
                "Derive addresses" => "주소 파생",
                "Public results" => "파생 결과",
                "Addresses and public keys are safe to share; no private keys are displayed." => {
                    "주소와 공개 키는 공유해도 안전하며 개인 키는 표시되지 않습니다."
                }
                "Index" => "인덱스",
                "Path" => "경로",
                "Address" => "주소",
                "Public key" => "공개 키",
                "Choose age recipient file" => "age 수신자 공개 키 파일 선택",
                "Choose age identity file" => "age 개인 키 파일 선택",
                "Supported files" => "지원 파일",
                "Save encrypted backup" => "암호화 백업 저장",
                "age backup" => "age 백업",
                "Backup Summary" => "백업 요약",
                "Type" => "유형",
                "Recovery Rule" => "복구 임계값",
                "Top-Level Fields" => "최상위 필드",
                "SSKR Recovery" => "SSKR 복구",
                "Recovered automatically" => "자동으로 복구됨",
                "Recovered Seed Material" => "복구된 니모닉 정보",
                "Seed Material" => "니모닉 정보",
                "SSKR Shares" => "SSKR 조각",
                "Total Shares" => "전체 조각 수",
                "Additional Fields" => "추가 필드",
                "Decrypted JSON" => "복호화된 JSON",
                "Value" => "값",
                "Group Data" => "그룹 데이터",
                "Share Data" => "조각 데이터",
                "SSKR Metadata" => "SSKR 메타데이터",
                "None" => "없음",
                "Schema Version" => "스키마 버전",
                "Backup Type" => "백업 유형",
                "Created" => "생성 시각",
                "Tool Version" => "도구 버전",
                "Share Hex" => "조각 16진수",
                "Share Mnemonic" => "조각 니모닉",
                "Entropy" => "엔트로피",
                "Private Key" => "개인 키",
                "Root XPRV" => "루트 XPRV",
                "Scroll for more" => "아래에 내용 더 있음",
                "Generated a new 24-word seed." => "새로운 24단어 니모닉을 생성했습니다.",
                "Address inputs loaded from the new seed." => {
                    "새 니모닉을 주소 파생 화면에 반영했습니다."
                }
                "Generate a seed before saving." => "백업을 저장하기 전에 니모닉을 생성하세요.",
                "Enter a seed phrase before saving." => "백업을 저장하기 전에 니모닉을 입력하세요.",
                "Address inputs loaded from the decrypted backup." => {
                    "백업의 니모닉을 주소 파생 화면에 불러왔습니다."
                }
                "Backup decrypted and seed loaded into address derivation." => {
                    "백업을 복호화하고 니모닉을 주소 파생 화면에 불러왔습니다."
                }
                "Recovered SSKR seed loaded." => "복구된 SSKR 시드를 불러왔습니다.",
                "Backup decrypted, and the SSKR seed was recovered automatically." => {
                    "백업을 복호화하고 SSKR 시드를 자동으로 복구했습니다."
                }
                "Backup decrypted, but it does not contain a seed phrase." => {
                    "백업을 복호화했지만 니모닉이 포함되어 있지 않습니다."
                }
                "Backup decrypted, but it does not contain seed material." => {
                    "백업을 복호화했지만 니모닉이나 SSKR 조각이 없습니다."
                }
                "Enter or load a seed phrase first." => "먼저 니모닉을 입력하거나 백업에서 불러오세요.",
                "Start index must be a number." => "시작 인덱스는 숫자여야 합니다.",
                "End index must be a number." => "끝 인덱스는 숫자여야 합니다.",
                "Start index cannot be greater than end index." => {
                    "시작 인덱스는 끝 인덱스보다 클 수 없습니다."
                }
                "Seed recovered and loaded into address derivation." => {
                    "시드를 복구하고 주소 파생 화면에 불러왔습니다."
                }
                "Sensitive GUI state cleared." => "이 작업에 사용된 민감한 정보를 메모리에서 지웠습니다.",
                "Error" => "오류",
                _ => english,
            },
        }
    }

    fn tip(self, tab: Tab) -> (&'static str, &'static str) {
        match (self, tab) {
            (Self::English, Tab::Generate) => (
                "Before you save",
                "The selected language must match the mnemonic wordlist. A BIP-39 passphrase is stored only when you explicitly include it; SSKR stores shares instead of the raw phrase.",
            ),
            (Self::English, Tab::Decrypt) => (
                "Identity, not recipient",
                "Decryption requires a private AGE-SECRET-KEY or identity file. Recovered mnemonic and SSKR material loads into Address Derivation automatically.",
            ),
            (Self::English, Tab::Recover) => (
                "Use unique shares",
                "Paste one share per line and select the original share language. Recovery requires enough unique shares to satisfy the configured threshold.",
            ),
            (Self::English, Tab::Addresses) => (
                "Public output only",
                "Derivation uses the phrase, passphrase, network, and index range shown below. The results contain public addresses and keys—never private keys.",
            ),
            (Self::SimplifiedChinese, Tab::Generate) => (
                "保存前请确认",
                "助记词语言必须与原始词库一致。BIP-39 附加密码只有在勾选后才会写入加密备份；启用 SSKR 时，备份保存恢复份额而不是助记词原文。",
            ),
            (Self::SimplifiedChinese, Tab::Decrypt) => (
                "解密需要私钥",
                "请提供 age 私钥（AGE-SECRET-KEY 或身份文件），接收公钥不能用于解密。成功恢复的助记词或 SSKR 种子会自动载入地址派生页面。",
            ),
            (Self::SimplifiedChinese, Tab::Recover) => (
                "使用不重复的份额",
                "每行粘贴一个份额，并选择创建份额时使用的语言。必须提供足够数量且互不重复的份额，才能满足恢复阈值。",
            ),
            (Self::SimplifiedChinese, Tab::Addresses) => (
                "仅输出公开数据",
                "地址派生使用下方的助记词、BIP-39 附加密码、网络和索引范围。结果只包含公开地址和公钥，不会显示私钥。",
            ),
            (Self::Japanese, Tab::Generate) => (
                "保存前の確認",
                "選択した言語はニーモニックの単語リストと一致する必要があります。BIP-39 パスフレーズは明示的に含めた場合のみ保存され、SSKR では元のニーモニックの代わりに復元シェアが保存されます。",
            ),
            (Self::Japanese, Tab::Decrypt) => (
                "復号には秘密鍵が必要です",
                "age 秘密鍵（AGE-SECRET-KEY または identity ファイル）を指定してください。受信者公開鍵では復号できません。復元したニーモニックや SSKR シードはアドレス導出画面に自動で読み込まれます。",
            ),
            (Self::Japanese, Tab::Recover) => (
                "重複しないシェアを使用",
                "1 行に 1 つのシェアを貼り付け、作成時と同じ言語を選択してください。復元には、設定されたしきい値を満たす十分な数の固有シェアが必要です。",
            ),
            (Self::Japanese, Tab::Addresses) => (
                "公開情報のみ",
                "導出には下記のニーモニック、パスフレーズ、ネットワーク、インデックス範囲が使われます。表示されるのは公開アドレスと公開鍵のみで、秘密鍵は表示されません。",
            ),
            (Self::Korean, Tab::Generate) => (
                "저장 전 확인",
                "니모닉 언어는 원래 단어 목록과 일치해야 합니다. BIP-39 패스프레이즈는 포함 옵션을 선택한 경우에만 저장되며, SSKR을 사용하면 니모닉 원문 대신 복구 조각이 저장됩니다.",
            ),
            (Self::Korean, Tab::Decrypt) => (
                "복호화에는 개인 키가 필요합니다",
                "age 개인 키(AGE-SECRET-KEY 또는 identity 파일)를 지정하세요. 수신자 공개 키로는 복호화할 수 없습니다. 복구된 니모닉이나 SSKR 시드는 주소 파생 화면에 자동으로 불러옵니다.",
            ),
            (Self::Korean, Tab::Recover) => (
                "중복되지 않은 조각 사용",
                "한 줄에 하나의 조각을 붙여 넣고 생성 당시의 언어를 선택하세요. 설정된 임계값을 충족할 만큼 서로 다른 조각이 있어야 복구할 수 있습니다.",
            ),
            (Self::Korean, Tab::Addresses) => (
                "공개 데이터만 출력",
                "아래의 니모닉, BIP-39 패스프레이즈, 네트워크 및 인덱스 범위를 사용해 주소를 파생합니다. 결과에는 공개 주소와 공개 키만 포함되며 개인 키는 표시되지 않습니다.",
            ),
        }
    }

    fn scroll_hint(self) -> &'static str {
        self.text("Scroll for more")
    }
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

    fn localized_label(self, language: GuidanceLanguage) -> &'static str {
        match language {
            GuidanceLanguage::English => self.label(),
            GuidanceLanguage::SimplifiedChinese => match self {
                Self::English => "英语",
                Self::SimplifiedChinese => "简体中文",
                Self::TraditionalChinese => "繁体中文",
                Self::Japanese => "日语",
                Self::Korean => "韩语",
                Self::Spanish => "西班牙语",
                Self::French => "法语",
                Self::Italian => "意大利语",
                Self::Czech => "捷克语",
                Self::Portuguese => "葡萄牙语",
            },
            GuidanceLanguage::Japanese => match self {
                Self::English => "英語",
                Self::SimplifiedChinese => "簡体字中国語",
                Self::TraditionalChinese => "繁体字中国語",
                Self::Japanese => "日本語",
                Self::Korean => "韓国語",
                Self::Spanish => "スペイン語",
                Self::French => "フランス語",
                Self::Italian => "イタリア語",
                Self::Czech => "チェコ語",
                Self::Portuguese => "ポルトガル語",
            },
            GuidanceLanguage::Korean => match self {
                Self::English => "영어",
                Self::SimplifiedChinese => "중국어 간체",
                Self::TraditionalChinese => "중국어 번체",
                Self::Japanese => "일본어",
                Self::Korean => "한국어",
                Self::Spanish => "스페인어",
                Self::French => "프랑스어",
                Self::Italian => "이탈리아어",
                Self::Czech => "체코어",
                Self::Portuguese => "포르투갈어",
            },
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
    guidance_language: GuidanceLanguage,
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
    reveal_recover_passphrase: bool,
    recover_status: String,
    derive_language: MnemonicLanguage,
    derive_phrase: Zeroizing<String>,
    derive_passphrase: Zeroizing<String>,
    reveal_derive_passphrase: bool,
    derive_kind: AddressKind,
    derive_start: String,
    derive_end: String,
    derive_hardened: bool,
    address_rows: Vec<AddressRow>,
    derive_status: String,
}

impl Bip39Gui {
    fn new_seed(&mut self) {
        let language = self.guidance_language;
        self.generated_phrase.zeroize();
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        match Mnemonic::from_entropy_in(self.language.bip39(), &entropy) {
            Ok(mnemonic) => {
                self.generated_phrase = Zeroizing::new(mnemonic.to_string());
                self.generate_status = language.text("Generated a new 24-word seed.").to_string();
                self.derive_language = self.language;
                self.derive_phrase = self.generated_phrase.clone();
                self.derive_passphrase = self.backup_passphrase.clone();
                self.address_rows.clear();
                self.derive_status = language
                    .text("Address inputs loaded from the new seed.")
                    .to_string();
            }
            Err(err) => {
                self.generate_status = localized_error(language, &err.to_string());
            }
        }
        entropy.zeroize();
    }

    fn save_seed_backup(&mut self) {
        let language = self.guidance_language;
        let phrase = self.seed_source.phrase(
            self.generated_phrase.as_str(),
            self.imported_phrase.as_str(),
        );
        if phrase.trim().is_empty() {
            self.generate_status = match self.seed_source {
                SeedSource::Generate => language.text("Generate a seed before saving.").to_string(),
                SeedSource::Import => language
                    .text("Enter a seed phrase before saving.")
                    .to_string(),
            };
            return;
        }

        let mnemonic = match parse_backup_mnemonic(self.language, phrase) {
            Ok(mnemonic) => mnemonic,
            Err(err) => {
                self.generate_status = localized_error(language, &err);
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
                    self.generate_status = localized_error(language, &err);
                    return;
                }
            }
        } else {
            backup
        };

        let recipients = match age_recipients_from_input(&self.recipient_input) {
            Ok(recipients) => recipients,
            Err(err) => {
                self.generate_status = localized_error(language, &err);
                return;
            }
        };

        let save_path = backup_save_path_from_input(&self.save_path);
        if let Err(err) = validate_save_path(&save_path) {
            self.generate_status = localized_error(language, &err);
            return;
        }

        let json = match serde_json::to_string_pretty(&backup) {
            Ok(json) => json,
            Err(err) => {
                backup.zeroize_sensitive();
                self.generate_status = localized_error(language, &err.to_string());
                return;
            }
        };
        backup.zeroize_sensitive();
        let json = Zeroizing::new(json);

        match encrypt_data(json.as_bytes(), &recipients)
            .and_then(|ciphertext| persist_noclobber(&save_path, &ciphertext))
        {
            Ok(()) => {
                self.generate_status =
                    localized_saved_status(language, self.sskr_enabled, &save_path);
            }
            Err(err) => {
                self.generate_status = localized_error(language, &err);
            }
        }
    }

    fn decrypt_backup(&mut self) {
        let ui_language = self.guidance_language;
        let path = backup_save_path_from_input(&self.decrypt_path);
        let ciphertext = match std::fs::read(&path) {
            Ok(ciphertext) => ciphertext,
            Err(err) => {
                self.decrypt_status =
                    localized_error(ui_language, &format!("{}: {err}", path.display()));
                return;
            }
        };

        let plaintext = match decrypt_data(&ciphertext, self.identity_input.as_str()) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                self.decrypt_status = localized_error(ui_language, &err);
                return;
            }
        };

        let backup_json = match serde_json::from_slice::<serde_json::Value>(plaintext.as_slice()) {
            Ok(value) => value,
            Err(err) => {
                self.decrypt_status = localized_error(ui_language, &err.to_string());
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
            self.derive_status = ui_language
                .text("Address inputs loaded from the decrypted backup.")
                .to_string();
            self.decrypt_status = ui_language
                .text("Backup decrypted and seed loaded into address derivation.")
                .to_string();
        } else if backup_summary.sskr_groups > 0 {
            self.derive_passphrase = Zeroizing::new(
                json_string_field(&backup_json, "passphrase")
                    .unwrap_or("")
                    .to_string(),
            );
            match recover_mnemonic_from_backup_json(&backup_json, language) {
                Ok(mnemonic_phrase) => {
                    self.derive_phrase = mnemonic_phrase;
                    self.derive_status =
                        ui_language.text("Recovered SSKR seed loaded.").to_string();
                    self.decrypt_status = ui_language
                        .text("Backup decrypted, and the SSKR seed was recovered automatically.")
                        .to_string();
                    backup_summary.recovered_from_sskr = true;
                }
                Err(err) => {
                    self.derive_phrase.zeroize();
                    self.derive_passphrase.zeroize();
                    self.derive_status = localized_error(ui_language, &err);
                    self.decrypt_status = localized_error(ui_language, &err);
                }
            }
        } else {
            self.derive_phrase.zeroize();
            self.derive_passphrase.zeroize();
            self.derive_status = ui_language
                .text("Backup decrypted, but it does not contain a seed phrase.")
                .to_string();
            self.decrypt_status = ui_language
                .text("Backup decrypted, but it does not contain seed material.")
                .to_string();
        }
        self.decrypted_backup = Some(backup_summary);
        self.decrypted_backup_json = Some(SensitiveJson::new(backup_json));
        self.address_rows.clear();
    }

    fn derive_addresses(&mut self) {
        let language = self.guidance_language;
        let phrase = self.derive_phrase.trim();
        if phrase.is_empty() {
            self.derive_status = language
                .text("Enter or load a seed phrase first.")
                .to_string();
            return;
        }

        let start = match self.derive_start.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                self.derive_status = language.text("Start index must be a number.").to_string();
                return;
            }
        };
        let end = match self.derive_end.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => {
                self.derive_status = language.text("End index must be a number.").to_string();
                return;
            }
        };
        if start > end {
            self.derive_status = language
                .text("Start index cannot be greater than end index.")
                .to_string();
            return;
        }
        if end - start + 1 > MAX_DERIVE_COUNT {
            self.derive_status = localized_max_address_status(language, MAX_DERIVE_COUNT);
            return;
        }

        let mnemonic = match Mnemonic::parse_in_normalized(self.derive_language.bip39(), phrase) {
            Ok(mnemonic) => mnemonic,
            Err(err) => {
                self.derive_status = localized_error(language, &err.to_string());
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
                self.derive_status = localized_derived_status(language, self.address_rows.len());
            }
            Err(err) => {
                self.derive_status = localized_error(language, &err);
            }
        }
    }

    fn recover_from_manual_shares(&mut self) {
        let language = self.guidance_language;
        let mut shares =
            match shares_from_text(self.recover_shares_input.as_str(), self.recover_language) {
                Ok(shares) => shares,
                Err(err) => {
                    self.recover_status = localized_error(language, &err);
                    return;
                }
            };

        match recover_mnemonic_from_shares(shares.as_slice(), self.recover_language) {
            Ok(mnemonic_phrase) => {
                self.derive_language = self.recover_language;
                self.derive_phrase = mnemonic_phrase;
                self.derive_passphrase = self.recover_passphrase.clone();
                self.address_rows.clear();
                self.recover_status = language
                    .text("Seed recovered and loaded into address derivation.")
                    .to_string();
                self.derive_status = language.text("Recovered SSKR seed loaded.").to_string();
                self.tab = Tab::Addresses;
            }
            Err(err) => {
                self.recover_status = localized_error(language, &err);
            }
        }
        shares.zeroize();
    }

    fn clear_sensitive_state(&mut self) {
        self.generated_phrase.zeroize();
        self.imported_phrase.zeroize();
        self.backup_passphrase.zeroize();
        self.reveal_backup_passphrase = false;
        self.identity_input.zeroize();
        self.decrypted_backup = None;
        self.decrypted_backup_json = None;
        self.recover_shares_input.zeroize();
        self.recover_passphrase.zeroize();
        self.reveal_recover_passphrase = false;
        self.derive_phrase.zeroize();
        self.derive_passphrase.zeroize();
        self.reveal_derive_passphrase = false;
        self.address_rows.clear();
        self.generate_status.clear();
        self.decrypt_status.clear();
        self.recover_status.clear();
        self.derive_status.clear();
        let status = self
            .guidance_language
            .text("Sensitive GUI state cleared.")
            .to_string();
        match self.tab {
            Tab::Generate => self.generate_status = status,
            Tab::Decrypt => self.decrypt_status = status,
            Tab::Recover => self.recover_status = status,
            Tab::Addresses => self.derive_status = status,
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
            guidance_language: GuidanceLanguage::English,
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
            reveal_recover_passphrase: false,
            recover_status: String::new(),
            derive_language: MnemonicLanguage::English,
            derive_phrase: Zeroizing::new(String::new()),
            derive_passphrase: Zeroizing::new(String::new()),
            reveal_derive_passphrase: false,
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
        let language = self.guidance_language;
        egui::Panel::left("navigation")
            .exact_size(230.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(sidebar_color())
                    .inner_margin(egui::Margin::same(18)),
            )
            .show_inside(ui, |ui| {
                brand_header(ui, language);
                ui.add_space(28.0);

                for tab in Tab::ALL {
                    if navigation_button(ui, tab, self.tab == tab, language).clicked() {
                        self.tab = tab;
                    }
                    ui.add_space(6.0);
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if sidebar_utility_button(
                        ui,
                        UiIcon::Trash,
                        language.text("Clear sensitive data"),
                    )
                    .clicked()
                    {
                        self.clear_sensitive_state();
                    }
                    ui.add_space(8.0);
                    sidebar_status_row(ui, UiIcon::Shield, language.text("Secrets: memory only"));
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(app_background_color())
                    .inner_margin(egui::Margin::symmetric(30, 24)),
            )
            .show_inside(ui, |ui| {
                let language_changed = page_header(
                    ui,
                    self.tab,
                    &mut self.show_tips,
                    &mut self.guidance_language,
                );
                if language_changed {
                    self.clear_status_messages();
                }
                ui.add_space(18.0);

                let scroll_output = egui::ScrollArea::vertical()
                    .id_salt(("workflow_scroll", self.tab))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if self.show_tips {
                            tips_panel(ui, self.tab, self.guidance_language);
                            ui.add_space(14.0);
                        }

                        match self.tab {
                            Tab::Generate => self.generate_tab(ui),
                            Tab::Decrypt => self.decrypt_tab(ui),
                            Tab::Recover => self.recover_tab(ui),
                            Tab::Addresses => self.addresses_tab(ui),
                        }
                        ui.add_space(24.0);
                    });
                paint_more_below_hint(ui, &scroll_output, self.guidance_language);
            });
    }
}

impl Bip39Gui {
    fn clear_status_messages(&mut self) {
        self.generate_status.clear();
        self.decrypt_status.clear();
        self.recover_status.clear();
        self.derive_status.clear();
    }

    fn generate_tab(&mut self, ui: &mut egui::Ui) {
        self.normalize_sskr_settings();
        if ui.available_width() >= 1080.0 {
            ui.columns(2, |columns| {
                self.seed_material_card(&mut columns[0]);
                self.recovery_format_card(&mut columns[1]);
                columns[1].add_space(14.0);
                self.encrypt_save_card(&mut columns[1]);
            });
        } else {
            self.seed_material_card(ui);
            ui.add_space(14.0);
            self.recovery_format_card(ui);
            ui.add_space(14.0);
            self.encrypt_save_card(ui);
        }
    }

    fn seed_material_card(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Key,
            language.text("Seed material"),
            language.text("Choose the mnemonic and optional BIP-39 passphrase to protect."),
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, language.text("Source"));
                    ui.selectable_value(
                        &mut self.seed_source,
                        SeedSource::Generate,
                        language.text("Generate new"),
                    );
                    ui.selectable_value(
                        &mut self.seed_source,
                        SeedSource::Import,
                        language.text("Import existing"),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, language.text("Language"));
                    language_combo(ui, "generate_language", &mut self.language, language);
                    if self.seed_source == SeedSource::Generate
                        && action_button(ui, UiIcon::Spark, language.text("Generate seed"), false)
                            .clicked()
                    {
                        self.new_seed();
                    }
                });

                ui.add_space(8.0);
                if self.seed_source == SeedSource::Import {
                    multiline_text_row(
                        ui,
                        language.text("Seed phrase"),
                        &mut self.imported_phrase,
                        4,
                    );
                } else {
                    ui.horizontal(|ui| {
                        form_label(ui, language.text("Seed phrase"));
                        ui.checkbox(
                            &mut self.reveal_generated,
                            language.text("Reveal generated phrase"),
                        );
                    });
                    seed_phrase_box(ui, self.generated_phrase.as_str(), self.reveal_generated);
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    form_label(ui, language.text("Passphrase"));
                    let field_width = (ui.available_width() - 8.0).clamp(220.0, 460.0);
                    let response = ui.add_sized(
                        [field_width, FIELD_HEIGHT],
                        egui::TextEdit::singleline(&mut *self.backup_passphrase)
                            .password(!self.reveal_backup_passphrase)
                            .hint_text(language.text("Optional BIP-39 passphrase"))
                            .desired_width(field_width),
                    );
                    if self.seed_source == SeedSource::Generate
                        && response.changed()
                        && !self.generated_phrase.is_empty()
                        && self.derive_phrase.as_str() == self.generated_phrase.as_str()
                    {
                        self.derive_passphrase = self.backup_passphrase.clone();
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, "");
                    ui.checkbox(
                        &mut self.reveal_backup_passphrase,
                        language.text("Reveal passphrase"),
                    );
                    ui.checkbox(
                        &mut self.store_passphrase,
                        language.text("Include passphrase in encrypted backup"),
                    );
                });
            },
        );
    }

    fn recovery_format_card(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Recovery,
            language.text("Recovery format"),
            language.text("Optionally replace the stored mnemonic with threshold recovery shares."),
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, "SSKR");
                    ui.checkbox(
                        &mut self.sskr_enabled,
                        language.text("Split seed into recovery shares"),
                    );
                });

                if self.sskr_enabled {
                    ui.add_space(10.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        form_label(ui, language.text("Groups"));
                        ui.label(language.text("Create"));
                        ui.add(
                            egui::DragValue::new(&mut self.sskr_group_count)
                                .range(1..=MAX_SSKR_GROUPS)
                                .speed(1.0),
                        );
                        ui.label(language.text("Require"));
                        ui.add(
                            egui::DragValue::new(&mut self.sskr_group_threshold)
                                .range(1..=self.sskr_group_count)
                                .speed(1.0),
                        );
                    });
                    ui.horizontal_wrapped(|ui| {
                        form_label(ui, language.text("Shares per group"));
                        ui.label(language.text("Create"));
                        ui.add(
                            egui::DragValue::new(&mut self.sskr_shares_per_group)
                                .range(1..=MAX_SSKR_SHARES_PER_GROUP)
                                .speed(1.0),
                        );
                        ui.label(language.text("Require"));
                        ui.add(
                            egui::DragValue::new(&mut self.sskr_required_shares_per_group)
                                .range(1..=self.sskr_shares_per_group)
                                .speed(1.0),
                        );
                    });
                    ui.horizontal_wrapped(|ui| {
                        form_label(ui, language.text("Recovery rule"));
                        ui.label(
                            egui::RichText::new(localized_sskr_rule(
                                language,
                                self.sskr_settings(),
                            ))
                            .color(accent_color()),
                        );
                    });
                }
            },
        );
    }

    fn encrypt_save_card(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Shield,
            language.text("Encrypt and save"),
            language
                .text("Select who can decrypt the backup and where the encrypted file is written."),
            |ui| {
                if text_field_row(
                    ui,
                    language.text("Recipient"),
                    &mut self.recipient_input,
                    false,
                    Some(language.text("Choose file")),
                ) {
                    choose_existing_file(
                        language.text("Choose age recipient file"),
                        &mut self.recipient_input,
                        &["txt", "pub", "toml"],
                        language,
                    );
                }
                if text_field_row(
                    ui,
                    language.text("Backup file"),
                    &mut self.save_path,
                    false,
                    Some(language.text("Save as")),
                ) {
                    choose_save_file(&mut self.save_path, language);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    if action_button(ui, UiIcon::Save, language.text("Encrypt and save"), true)
                        .clicked()
                    {
                        self.save_seed_backup();
                    }
                });
                status_banner(ui, &self.generate_status);
            },
        );
    }

    fn decrypt_tab(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Open,
            language.text("Unlock backup"),
            language.text("Choose the encrypted file and supply a matching private age identity."),
            |ui| {
                if text_field_row(
                    ui,
                    language.text("Backup file"),
                    &mut self.decrypt_path,
                    false,
                    Some(language.text("Open file")),
                ) {
                    choose_existing_file(
                        language.text("Open encrypted backup"),
                        &mut self.decrypt_path,
                        &["age"],
                        language,
                    );
                }
                if text_field_row(
                    ui,
                    language.text("Private identity"),
                    &mut self.identity_input,
                    !self.reveal_identity_input,
                    Some(language.text("Choose file")),
                ) {
                    choose_existing_file(
                        language.text("Choose age identity file"),
                        &mut self.identity_input,
                        &["txt", "key"],
                        language,
                    );
                }
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    ui.checkbox(
                        &mut self.reveal_identity_input,
                        language.text("Reveal identity"),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    if action_button(ui, UiIcon::Open, language.text("Decrypt backup"), true)
                        .clicked()
                    {
                        self.decrypt_backup();
                    }
                });
                status_banner(ui, &self.decrypt_status);
            },
        );

        let recovered_from_sskr = self
            .decrypted_backup
            .as_ref()
            .is_some_and(|backup| backup.recovered_from_sskr);
        let seed_loaded = self
            .decrypted_backup
            .as_ref()
            .is_some_and(|backup| backup.has_seed_phrase || backup.recovered_from_sskr);
        if self.decrypted_backup_json.is_some() {
            ui.add_space(14.0);
            section_card(
                ui,
                UiIcon::Shield,
                language.text("Decrypted contents"),
                language.text("Sensitive values remain masked until you explicitly reveal them."),
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if let Some(backup) = &self.decrypted_backup {
                            metadata_chip(
                                ui,
                                MnemonicLanguage::from_backup_name(&backup.language)
                                    .localized_label(language),
                            );
                            metadata_chip(ui, &localized_group_count(language, backup.sskr_groups));
                            metadata_chip(ui, backup.seed_storage_label(language));
                            if backup.recovered_from_sskr {
                                success_chip(ui, language.text("Recovery complete"));
                            }
                        }
                    });
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.checkbox(
                            &mut self.reveal_decrypted,
                            language.text("Reveal sensitive values"),
                        );
                        if seed_loaded
                            && action_button(
                                ui,
                                UiIcon::Arrow,
                                language.text("Open address derivation"),
                                false,
                            )
                            .clicked()
                        {
                            self.tab = Tab::Addresses;
                        }
                    });

                    if let Some(backup_json) = &self.decrypted_backup_json {
                        let recovered_phrase =
                            recovered_from_sskr.then_some(self.derive_phrase.as_str());
                        render_backup_view(
                            ui,
                            backup_json.as_value(),
                            recovered_phrase,
                            self.reveal_decrypted,
                            language,
                        );
                    }
                },
            );
        }
    }

    fn recover_tab(&mut self, ui: &mut egui::Ui) {
        if ui.available_width() >= 1080.0 {
            ui.columns(2, |columns| {
                self.recovery_shares_card(&mut columns[0]);
                self.recovery_passphrase_card(&mut columns[1]);
            });
        } else {
            self.recovery_shares_card(ui);
            ui.add_space(14.0);
            self.recovery_passphrase_card(ui);
        }
    }

    fn recovery_shares_card(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Recovery,
            language.text("Recovery shares"),
            language.text("Paste one unique hexadecimal or mnemonic SSKR share per line."),
            |ui| {
                ui.horizontal(|ui| {
                    form_label(ui, language.text("Share language"));
                    language_combo(ui, "recover_language", &mut self.recover_language, language);
                });
                ui.add_space(6.0);
                multiline_text_row(
                    ui,
                    language.text("SSKR shares"),
                    &mut self.recover_shares_input,
                    9,
                );
            },
        );
    }

    fn recovery_passphrase_card(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Key,
            language.text("Wallet passphrase"),
            language.text("Enter the original BIP-39 passphrase if this wallet used one."),
            |ui| {
                ui.horizontal(|ui| {
                    form_label(ui, language.text("Passphrase"));
                    let field_width = (ui.available_width() - 8.0).clamp(220.0, 460.0);
                    ui.add_sized(
                        [field_width, FIELD_HEIGHT],
                        egui::TextEdit::singleline(&mut *self.recover_passphrase)
                            .password(!self.reveal_recover_passphrase)
                            .hint_text(language.text("Optional BIP-39 passphrase"))
                            .desired_width(field_width),
                    );
                });
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    ui.checkbox(
                        &mut self.reveal_recover_passphrase,
                        language.text("Reveal passphrase"),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    if action_button(ui, UiIcon::Recovery, language.text("Recover seed"), true)
                        .clicked()
                    {
                        self.recover_from_manual_shares();
                    }
                });
                status_banner(ui, &self.recover_status);
            },
        );
    }

    fn addresses_tab(&mut self, ui: &mut egui::Ui) {
        let language = self.guidance_language;
        section_card(
            ui,
            UiIcon::Wallet,
            language.text("Derivation inputs"),
            language.text("Use a loaded backup or paste a valid BIP-39 mnemonic manually."),
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, language.text("Language"));
                    language_combo(ui, "derive_language", &mut self.derive_language, language);
                    ui.add_space(12.0);
                    ui.label(language.text("Network"));
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

                ui.add_space(6.0);
                multiline_text_row(ui, language.text("Seed phrase"), &mut self.derive_phrase, 4);

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    form_label(ui, language.text("Passphrase"));
                    let field_width = (ui.available_width() - 8.0).clamp(220.0, 460.0);
                    ui.add_sized(
                        [field_width, FIELD_HEIGHT],
                        egui::TextEdit::singleline(&mut *self.derive_passphrase)
                            .password(!self.reveal_derive_passphrase)
                            .hint_text(language.text("Optional BIP-39 passphrase"))
                            .desired_width(field_width),
                    );
                });
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    ui.checkbox(
                        &mut self.reveal_derive_passphrase,
                        language.text("Reveal passphrase"),
                    );
                });

                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    form_label(ui, language.text("Index range"));
                    ui.label(language.text("Start"));
                    ui.add_sized(
                        [78.0, FIELD_HEIGHT],
                        egui::TextEdit::singleline(&mut self.derive_start).desired_width(78.0),
                    );
                    ui.label(language.text("End"));
                    ui.add_sized(
                        [78.0, FIELD_HEIGHT],
                        egui::TextEdit::singleline(&mut self.derive_end).desired_width(78.0),
                    );
                    if matches!(
                        self.derive_kind,
                        AddressKind::Bitcoin | AddressKind::Ethereum
                    ) {
                        ui.checkbox(
                            &mut self.derive_hardened,
                            language.text("Harden final index"),
                        );
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    form_label(ui, "");
                    if action_button(ui, UiIcon::Spark, language.text("Derive addresses"), true)
                        .clicked()
                    {
                        self.derive_addresses();
                    }
                });
                status_banner(ui, &self.derive_status);
            },
        );

        if !self.address_rows.is_empty() {
            ui.add_space(14.0);
            section_card(
                ui,
                UiIcon::Wallet,
                language.text("Public results"),
                language.text(
                    "Addresses and public keys are safe to share; no private keys are displayed.",
                ),
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        success_chip(
                            ui,
                            &localized_address_count(language, self.address_rows.len()),
                        );
                        metadata_chip(ui, self.derive_kind.label());
                    });
                    ui.add_space(10.0);
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            egui::Grid::new("addresses_grid")
                                .striped(true)
                                .min_col_width(90.0)
                                .spacing([18.0, 10.0])
                                .show(ui, |ui| {
                                    ui.strong(language.text("Index"));
                                    ui.strong(language.text("Path"));
                                    ui.strong(language.text("Address"));
                                    ui.strong(language.text("Public key"));
                                    ui.end_row();
                                    for row in &self.address_rows {
                                        ui.label(row.index.to_string());
                                        ui.monospace(&row.path);
                                        ui.monospace(&row.address);
                                        ui.monospace(&row.public_key);
                                        ui.end_row();
                                    }
                                });
                        });
                },
            );
        }
    }
}

fn configure_ui_style(context: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let cjk_font_name = "NotoSansCJK-Tips".to_string();
    fonts.font_data.insert(
        cjk_font_name.clone(),
        std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/NotoSansCJK-Tips.otf"
        ))),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push(cjk_font_name);
    context.set_fonts(fonts);

    let mut style = (*context.global_style()).clone();
    style.spacing.item_spacing = egui::vec2(9.0, 8.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size.y = FIELD_HEIGHT;
    style.spacing.combo_width = 170.0;
    style.spacing.text_edit_width = 320.0;
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(24.0));

    let mut visuals = egui::Visuals::light();
    visuals.panel_fill = app_background_color();
    visuals.window_fill = surface_color();
    visuals.extreme_bg_color = egui::Color32::WHITE;
    visuals.text_edit_bg_color = Some(egui::Color32::WHITE);
    visuals.faint_bg_color = egui::Color32::from_rgb(247, 249, 251);
    visuals.selection.bg_fill = accent_color();
    visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    visuals.hyperlink_color = accent_color();
    visuals.warn_fg_color = warning_color();
    visuals.error_fg_color = error_color();
    visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, text_color());
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, border_color());
    visuals.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(243, 246, 249);
    visuals.widgets.inactive.bg_fill = egui::Color32::WHITE;
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, border_color());
    visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(8);
    visuals.widgets.hovered.weak_bg_fill = egui::Color32::from_rgb(229, 241, 240);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(247, 252, 251);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent_color());
    visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, accent_color());
    visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(8);
    visuals.widgets.active.weak_bg_fill = egui::Color32::from_rgb(207, 232, 229);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(229, 241, 240);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, accent_color());
    visuals.widgets.active.fg_stroke = egui::Stroke::new(1.5, accent_color());
    visuals.widgets.active.corner_radius = egui::CornerRadius::same(8);
    style.visuals = visuals;
    context.set_global_style(style);
}

fn app_background_color() -> egui::Color32 {
    egui::Color32::from_rgb(244, 247, 249)
}

fn surface_color() -> egui::Color32 {
    egui::Color32::WHITE
}

fn sidebar_color() -> egui::Color32 {
    egui::Color32::from_rgb(19, 30, 43)
}

fn sidebar_text_color() -> egui::Color32 {
    egui::Color32::from_rgb(241, 245, 249)
}

fn sidebar_muted_color() -> egui::Color32 {
    egui::Color32::from_rgb(148, 163, 184)
}

fn accent_color() -> egui::Color32 {
    egui::Color32::from_rgb(13, 116, 110)
}

fn accent_soft_color() -> egui::Color32 {
    egui::Color32::from_rgb(224, 242, 240)
}

fn text_color() -> egui::Color32 {
    egui::Color32::from_rgb(30, 41, 59)
}

fn muted_text_color() -> egui::Color32 {
    egui::Color32::from_rgb(100, 116, 139)
}

fn border_color() -> egui::Color32 {
    egui::Color32::from_rgb(220, 227, 234)
}

fn success_color() -> egui::Color32 {
    egui::Color32::from_rgb(21, 128, 61)
}

fn error_color() -> egui::Color32 {
    egui::Color32::from_rgb(185, 28, 28)
}

fn warning_color() -> egui::Color32 {
    egui::Color32::from_rgb(180, 83, 9)
}

fn brand_header(ui: &mut egui::Ui, language: GuidanceLanguage) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, 11.0, egui::Color32::from_rgb(17, 39, 53));
        ui.painter().rect_stroke(
            rect,
            11.0,
            egui::Stroke::new(1.0, egui::Color32::from_rgb(49, 109, 116)),
            egui::StrokeKind::Inside,
        );
        paint_fortress_mark(ui.painter(), rect.shrink(5.0));
        ui.add_space(3.0);
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new("BIP39 Tool")
                    .size(18.0)
                    .strong()
                    .color(sidebar_text_color()),
            );
            ui.label(
                egui::RichText::new(language.text("Encrypted recovery"))
                    .size(11.0)
                    .color(sidebar_muted_color()),
            );
        });
    });
}

/// Twenty-four mnemonic blocks form a fortress around the protected seed.
/// This mirrors the release icon while staying legible in the 40 px sidebar mark.
fn paint_fortress_mark(painter: &egui::Painter, rect: egui::Rect) {
    let mint = egui::Color32::from_rgb(224, 255, 248);
    let teal = egui::Color32::from_rgb(69, 208, 192);
    let ink = egui::Color32::from_rgb(12, 37, 50);
    let width = rect.width();
    let height = rect.height();
    let point = |x: f32, y: f32| egui::pos2(rect.left() + width * x, rect.top() + height * y);

    for bounds in [
        (0.05, 0.34, 0.35, 0.88),
        (0.65, 0.34, 0.95, 0.88),
        (0.35, 0.42, 0.65, 0.88),
        (0.05, 0.18, 0.16, 0.42),
        (0.25, 0.18, 0.35, 0.42),
        (0.65, 0.18, 0.75, 0.42),
        (0.84, 0.18, 0.95, 0.42),
    ] {
        painter.rect_filled(
            egui::Rect::from_min_max(point(bounds.0, bounds.1), point(bounds.2, bounds.3)),
            0.0,
            teal,
        );
    }
    painter.add(egui::Shape::closed_line(
        vec![
            point(0.05, 0.88),
            point(0.05, 0.18),
            point(0.16, 0.18),
            point(0.16, 0.34),
            point(0.25, 0.34),
            point(0.25, 0.18),
            point(0.35, 0.18),
            point(0.35, 0.42),
            point(0.65, 0.42),
            point(0.65, 0.18),
            point(0.75, 0.18),
            point(0.75, 0.34),
            point(0.84, 0.34),
            point(0.84, 0.18),
            point(0.95, 0.18),
            point(0.95, 0.88),
        ],
        egui::Stroke::new((width * 0.03).max(0.9), mint),
    ));

    let brick_width = width * 0.04;
    let brick_height = height * 0.025;
    for y in [0.50, 0.60, 0.70, 0.80] {
        for x in [0.14, 0.23, 0.32, 0.68, 0.77, 0.86] {
            painter.rect_filled(
                egui::Rect::from_center_size(point(x, y), egui::vec2(brick_width, brick_height)),
                brick_height,
                mint,
            );
        }
    }

    let gate = egui::Rect::from_min_max(point(0.38, 0.49), point(0.62, 0.90));
    painter.rect_filled(gate, width * 0.12, ink);
    painter.rect_stroke(
        gate,
        width * 0.12,
        egui::Stroke::new((width * 0.026).max(0.8), mint),
        egui::StrokeKind::Inside,
    );
    painter.add(egui::Shape::convex_polygon(
        vec![
            point(0.50, 0.56),
            point(0.58, 0.70),
            point(0.50, 0.84),
            point(0.42, 0.70),
        ],
        mint,
        egui::Stroke::NONE,
    ));
    painter.line_segment(
        [point(0.02, 0.89), point(0.98, 0.89)],
        egui::Stroke::new((width * 0.045).max(1.3), mint),
    );
}

fn navigation_button(
    ui: &mut egui::Ui,
    tab: Tab,
    selected: bool,
    language: GuidanceLanguage,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 56.0), egui::Sense::click());
    let fill = if selected {
        egui::Color32::from_rgb(31, 55, 68)
    } else if response.hovered() {
        egui::Color32::from_rgb(25, 42, 56)
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, 10.0, fill);
    if selected {
        let accent_rect = egui::Rect::from_min_max(
            egui::pos2(rect.left(), rect.top() + 10.0),
            egui::pos2(rect.left() + 3.0, rect.bottom() - 10.0),
        );
        ui.painter().rect_filled(accent_rect, 2.0, accent_color());
    }

    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 24.0, rect.center().y),
        egui::vec2(20.0, 20.0),
    );
    let foreground = if selected {
        egui::Color32::from_rgb(94, 234, 212)
    } else {
        sidebar_muted_color()
    };
    paint_icon(ui.painter(), tab.icon(), icon_rect, foreground);
    ui.painter().text(
        egui::pos2(rect.left() + 46.0, rect.center().y - 8.0),
        egui::Align2::LEFT_CENTER,
        tab.nav_label(language),
        egui::FontId::proportional(14.0),
        if selected {
            sidebar_text_color()
        } else {
            egui::Color32::from_rgb(203, 213, 225)
        },
    );
    ui.painter().text(
        egui::pos2(rect.left() + 46.0, rect.center().y + 10.0),
        egui::Align2::LEFT_CENTER,
        tab.nav_hint(language),
        egui::FontId::proportional(11.0),
        sidebar_muted_color(),
    );
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, true, tab.nav_label(language))
    });
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn sidebar_utility_button(ui: &mut egui::Ui, icon: UiIcon, label: &str) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
    if response.hovered() {
        ui.painter()
            .rect_filled(rect, 8.0, egui::Color32::from_rgb(43, 37, 48));
    }
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 18.0, rect.center().y),
        egui::vec2(16.0, 16.0),
    );
    let color = egui::Color32::from_rgb(248, 113, 113);
    paint_icon(ui.painter(), icon, icon_rect, color);
    ui.painter().text(
        egui::pos2(rect.left() + 36.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.0),
        color,
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn sidebar_status_row(ui: &mut egui::Ui, icon: UiIcon, label: &str) {
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 18.0, rect.center().y),
        egui::vec2(16.0, 16.0),
    );
    paint_icon(ui.painter(), icon, icon_rect, sidebar_muted_color());
    ui.painter().text(
        egui::pos2(rect.left() + 36.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(11.0),
        sidebar_muted_color(),
    );
}

fn page_header(
    ui: &mut egui::Ui,
    tab: Tab,
    show_tips: &mut bool,
    guidance_language: &mut GuidanceLanguage,
) -> bool {
    let mut language_changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new(tab.title(*guidance_language))
                    .size(27.0)
                    .strong()
                    .color(text_color()),
            );
            ui.label(
                egui::RichText::new(tab.subtitle(*guidance_language))
                    .size(13.0)
                    .color(muted_text_color()),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.toggle_value(show_tips, guidance_language.text("Guidance"));
            egui::ComboBox::from_id_salt("guidance_language")
                .selected_text(guidance_language.label())
                .width(112.0)
                .show_ui(ui, |ui| {
                    for language in GuidanceLanguage::ALL {
                        language_changed |= ui
                            .selectable_value(guidance_language, language, language.label())
                            .changed();
                    }
                });
        });
    });
    language_changed
}

fn paint_more_below_hint<R>(
    ui: &egui::Ui,
    output: &egui::scroll_area::ScrollAreaOutput<R>,
    language: GuidanceLanguage,
) {
    let overflow = (output.content_size.y - output.inner_rect.height()).max(0.0);
    let remaining = overflow - output.state.offset.y;
    if remaining <= 18.0 {
        return;
    }

    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(16));
    let time = ui.input(|input| input.time) as f32;
    let pulse = (time * 2.8).sin() * 0.5 + 0.5;
    let arrow_bob = (time * 4.2).sin() * 2.2;

    let fade_rect = egui::Rect::from_min_max(
        egui::pos2(output.inner_rect.left(), output.inner_rect.bottom() - 74.0),
        output.inner_rect.right_bottom(),
    );
    for step in 0..10 {
        let top = fade_rect.top() + fade_rect.height() * step as f32 / 10.0;
        let bottom = fade_rect.top() + fade_rect.height() * (step + 1) as f32 / 10.0;
        let alpha = (18.0 + step as f32 * 22.0) as u8;
        ui.painter().rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(fade_rect.left(), top),
                egui::pos2(fade_rect.right(), bottom),
            ),
            0.0,
            egui::Color32::from_rgba_unmultiplied(226, 245, 242, alpha),
        );
    }
    let hint_width = match language {
        GuidanceLanguage::English => 174.0,
        GuidanceLanguage::SimplifiedChinese => 190.0,
        GuidanceLanguage::Japanese => 176.0,
        GuidanceLanguage::Korean => 174.0,
    };
    let hint_rect = egui::Rect::from_center_size(
        egui::pos2(
            output.inner_rect.center().x,
            output.inner_rect.bottom() - 27.0,
        ),
        egui::vec2(hint_width, 38.0),
    );
    let glow = hint_rect.expand(3.0 + pulse * 2.0);
    ui.painter().rect_filled(
        glow,
        22.0,
        egui::Color32::from_rgba_unmultiplied(20, 184, 166, (32.0 + pulse * 24.0) as u8),
    );
    ui.painter().rect(
        hint_rect,
        19.0,
        egui::Color32::from_rgb(8, 104, 99),
        egui::Stroke::new(1.0, egui::Color32::from_rgb(94, 234, 212)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        egui::pos2(hint_rect.center().x - 8.0, hint_rect.center().y),
        egui::Align2::CENTER_CENTER,
        language.scroll_hint(),
        egui::FontId::proportional(12.0),
        egui::Color32::WHITE,
    );
    let arrow_x = hint_rect.right() - 24.0;
    let arrow_y = hint_rect.center().y + arrow_bob;
    let stroke = egui::Stroke::new(1.8, egui::Color32::from_rgb(153, 246, 228));
    ui.painter().line_segment(
        [
            egui::pos2(arrow_x, arrow_y - 4.0),
            egui::pos2(arrow_x, arrow_y + 4.0),
        ],
        stroke,
    );
    ui.painter().line_segment(
        [
            egui::pos2(arrow_x - 3.0, arrow_y + 1.0),
            egui::pos2(arrow_x, arrow_y + 4.0),
        ],
        stroke,
    );
    ui.painter().line_segment(
        [
            egui::pos2(arrow_x, arrow_y + 4.0),
            egui::pos2(arrow_x + 3.0, arrow_y + 1.0),
        ],
        stroke,
    );
}

fn section_card(
    ui: &mut egui::Ui,
    icon: UiIcon,
    title: &str,
    subtitle: &str,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::new()
        .fill(surface_color())
        .stroke(egui::Stroke::new(1.0, border_color()))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(34.0, 34.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 9.0, accent_soft_color());
                paint_icon(ui.painter(), icon, rect.shrink(8.0), accent_color());
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .size(16.0)
                            .strong()
                            .color(text_color()),
                    );
                    ui.label(
                        egui::RichText::new(subtitle)
                            .size(12.0)
                            .color(muted_text_color()),
                    );
                });
            });
            ui.add_space(16.0);
            add_contents(ui);
        });
}

fn action_button(ui: &mut egui::Ui, icon: UiIcon, label: &str, primary: bool) -> egui::Response {
    let width = (label.chars().count() as f32 * 7.4 + 48.0).clamp(132.0, 224.0);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(width, 38.0), egui::Sense::click());
    let (fill, stroke, foreground) = if primary {
        let fill = if response.is_pointer_button_down_on() {
            egui::Color32::from_rgb(10, 91, 86)
        } else if response.hovered() {
            egui::Color32::from_rgb(15, 133, 126)
        } else {
            accent_color()
        };
        (fill, egui::Stroke::NONE, egui::Color32::WHITE)
    } else {
        let fill = if response.hovered() {
            accent_soft_color()
        } else {
            egui::Color32::WHITE
        };
        (fill, egui::Stroke::new(1.0, border_color()), accent_color())
    };
    ui.painter()
        .rect(rect, 8.0, fill, stroke, egui::StrokeKind::Inside);
    let icon_rect = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 22.0, rect.center().y),
        egui::vec2(16.0, 16.0),
    );
    paint_icon(ui.painter(), icon, icon_rect, foreground);
    ui.painter().text(
        egui::pos2(rect.left() + 38.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.0),
        foreground,
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, true, label));
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn metadata_chip(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(241, 245, 249))
        .stroke(egui::Stroke::new(1.0, border_color()))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .size(11.0)
                    .color(muted_text_color()),
            );
        });
}

fn success_chip(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(236, 253, 245))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(167, 243, 208),
        ))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(11.0).color(success_color()));
        });
}

fn paint_icon_widget(ui: &mut egui::Ui, icon: UiIcon, size: f32, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    paint_icon(ui.painter(), icon, rect, color);
}

fn paint_icon(painter: &egui::Painter, icon: UiIcon, rect: egui::Rect, color: egui::Color32) {
    let stroke = egui::Stroke::new((rect.width() / 12.0).clamp(1.25, 1.8), color);
    let center = rect.center();
    let r = rect.shrink(rect.width() * 0.08);
    match icon {
        UiIcon::Backup => {
            let doc = egui::Rect::from_min_max(
                egui::pos2(r.left() + r.width() * 0.18, r.top()),
                egui::pos2(r.right() - r.width() * 0.12, r.bottom()),
            );
            painter.rect_stroke(doc, 2.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(center.x, center.y - r.height() * 0.18),
                    egui::pos2(center.x, center.y + r.height() * 0.24),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x - r.width() * 0.2, center.y + r.height() * 0.03),
                    egui::pos2(center.x + r.width() * 0.2, center.y + r.height() * 0.03),
                ],
                stroke,
            );
        }
        UiIcon::Open => {
            let path = vec![
                egui::pos2(r.left(), r.top() + r.height() * 0.32),
                egui::pos2(r.left() + r.width() * 0.34, r.top() + r.height() * 0.32),
                egui::pos2(r.left() + r.width() * 0.43, r.top() + r.height() * 0.18),
                egui::pos2(r.right(), r.top() + r.height() * 0.18),
                egui::pos2(r.right(), r.bottom()),
                egui::pos2(r.left(), r.bottom()),
                egui::pos2(r.left(), r.top() + r.height() * 0.32),
            ];
            painter.add(egui::Shape::line(path, stroke));
        }
        UiIcon::Recovery => {
            let top = egui::pos2(center.x, r.top() + r.height() * 0.18);
            let left = egui::pos2(r.left() + r.width() * 0.18, r.bottom() - r.height() * 0.18);
            let right = egui::pos2(r.right() - r.width() * 0.18, r.bottom() - r.height() * 0.18);
            painter.line_segment([top, left], stroke);
            painter.line_segment([top, right], stroke);
            painter.line_segment([left, right], stroke);
            for point in [top, left, right] {
                painter.circle_filled(point, r.width() * 0.11, color);
            }
        }
        UiIcon::Wallet => {
            painter.rect_stroke(r, 3.0, stroke, egui::StrokeKind::Inside);
            let clasp = egui::Rect::from_min_max(
                egui::pos2(center.x + r.width() * 0.08, center.y - r.height() * 0.16),
                egui::pos2(r.right(), center.y + r.height() * 0.2),
            );
            painter.rect_stroke(clasp, 2.0, stroke, egui::StrokeKind::Inside);
            painter.circle_filled(
                egui::pos2(clasp.left() + clasp.width() * 0.28, clasp.center().y),
                r.width() * 0.06,
                color,
            );
        }
        UiIcon::Shield => {
            let path = vec![
                egui::pos2(center.x, r.top()),
                egui::pos2(r.right(), r.top() + r.height() * 0.18),
                egui::pos2(r.right() - r.width() * 0.12, r.bottom() - r.height() * 0.23),
                egui::pos2(center.x, r.bottom()),
                egui::pos2(r.left() + r.width() * 0.12, r.bottom() - r.height() * 0.23),
                egui::pos2(r.left(), r.top() + r.height() * 0.18),
                egui::pos2(center.x, r.top()),
            ];
            painter.add(egui::Shape::line(path, stroke));
            painter.line_segment(
                [
                    egui::pos2(center.x - r.width() * 0.2, center.y),
                    egui::pos2(center.x - r.width() * 0.03, center.y + r.height() * 0.17),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x - r.width() * 0.03, center.y + r.height() * 0.17),
                    egui::pos2(center.x + r.width() * 0.24, center.y - r.height() * 0.15),
                ],
                stroke,
            );
        }
        UiIcon::Key => {
            painter.circle_stroke(
                egui::pos2(r.left() + r.width() * 0.3, center.y - r.height() * 0.08),
                r.width() * 0.22,
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.left() + r.width() * 0.46, center.y + r.height() * 0.08),
                    egui::pos2(r.right(), r.bottom()),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.right() - r.width() * 0.22, r.bottom() - r.height() * 0.22),
                    egui::pos2(r.right() - r.width() * 0.34, r.bottom() - r.height() * 0.1),
                ],
                stroke,
            );
        }
        UiIcon::Save => {
            painter.rect_stroke(r, 2.0, stroke, egui::StrokeKind::Inside);
            let slot = egui::Rect::from_min_max(
                egui::pos2(r.left() + r.width() * 0.2, r.top()),
                egui::pos2(r.right() - r.width() * 0.2, center.y - r.height() * 0.05),
            );
            painter.rect_stroke(slot, 1.0, stroke, egui::StrokeKind::Inside);
            painter.circle_stroke(
                egui::pos2(center.x, r.bottom() - r.height() * 0.23),
                r.width() * 0.13,
                stroke,
            );
        }
        UiIcon::Spark => {
            painter.line_segment(
                [
                    egui::pos2(center.x, r.top()),
                    egui::pos2(center.x, r.bottom()),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.left(), center.y),
                    egui::pos2(r.right(), center.y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.left() + r.width() * 0.18, r.top() + r.height() * 0.18),
                    egui::pos2(r.right() - r.width() * 0.18, r.bottom() - r.height() * 0.18),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.right() - r.width() * 0.18, r.top() + r.height() * 0.18),
                    egui::pos2(r.left() + r.width() * 0.18, r.bottom() - r.height() * 0.18),
                ],
                stroke,
            );
        }
        UiIcon::Info => {
            painter.circle_stroke(center, r.width() * 0.47, stroke);
            painter.circle_filled(
                egui::pos2(center.x, center.y - r.height() * 0.2),
                r.width() * 0.06,
                color,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x, center.y - r.height() * 0.02),
                    egui::pos2(center.x, center.y + r.height() * 0.25),
                ],
                stroke,
            );
        }
        UiIcon::Trash => {
            let body = egui::Rect::from_min_max(
                egui::pos2(r.left() + r.width() * 0.2, r.top() + r.height() * 0.28),
                egui::pos2(r.right() - r.width() * 0.2, r.bottom()),
            );
            painter.rect_stroke(body, 1.0, stroke, egui::StrokeKind::Inside);
            painter.line_segment(
                [
                    egui::pos2(r.left() + r.width() * 0.1, r.top() + r.height() * 0.25),
                    egui::pos2(r.right() - r.width() * 0.1, r.top() + r.height() * 0.25),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(center.x - r.width() * 0.15, r.top() + r.height() * 0.08),
                    egui::pos2(center.x + r.width() * 0.15, r.top() + r.height() * 0.08),
                ],
                stroke,
            );
        }
        UiIcon::Arrow => {
            painter.line_segment(
                [
                    egui::pos2(r.left(), center.y),
                    egui::pos2(r.right(), center.y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.right() - r.width() * 0.32, r.top() + r.height() * 0.18),
                    egui::pos2(r.right(), center.y),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(r.right(), center.y),
                    egui::pos2(r.right() - r.width() * 0.32, r.bottom() - r.height() * 0.18),
                ],
                stroke,
            );
        }
    }
}

fn language_combo(
    ui: &mut egui::Ui,
    id: &str,
    language: &mut MnemonicLanguage,
    app_language: GuidanceLanguage,
) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(language.localized_label(app_language))
        .show_ui(ui, |ui| {
            for value in MnemonicLanguage::ALL {
                ui.selectable_value(language, value, value.localized_label(app_language));
            }
        });
}

fn localized_group_count(language: GuidanceLanguage, count: usize) -> String {
    match language {
        GuidanceLanguage::English => format!("{count} SSKR groups"),
        GuidanceLanguage::SimplifiedChinese => format!("{count} 个 SSKR 组"),
        GuidanceLanguage::Japanese => format!("SSKR グループ：{count}"),
        GuidanceLanguage::Korean => format!("SSKR 그룹 {count}개"),
    }
}

fn localized_address_count(language: GuidanceLanguage, count: usize) -> String {
    match language {
        GuidanceLanguage::English => format!("{count} addresses"),
        GuidanceLanguage::SimplifiedChinese => format!("{count} 个地址"),
        GuidanceLanguage::Japanese => format!("アドレス：{count}"),
        GuidanceLanguage::Korean => format!("주소 {count}개"),
    }
}

fn localized_sskr_rule(language: GuidanceLanguage, settings: SskrSettings) -> String {
    match language {
        GuidanceLanguage::English => sskr_rule_label(settings),
        GuidanceLanguage::SimplifiedChinese => format!(
            "组门限 {}/{} · 组内份额门限 {}/{}",
            settings.group_threshold,
            settings.groups,
            settings.required_shares_per_group,
            settings.shares_per_group
        ),
        GuidanceLanguage::Japanese => format!(
            "グループしきい値 {}/{} · シェアしきい値 {}/{}",
            settings.group_threshold,
            settings.groups,
            settings.required_shares_per_group,
            settings.shares_per_group
        ),
        GuidanceLanguage::Korean => format!(
            "그룹 임계값 {}/{} · 그룹 내 조각 임계값 {}/{}",
            settings.group_threshold,
            settings.groups,
            settings.required_shares_per_group,
            settings.shares_per_group
        ),
    }
}

fn localized_group_share_heading(
    language: GuidanceLanguage,
    group: usize,
    shares: usize,
) -> String {
    match language {
        GuidanceLanguage::English => format!("Group {group} - {shares} share(s)"),
        GuidanceLanguage::SimplifiedChinese => format!("第 {group} 组 · {shares} 个份额"),
        GuidanceLanguage::Japanese => format!("グループ {group} · {shares} シェア"),
        GuidanceLanguage::Korean => format!("그룹 {group} · 조각 {shares}개"),
    }
}

fn localized_share_heading(language: GuidanceLanguage, share: usize) -> String {
    match language {
        GuidanceLanguage::English => format!("Share {share}"),
        GuidanceLanguage::SimplifiedChinese => format!("份额 {share}"),
        GuidanceLanguage::Japanese => format!("シェア {share}"),
        GuidanceLanguage::Korean => format!("조각 {share}"),
    }
}

fn localized_item_heading(language: GuidanceLanguage, item: usize) -> String {
    match language {
        GuidanceLanguage::English => format!("Item {item}"),
        GuidanceLanguage::SimplifiedChinese => format!("项目 {item}"),
        GuidanceLanguage::Japanese => format!("項目 {item}"),
        GuidanceLanguage::Korean => format!("항목 {item}"),
    }
}

fn localized_field_count(language: GuidanceLanguage, label: &str, count: usize) -> String {
    let separator = if label.is_empty() { "" } else { " · " };
    match language {
        GuidanceLanguage::English => format!("{label}{separator}{count} field(s)"),
        GuidanceLanguage::SimplifiedChinese => format!("{label}{separator}{count} 个字段"),
        GuidanceLanguage::Japanese => format!("{label}{separator}{count} フィールド"),
        GuidanceLanguage::Korean => format!("{label}{separator}필드 {count}개"),
    }
}

fn localized_item_count(language: GuidanceLanguage, label: &str, count: usize) -> String {
    let separator = if label.is_empty() { "" } else { " · " };
    match language {
        GuidanceLanguage::English => format!("{label}{separator}{count} item(s)"),
        GuidanceLanguage::SimplifiedChinese => format!("{label}{separator}{count} 个项目"),
        GuidanceLanguage::Japanese => format!("{label}{separator}{count} 項目"),
        GuidanceLanguage::Korean => format!("{label}{separator}항목 {count}개"),
    }
}

fn localized_hidden_count(language: GuidanceLanguage, count: usize, fields: bool) -> String {
    match (language, fields) {
        (GuidanceLanguage::English, true) => format!("<hidden: {count} field(s)>"),
        (GuidanceLanguage::English, false) => format!("<hidden: {count} item(s)>"),
        (GuidanceLanguage::SimplifiedChinese, true) => format!("<已隐藏：{count} 个字段>"),
        (GuidanceLanguage::SimplifiedChinese, false) => format!("<已隐藏：{count} 个项目>"),
        (GuidanceLanguage::Japanese, true) => format!("<非表示：{count} フィールド>"),
        (GuidanceLanguage::Japanese, false) => format!("<非表示：{count} 項目>"),
        (GuidanceLanguage::Korean, true) => format!("<숨김: 필드 {count}개>"),
        (GuidanceLanguage::Korean, false) => format!("<숨김: 항목 {count}개>"),
    }
}

fn localized_error(language: GuidanceLanguage, detail: &str) -> String {
    format!("{}: {detail}", language.text("Error"))
}

fn localized_saved_status(language: GuidanceLanguage, sskr: bool, path: &Path) -> String {
    let path = path.display();
    match (language, sskr) {
        (GuidanceLanguage::English, true) => format!("Saved encrypted SSKR backup to {path}."),
        (GuidanceLanguage::English, false) => {
            format!("Saved encrypted mnemonic backup to {path}.")
        }
        (GuidanceLanguage::SimplifiedChinese, true) => {
            format!("已将加密 SSKR 备份保存到 {path}。")
        }
        (GuidanceLanguage::SimplifiedChinese, false) => {
            format!("已将加密助记词备份保存到 {path}。")
        }
        (GuidanceLanguage::Japanese, true) => {
            format!("暗号化 SSKR バックアップを {path} に保存しました。")
        }
        (GuidanceLanguage::Japanese, false) => {
            format!("暗号化ニーモニックバックアップを {path} に保存しました。")
        }
        (GuidanceLanguage::Korean, true) => {
            format!("암호화된 SSKR 백업을 {path}에 저장했습니다.")
        }
        (GuidanceLanguage::Korean, false) => {
            format!("암호화된 니모닉 백업을 {path}에 저장했습니다.")
        }
    }
}

fn localized_max_address_status(language: GuidanceLanguage, count: u32) -> String {
    match language {
        GuidanceLanguage::English => format!("Derive at most {count} addresses at once."),
        GuidanceLanguage::SimplifiedChinese => format!("每次最多派生 {count} 个地址。"),
        GuidanceLanguage::Japanese => format!("一度に導出できるアドレスは {count} 件までです。"),
        GuidanceLanguage::Korean => format!("한 번에 최대 {count}개 주소를 파생할 수 있습니다."),
    }
}

fn localized_derived_status(language: GuidanceLanguage, count: usize) -> String {
    match language {
        GuidanceLanguage::English => format!("Derived {count} address rows."),
        GuidanceLanguage::SimplifiedChinese => format!("已派生 {count} 个地址。"),
        GuidanceLanguage::Japanese => format!("{count} 件のアドレスを導出しました。"),
        GuidanceLanguage::Korean => format!("주소 {count}개를 파생했습니다."),
    }
}

fn tips_panel(ui: &mut egui::Ui, tab: Tab, language: GuidanceLanguage) {
    let (title, body) = language.tip(tab);

    egui::Frame::new()
        .fill(egui::Color32::from_rgb(238, 247, 246))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(186, 224, 220),
        ))
        .corner_radius(10.0)
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                paint_icon_widget(ui, UiIcon::Info, 18.0, accent_color());
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new(title)
                            .size(13.0)
                            .strong()
                            .color(text_color()),
                    );
                    ui.label(
                        egui::RichText::new(body)
                            .size(12.0)
                            .color(muted_text_color()),
                    );
                });
            });
        });
}

fn form_label(ui: &mut egui::Ui, label: &str) {
    ui.add_sized(
        [FORM_LABEL_WIDTH, FIELD_HEIGHT],
        egui::Label::new(
            egui::RichText::new(label)
                .size(12.0)
                .color(muted_text_color()),
        )
        .halign(egui::Align::RIGHT),
    );
}

fn stacked_form_label(ui: &mut egui::Ui, label: &str) {
    ui.label(
        egui::RichText::new(label)
            .size(12.0)
            .color(muted_text_color()),
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
    if ui.available_width() < 620.0 {
        stacked_form_label(ui, label);
        ui.horizontal(|ui| {
            let button_width = button_label.map(|_| FORM_BUTTON_WIDTH).unwrap_or(0.0);
            let field_width =
                (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(180.0);
            let mut edit = egui::TextEdit::singleline(value).desired_width(field_width);
            if password {
                edit = edit.password(true);
            }
            ui.add_sized([field_width, FIELD_HEIGHT], edit);
            if let Some(button_label) = button_label {
                clicked = ui
                    .add_sized(
                        [FORM_BUTTON_WIDTH, FIELD_HEIGHT],
                        egui::Button::new(button_label),
                    )
                    .clicked();
            }
        });
        return clicked;
    }

    ui.horizontal(|ui| {
        form_label(ui, label);
        let button_width = button_label.map(|_| FORM_BUTTON_WIDTH).unwrap_or(0.0);
        let field_width =
            (ui.available_width() - button_width - ui.spacing().item_spacing.x).max(240.0);
        let mut edit = egui::TextEdit::singleline(value).desired_width(field_width);
        if password {
            edit = edit.password(true);
        }
        ui.add_sized([field_width, FIELD_HEIGHT], edit);
        if let Some(button_label) = button_label {
            clicked = ui
                .add_sized(
                    [FORM_BUTTON_WIDTH, FIELD_HEIGHT],
                    egui::Button::new(button_label),
                )
                .clicked();
        }
    });
    clicked
}

fn multiline_text_row(ui: &mut egui::Ui, label: &str, value: &mut String, rows: usize) {
    if ui.available_width() < 620.0 {
        stacked_form_label(ui, label);
        let field_width = ui.available_width().max(180.0);
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
        ui.add_sized(
            [field_width, row_height * rows as f32],
            egui::TextEdit::multiline(value)
                .desired_rows(rows)
                .lock_focus(true)
                .desired_width(field_width),
        );
        return;
    }

    ui.horizontal(|ui| {
        form_label(ui, label);
        let field_width = ui.available_width().max(240.0);
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 8.0;
        ui.add_sized(
            [field_width, row_height * rows as f32],
            egui::TextEdit::multiline(value)
                .desired_rows(rows)
                .lock_focus(true)
                .desired_width(field_width),
        );
    });
}

fn choose_existing_file(
    title: &str,
    target: &mut String,
    extensions: &[&str],
    language: GuidanceLanguage,
) {
    let mut dialog = FileDialog::new().set_title(title);
    if !extensions.is_empty() {
        dialog = dialog.add_filter(language.text("Supported files"), extensions);
    }
    if let Some(path) = dialog.pick_file() {
        *target = path_to_string(path);
    }
}

fn choose_save_file(target: &mut String, language: GuidanceLanguage) {
    let mut dialog = FileDialog::new()
        .set_title(language.text("Save encrypted backup"))
        .set_file_name(DEFAULT_BACKUP_FILE)
        .add_filter(language.text("age backup"), &["age"]);

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
    language: GuidanceLanguage,
) {
    ui.add_space(8.0);
    match value {
        serde_json::Value::Object(map) => {
            render_backup_summary(ui, map, recovered_seed_phrase.is_some(), language);
            if let Some(seed_phrase) = recovered_seed_phrase {
                render_recovered_seed_material(ui, seed_phrase, reveal_sensitive, language);
            }
            render_seed_material(ui, map, reveal_sensitive, language);
            render_sskr_material(ui, map, reveal_sensitive, language);
            render_additional_fields(ui, map, reveal_sensitive, language);
        }
        _ => {
            section_header(ui, language.text("Decrypted JSON"));
            render_json_field(ui, "Value", value, reveal_sensitive, language);
        }
    }
}

fn render_backup_summary(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    recovered_from_sskr: bool,
    language: GuidanceLanguage,
) {
    section_header(ui, language.text("Backup Summary"));
    field_grid(ui, "backup_summary_grid", |ui| {
        render_field_row(
            ui,
            language.text("Type"),
            backup_kind_label(map, language),
            false,
            egui::Color32::DARK_GRAY,
        );
        if let Some(value) = map.get("language") {
            render_field_row(
                ui,
                language.text("Language"),
                display_json_value("language", value, true, language),
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
                    human_json_key(key, language),
                    display_json_value(key, value, true, language),
                    false,
                    egui::Color32::DARK_GRAY,
                );
            }
        }
        if let Some(value) = map.get("recovery_info") {
            render_field_row(
                ui,
                language.text("Recovery Rule"),
                display_json_value("recovery_info", value, true, language),
                false,
                egui::Color32::DARK_GRAY,
            );
        }
        render_field_row(
            ui,
            language.text("Top-Level Fields"),
            map.len().to_string(),
            false,
            egui::Color32::DARK_GRAY,
        );
        if recovered_from_sskr {
            render_field_row(
                ui,
                language.text("SSKR Recovery"),
                language.text("Recovered automatically").to_string(),
                false,
                egui::Color32::DARK_GRAY,
            );
        }
    });
}

fn render_recovered_seed_material(
    ui: &mut egui::Ui,
    seed_phrase: &str,
    reveal_sensitive: bool,
    language: GuidanceLanguage,
) {
    section_header(ui, language.text("Recovered Seed Material"));
    field_grid(ui, "recovered_seed_material_grid", |ui| {
        let display = if reveal_sensitive {
            seed_phrase.to_string()
        } else {
            mask_secret_text(seed_phrase, language)
        };
        render_field_row(
            ui,
            language.text("Seed phrase"),
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
    language: GuidanceLanguage,
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

    section_header(ui, language.text("Seed Material"));
    field_grid(ui, "seed_material_grid", |ui| {
        for key in seed_keys {
            if let Some(value) = map.get(key) {
                render_field_row(
                    ui,
                    human_json_key(key, language),
                    display_json_value(key, value, reveal_sensitive, language),
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
    language: GuidanceLanguage,
) {
    let Some(sskr) = map.get("sskr") else {
        return;
    };
    let Some(groups) = sskr.get("groups").and_then(serde_json::Value::as_array) else {
        section_header(ui, "SSKR");
        render_json_field(ui, "sskr", sskr, reveal_sensitive, language);
        return;
    };

    section_header(ui, language.text("SSKR Shares"));
    field_grid(ui, "sskr_summary_grid", |ui| {
        render_field_row(
            ui,
            language.text("Groups"),
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
            language.text("Total Shares"),
            share_count.to_string(),
            false,
            egui::Color32::DARK_GRAY,
        );
    });

    for (group_index, group) in groups.iter().enumerate() {
        let share_count = group.as_array().map(Vec::len).unwrap_or(0);
        egui::CollapsingHeader::new(
            egui::RichText::new(localized_group_share_heading(
                language,
                group_index + 1,
                share_count,
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
                        egui::RichText::new(localized_share_heading(language, share_index + 1))
                            .strong(),
                    );
                    render_share(
                        ui,
                        group_index,
                        share_index,
                        share,
                        reveal_sensitive,
                        language,
                    );
                }
            } else {
                render_json_field(ui, "Group Data", group, reveal_sensitive, language);
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
                egui::RichText::new(language.text("SSKR Metadata")).strong(),
            );
            for (key, value) in extra_fields {
                render_json_field(ui, key, value, reveal_sensitive, language);
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
    language: GuidanceLanguage,
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
                                human_json_key(key, language),
                                display_json_value(key, value, reveal_sensitive, language),
                                true,
                                sensitive_color(key, reveal_sensitive),
                            );
                        }
                    }
                    for (key, value) in map {
                        if key != "share_hex" && key != "mnemonic" {
                            render_field_row(
                                ui,
                                human_json_key(key, language),
                                display_json_value(key, value, reveal_sensitive, language),
                                should_use_monospace(key, value),
                                sensitive_color(key, reveal_sensitive),
                            );
                        }
                    }
                },
            );
        }
        _ => render_json_field(ui, "Share Data", share, reveal_sensitive, language),
    }
}

fn render_additional_fields(
    ui: &mut egui::Ui,
    map: &serde_json::Map<String, serde_json::Value>,
    reveal_sensitive: bool,
    language: GuidanceLanguage,
) {
    let additional = map
        .iter()
        .filter(|(key, _)| !is_known_backup_key(key))
        .collect::<Vec<_>>();
    if additional.is_empty() {
        return;
    }

    section_header(ui, language.text("Additional Fields"));
    for (key, value) in additional {
        render_json_field(ui, key, value, reveal_sensitive, language);
    }
}

fn render_json_field(
    ui: &mut egui::Ui,
    key: &str,
    value: &serde_json::Value,
    reveal_sensitive: bool,
    language: GuidanceLanguage,
) {
    if is_sensitive_json_key(key) {
        field_grid(ui, &format!("json_sensitive_{key}_grid"), |ui| {
            render_field_row(
                ui,
                human_json_key(key, language),
                display_json_value(key, value, reveal_sensitive, language),
                true,
                sensitive_color(key, reveal_sensitive),
            );
        });
        return;
    }

    match value {
        serde_json::Value::Object(map) => {
            egui::CollapsingHeader::new(
                egui::RichText::new(localized_field_count(
                    language,
                    human_json_key(key, language),
                    map.len(),
                ))
                .strong()
                .color(section_color()),
            )
            .default_open(true)
            .show(ui, |ui| {
                for (child_key, child_value) in map {
                    render_json_field(ui, child_key, child_value, reveal_sensitive, language);
                }
            });
        }
        serde_json::Value::Array(items) => {
            egui::CollapsingHeader::new(
                egui::RichText::new(localized_item_count(
                    language,
                    human_json_key(key, language),
                    items.len(),
                ))
                .strong()
                .color(section_color()),
            )
            .default_open(items.len() <= 4)
            .show(ui, |ui| {
                for (index, item) in items.iter().enumerate() {
                    render_json_field(
                        ui,
                        &localized_item_heading(language, index + 1),
                        item,
                        reveal_sensitive,
                        language,
                    );
                }
            });
        }
        _ => {
            field_grid(ui, &format!("json_scalar_{key}_grid"), |ui| {
                render_field_row(
                    ui,
                    human_json_key(key, language),
                    display_json_value(key, value, reveal_sensitive, language),
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

fn backup_kind_label(
    map: &serde_json::Map<String, serde_json::Value>,
    language: GuidanceLanguage,
) -> String {
    let sskr_groups = map
        .get("sskr")
        .and_then(|value| value.get("groups"))
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    if sskr_groups > 0 {
        match language {
            GuidanceLanguage::English => "SSKR share backup",
            GuidanceLanguage::SimplifiedChinese => "SSKR 份额备份",
            GuidanceLanguage::Japanese => "SSKR シェアバックアップ",
            GuidanceLanguage::Korean => "SSKR 조각 백업",
        }
        .to_string()
    } else if map.contains_key("seed_phrase") {
        match language {
            GuidanceLanguage::English => "Mnemonic backup",
            GuidanceLanguage::SimplifiedChinese => "助记词备份",
            GuidanceLanguage::Japanese => "ニーモニックバックアップ",
            GuidanceLanguage::Korean => "니모닉 백업",
        }
        .to_string()
    } else {
        match language {
            GuidanceLanguage::English => "JSON backup",
            GuidanceLanguage::SimplifiedChinese => "JSON 备份",
            GuidanceLanguage::Japanese => "JSON バックアップ",
            GuidanceLanguage::Korean => "JSON 백업",
        }
        .to_string()
    }
}

fn display_json_value(
    key: &str,
    value: &serde_json::Value,
    reveal_sensitive: bool,
    language: GuidanceLanguage,
) -> String {
    if is_sensitive_json_key(key) && !reveal_sensitive {
        return masked_json_summary(value, language);
    }

    if let serde_json::Value::String(text) = value {
        if key == "language" {
            return MnemonicLanguage::from_backup_name(text)
                .localized_label(language)
                .to_string();
        }
        if key == "backup_type" && text == "mnemonic" {
            return backup_type_mnemonic(language).to_string();
        }
        if key == "recovery_info" && text == "Mnemonic seed phrase backup" {
            return mnemonic_backup_description(language).to_string();
        }
        if key == "recovery_info" {
            if let Some(settings) = parse_stored_sskr_rule(text) {
                return localized_sskr_rule(language, settings);
            }
        }
    }

    match value {
        serde_json::Value::Null => language.text("None").to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Array(items) => localized_item_count(language, "", items.len()),
        serde_json::Value::Object(map) => localized_field_count(language, "", map.len()),
    }
}

fn masked_json_summary(value: &serde_json::Value, language: GuidanceLanguage) -> String {
    match value {
        serde_json::Value::String(text) => mask_secret_text(text, language),
        serde_json::Value::Array(items) => localized_hidden_count(language, items.len(), false),
        serde_json::Value::Object(map) => localized_hidden_count(language, map.len(), true),
        serde_json::Value::Null => language.text("None").to_string(),
        _ => match language {
            GuidanceLanguage::English => "<hidden>",
            GuidanceLanguage::SimplifiedChinese => "<已隐藏>",
            GuidanceLanguage::Japanese => "<非表示>",
            GuidanceLanguage::Korean => "<숨김>",
        }
        .to_string(),
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

fn human_json_key(key: &str, language: GuidanceLanguage) -> &str {
    language.text(match key {
        "language" => "Language",
        "seed_phrase" => "Seed phrase",
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
        "Value" => "Value",
        "Group Data" => "Group Data",
        "Share Data" => "Share Data",
        _ => return key,
    })
}

fn backup_type_mnemonic(language: GuidanceLanguage) -> &'static str {
    match language {
        GuidanceLanguage::English => "mnemonic",
        GuidanceLanguage::SimplifiedChinese => "助记词",
        GuidanceLanguage::Japanese => "ニーモニック",
        GuidanceLanguage::Korean => "니모닉",
    }
}

fn mnemonic_backup_description(language: GuidanceLanguage) -> &'static str {
    match language {
        GuidanceLanguage::English => "Mnemonic seed phrase backup",
        GuidanceLanguage::SimplifiedChinese => "BIP-39 助记词备份",
        GuidanceLanguage::Japanese => "BIP-39 ニーモニックのバックアップ",
        GuidanceLanguage::Korean => "BIP-39 니모닉 백업",
    }
}

fn parse_stored_sskr_rule(value: &str) -> Option<SskrSettings> {
    if !value.starts_with("Recovery rule:") {
        return None;
    }
    let numbers = value
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if numbers.len() != 4 {
        return None;
    }
    Some(SskrSettings {
        group_threshold: numbers[0],
        groups: numbers[1],
        required_shares_per_group: numbers[2],
        shares_per_group: numbers[3],
    })
}

fn section_color() -> egui::Color32 {
    accent_color()
}

fn subheader_color() -> egui::Color32 {
    egui::Color32::from_rgb(15, 118, 110)
}

fn label_color() -> egui::Color32 {
    muted_text_color()
}

fn sensitive_color(key: &str, reveal_sensitive: bool) -> egui::Color32 {
    if is_sensitive_json_key(key) && reveal_sensitive {
        warning_color()
    } else {
        text_color()
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

fn mask_secret_text(text: &str, language: GuidanceLanguage) -> String {
    if text.is_empty() {
        return String::new();
    }
    let word_count = text.split_whitespace().count();
    if word_count > 1 {
        return match language {
            GuidanceLanguage::English => format!("<hidden: {word_count} words>"),
            GuidanceLanguage::SimplifiedChinese => format!("<已隐藏：{word_count} 个词>"),
            GuidanceLanguage::Japanese => format!("<非表示：{word_count} 語>"),
            GuidanceLanguage::Korean => format!("<숨김: {word_count}단어>"),
        };
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

fn status_is_error(status: &str) -> bool {
    status.contains("failed")
        || status.contains("Failed")
        || status.contains("Error")
        || status.contains("must")
        || status.contains("cannot")
        || status.contains("not ")
        || status.contains("requires")
        || status.contains("invalid")
        || status.contains("错误")
        || status.contains("失败")
        || status.contains("エラー")
        || status.contains("失敗")
        || status.contains("오류")
        || status.contains("실패")
}

fn status_banner(ui: &mut egui::Ui, status: &str) {
    if status.is_empty() {
        return;
    }
    ui.add_space(10.0);
    let is_error = status_is_error(status);
    let (foreground, background, border) = if is_error {
        (
            error_color(),
            egui::Color32::from_rgb(254, 242, 242),
            egui::Color32::from_rgb(254, 202, 202),
        )
    } else {
        (
            success_color(),
            egui::Color32::from_rgb(240, 253, 244),
            egui::Color32::from_rgb(187, 247, 208),
        )
    };
    egui::Frame::new()
        .fill(background)
        .stroke(egui::Stroke::new(1.0, border))
        .corner_radius(8.0)
        .inner_margin(egui::Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                paint_icon_widget(
                    ui,
                    if is_error {
                        UiIcon::Info
                    } else {
                        UiIcon::Shield
                    },
                    16.0,
                    foreground,
                );
                ui.label(egui::RichText::new(status).size(12.0).color(foreground));
            });
        });
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

#[derive(Deserialize)]
struct AgeGitHubRelease {
    tag_name: String,
    assets: Vec<AgeGitHubAsset>,
}

#[derive(Deserialize)]
struct AgeGitHubAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
}

fn spawn_age_auto_update() {
    std::thread::spawn(|| {
        let _ = update_age_component();
    });
}

fn age_executable_name(os: &str) -> &'static str {
    if os == "windows" {
        "age.exe"
    } else {
        "age"
    }
}

fn age_release_asset_name(tag: &str, os: &str, arch: &str) -> Option<String> {
    let platform = match (os, arch) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("linux", "x86_64") => "linux-amd64",
        ("windows", "x86_64") => "windows-amd64",
        _ => return None,
    };
    let extension = if os == "windows" { "zip" } else { "tar.gz" };
    Some(format!("age-{tag}-{platform}.{extension}"))
}

fn parse_age_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.trim().trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_text = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let patch_digits = patch_text
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if patch_digits.is_empty() {
        return None;
    }
    Some((major, minor, patch_digits.parse().ok()?))
}

fn age_cache_root() -> Option<PathBuf> {
    dirs::data_local_dir().map(|directory| directory.join("BIP39 Tool").join("age"))
}

fn auto_updated_age_binary() -> Option<PathBuf> {
    let root = age_cache_root()?;
    let bundled_version = parse_age_version(BUNDLED_AGE_VERSION)?;
    let executable_name = age_executable_name(std::env::consts::OS);
    std::fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let version_name = entry.file_name();
            let version = parse_age_version(version_name.to_str()?)?;
            let binary = entry.path().join(executable_name);
            (version >= bundled_version && binary.is_file()).then_some((version, binary))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, binary)| binary)
}

fn update_age_component() -> Result<(), String> {
    let root =
        age_cache_root().ok_or_else(|| "No per-user data directory available.".to_string())?;
    let check_marker = root.join("last-check");
    if std::fs::metadata(&check_marker)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|elapsed| elapsed < AGE_UPDATE_INTERVAL)
    {
        return Ok(());
    }

    let release: AgeGitHubRelease = ureq::get(AGE_RELEASE_API)
        .set("Accept", "application/vnd.github+json")
        .set(
            "User-Agent",
            concat!("bip39-tool/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|error| format!("Could not check the latest age release: {error}"))?
        .into_json()
        .map_err(|error| format!("Could not read the age release response: {error}"))?;

    let latest_version = parse_age_version(&release.tag_name)
        .ok_or_else(|| "The latest age release has an invalid version.".to_string())?;
    let bundled_version = parse_age_version(BUNDLED_AGE_VERSION)
        .ok_or_else(|| "The bundled age version is invalid.".to_string())?;
    let version_directory = root.join(format!(
        "v{}.{}.{}",
        latest_version.0, latest_version.1, latest_version.2
    ));
    let executable_name = age_executable_name(std::env::consts::OS);
    let installed_binary = version_directory.join(executable_name);

    if latest_version > bundled_version && !installed_binary.is_file() {
        let asset_name = age_release_asset_name(
            &release.tag_name,
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
        .ok_or_else(|| "No automatic age update is available for this platform.".to_string())?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or_else(|| format!("The age release does not contain {asset_name}."))?;
        install_age_release(asset, &version_directory, executable_name)?;
    }

    std::fs::create_dir_all(&root)
        .map_err(|error| format!("Could not create the age update directory: {error}"))?;
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(check_marker)
        .and_then(|mut file| file.write_all(release.tag_name.as_bytes()))
        .map_err(|error| format!("Could not record the age update check: {error}"))?;
    Ok(())
}

fn install_age_release(
    asset: &AgeGitHubAsset,
    version_directory: &Path,
    executable_name: &str,
) -> Result<(), String> {
    if !asset.browser_download_url.starts_with(AGE_DOWNLOAD_PREFIX) {
        return Err("The age release asset does not use the official download host.".to_string());
    }
    let expected_digest = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64)
        .ok_or_else(|| "The age release asset has no SHA-256 digest.".to_string())?;
    let archive = read_limited(
        ureq::get(&asset.browser_download_url)
            .set(
                "User-Agent",
                concat!("bip39-tool/", env!("CARGO_PKG_VERSION")),
            )
            .call()
            .map_err(|error| format!("Could not download the age release: {error}"))?
            .into_reader(),
        MAX_AGE_ARCHIVE_BYTES,
        "age release archive",
    )?;
    let actual_digest = hex::encode(Sha256::digest(&archive));
    if !actual_digest.eq_ignore_ascii_case(expected_digest) {
        return Err("The downloaded age release failed SHA-256 verification.".to_string());
    }

    let (executable, license) = if asset.name.ends_with(".zip") {
        read_age_zip(&archive, executable_name)?
    } else {
        read_age_tar_gz(&archive, executable_name)?
    };
    std::fs::create_dir_all(version_directory)
        .map_err(|error| format!("Could not create the age version directory: {error}"))?;
    write_age_update_file(&version_directory.join("LICENSE"), &license)?;

    let executable_suffix = if executable_name.ends_with(".exe") {
        ".exe"
    } else {
        ""
    };
    let mut temporary_file = tempfile::Builder::new()
        .prefix(".age-update-")
        .suffix(executable_suffix)
        .tempfile_in(version_directory)
        .map_err(|error| format!("Could not create the temporary age update: {error}"))?;
    temporary_file
        .as_file_mut()
        .write_all(&executable)
        .and_then(|()| temporary_file.as_file().sync_all())
        .map_err(|error| format!("Could not write the temporary age update: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("Could not make the age update executable: {error}"))?;
    }
    let temporary_binary = temporary_file.path().to_path_buf();
    let final_binary = version_directory.join(executable_name);
    let validation = Command::new(&temporary_binary).arg("--version").output();
    if !validation.is_ok_and(|output| output.status.success()) {
        return Err("The downloaded age executable did not pass its launch check.".to_string());
    }
    if !final_binary.is_file() {
        temporary_file
            .persist_noclobber(&final_binary)
            .map_err(|error| format!("Could not activate the age update: {}", error.error))?;
    }
    Ok(())
}

fn read_limited<R: Read>(reader: R, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Could not read the {label}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("The {label} is unexpectedly large."));
    }
    Ok(bytes)
}

fn read_age_tar_gz(archive: &[u8], executable_name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let decoder = flate2::read::GzDecoder::new(archive);
    let mut tar_archive = tar::Archive::new(decoder);
    let mut executable = None;
    let mut license = None;
    for entry in tar_archive
        .entries()
        .map_err(|error| format!("Could not open the age archive: {error}"))?
    {
        let mut entry =
            entry.map_err(|error| format!("Could not read the age archive: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("Could not read an age archive path: {error}"))?;
        if path == Path::new("age").join(executable_name) {
            executable = Some(read_limited(
                &mut entry,
                MAX_AGE_EXECUTABLE_BYTES,
                "age executable",
            )?);
        } else if path == Path::new("age/LICENSE") {
            license = Some(read_limited(
                &mut entry,
                MAX_AGE_LICENSE_BYTES,
                "age license",
            )?);
        }
    }
    Ok((
        executable.ok_or_else(|| "The age archive has no executable.".to_string())?,
        license.ok_or_else(|| "The age archive has no license.".to_string())?,
    ))
}

fn read_age_zip(archive: &[u8], executable_name: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let reader = std::io::Cursor::new(archive);
    let mut zip_archive = zip::ZipArchive::new(reader)
        .map_err(|error| format!("Could not open the age archive: {error}"))?;
    let mut executable = None;
    let mut license = None;
    for index in 0..zip_archive.len() {
        let mut entry = zip_archive
            .by_index(index)
            .map_err(|error| format!("Could not read the age archive: {error}"))?;
        if entry.name() == format!("age/{executable_name}") {
            executable = Some(read_limited(
                &mut entry,
                MAX_AGE_EXECUTABLE_BYTES,
                "age executable",
            )?);
        } else if entry.name() == "age/LICENSE" {
            license = Some(read_limited(
                &mut entry,
                MAX_AGE_LICENSE_BYTES,
                "age license",
            )?);
        }
    }
    Ok((
        executable.ok_or_else(|| "The age archive has no executable.".to_string())?,
        license.ok_or_else(|| "The age archive has no license.".to_string())?,
    ))
}

fn write_age_update_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("Could not finish writing {}: {error}", path.display()))?;
    Ok(())
}

fn resolve_age_binary(
    override_binary: Option<OsString>,
    updated_binary: Option<PathBuf>,
    current_executable: Option<&Path>,
) -> OsString {
    if let Some(binary) = override_binary {
        return binary;
    }

    if let Some(binary) = updated_binary.filter(|path| path.is_file()) {
        return binary.into_os_string();
    }

    if let Some(bundled_binary) = current_executable
        .and_then(Path::parent)
        .map(|directory| directory.join(age_executable_name(std::env::consts::OS)))
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
        auto_updated_age_binary(),
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
            resolve_age_binary(None, None, Some(&executable)),
            bundled_age.into_os_string()
        );
    }

    #[test]
    fn verified_age_update_is_preferred_over_bundled_binary() {
        let tempdir = tempfile::tempdir().unwrap();
        let executable = tempdir.path().join("bip39");
        let bundled_age = tempdir.path().join("age");
        let updated_age = tempdir.path().join("updated-age");
        std::fs::write(bundled_age, b"bundled age").unwrap();
        std::fs::write(&updated_age, b"updated age").unwrap();

        assert_eq!(
            resolve_age_binary(None, Some(updated_age.clone()), Some(&executable)),
            updated_age.into_os_string()
        );
    }

    #[test]
    fn configured_age_binary_overrides_bundled_binary() {
        let tempdir = tempfile::tempdir().unwrap();
        let executable = tempdir.path().join("bip39");
        std::fs::write(tempdir.path().join("age"), b"bundled age").unwrap();
        let configured = OsString::from("/custom/age");

        assert_eq!(
            resolve_age_binary(Some(configured.clone()), None, Some(&executable)),
            configured
        );
    }

    #[test]
    fn age_binary_falls_back_to_path_lookup() {
        assert_eq!(resolve_age_binary(None, None, None), OsString::from("age"));
    }

    #[test]
    fn age_release_assets_cover_packaged_platforms() {
        assert_eq!(
            age_release_asset_name("v1.3.1", "macos", "aarch64").as_deref(),
            Some("age-v1.3.1-darwin-arm64.tar.gz")
        );
        assert_eq!(
            age_release_asset_name("v1.3.1", "linux", "x86_64").as_deref(),
            Some("age-v1.3.1-linux-amd64.tar.gz")
        );
        assert_eq!(
            age_release_asset_name("v1.3.1", "windows", "x86_64").as_deref(),
            Some("age-v1.3.1-windows-amd64.zip")
        );
    }

    #[test]
    fn age_versions_are_compared_numerically() {
        assert!(parse_age_version("v1.10.0") > parse_age_version("v1.9.9"));
        assert_eq!(parse_age_version("1.3.1"), Some((1, 3, 1)));
        assert_eq!(parse_age_version("latest"), None);
    }

    #[test]
    fn app_languages_translate_complete_primary_workflow() {
        let workflow_copy = [
            "Encrypted recovery",
            "Clear sensitive data",
            "Secrets: memory only",
            "Guidance",
            "Seed material",
            "Choose the mnemonic and optional BIP-39 passphrase to protect.",
            "Source",
            "Generate new",
            "Import existing",
            "Language",
            "Generate seed",
            "Seed phrase",
            "Reveal generated phrase",
            "Passphrase",
            "Optional BIP-39 passphrase",
            "Reveal passphrase",
            "Include passphrase in encrypted backup",
            "Recovery format",
            "Optionally replace the stored mnemonic with threshold recovery shares.",
            "Split seed into recovery shares",
            "Groups",
            "Create",
            "Require",
            "Shares per group",
            "Recovery rule",
            "Encrypt and save",
            "Recipient",
            "Choose file",
            "Backup file",
            "Save as",
            "Unlock backup",
            "Open file",
            "Private identity",
            "Reveal identity",
            "Decrypt backup",
            "Decrypted contents",
            "Recovery complete",
            "Reveal sensitive values",
            "Open address derivation",
            "Recovery shares",
            "Share language",
            "SSKR shares",
            "Wallet passphrase",
            "Recover seed",
            "Derivation inputs",
            "Network",
            "Index range",
            "Start",
            "End",
            "Harden final index",
            "Derive addresses",
            "Public results",
            "Index",
            "Path",
            "Address",
            "Public key",
            "Backup Summary",
            "Type",
            "Recovery Rule",
            "Top-Level Fields",
            "Recovered Seed Material",
            "Seed Material",
            "SSKR Shares",
            "Total Shares",
            "Additional Fields",
            "Scroll for more",
        ];

        for language in [
            GuidanceLanguage::SimplifiedChinese,
            GuidanceLanguage::Japanese,
            GuidanceLanguage::Korean,
        ] {
            for copy in workflow_copy {
                assert_ne!(language.text(copy), copy, "missing {language:?}: {copy}");
            }
            for tab in Tab::ALL {
                assert_ne!(tab.title(language), tab.title(GuidanceLanguage::English));
                assert_ne!(
                    tab.subtitle(language),
                    tab.subtitle(GuidanceLanguage::English)
                );
                assert_ne!(
                    tab.nav_label(language),
                    tab.nav_label(GuidanceLanguage::English)
                );
                assert_ne!(
                    tab.nav_hint(language),
                    tab.nav_hint(GuidanceLanguage::English)
                );
                assert_ne!(language.tip(tab), GuidanceLanguage::English.tip(tab));
            }
            assert_ne!(
                MnemonicLanguage::English.localized_label(language),
                MnemonicLanguage::English.label()
            );
        }
    }

    #[test]
    fn stored_sskr_rule_is_localized_for_summary() {
        let value = serde_json::Value::String(
            "Recovery rule: 1 of 2 group(s), 2 of 3 share(s) per group".to_string(),
        );
        let chinese = display_json_value(
            "recovery_info",
            &value,
            true,
            GuidanceLanguage::SimplifiedChinese,
        );
        assert_eq!(chinese, "组门限 1/2 · 组内份额门限 2/3");
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
        assert_eq!(
            backup_kind_label(map, GuidanceLanguage::English),
            "SSKR share backup"
        );
        assert_eq!(
            display_json_value(
                "language",
                &backup_json["language"],
                false,
                GuidanceLanguage::English,
            ),
            "English"
        );
        assert_eq!(
            display_json_value(
                "recovery_info",
                &backup_json["recovery_info"],
                false,
                GuidanceLanguage::English,
            ),
            "SSKR backup"
        );

        let masked_seed = display_json_value(
            "seed_phrase",
            &backup_json["seed_phrase"],
            false,
            GuidanceLanguage::English,
        );
        assert!(masked_seed.contains("<hidden: 12 words>"));
        assert!(!masked_seed.contains("abandon abandon"));

        let share = &backup_json["sskr"]["groups"][0][0];
        let masked_share_hex = display_json_value(
            "share_hex",
            &share["share_hex"],
            false,
            GuidanceLanguage::English,
        );
        assert!(!masked_share_hex.contains("0123456789abcdef"));
        assert_eq!(
            display_json_value(
                "share_hex",
                &share["share_hex"],
                true,
                GuidanceLanguage::English,
            ),
            "0123456789abcdef"
        );

        let summary = BackupSummary::from_json(&backup_json);
        assert_eq!(
            summary.seed_storage_label(GuidanceLanguage::English),
            "Seed storage: mnemonic"
        );
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
        assert_eq!(
            summary.seed_storage_label(GuidanceLanguage::English),
            "Seed storage: SSKR shares"
        );
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

    #[test]
    fn embedded_app_icon_has_transparent_corners() {
        let icon = embedded_app_icon();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
        assert_eq!(icon.rgba[3], 0, "top-left corner must be transparent");
        let center_alpha = ((128 * 256 + 128) * 4) + 3;
        assert_eq!(icon.rgba[center_alpha], 255);
    }

    #[test]
    fn fortress_icon_contains_24_mnemonic_blocks() {
        let svg = include_str!("../assets/bip39-tool-icon.svg");
        assert_eq!(svg.matches("rx=\"11.5\"").count(), 24);
    }
}
