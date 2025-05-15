use std::{path::PathBuf, process::Command};

use clap::Parser;

/// eBPFプログラムのアーキテクチャを定義する列挙型
#[derive(Debug, Copy, Clone)]
pub enum Architecture {
    /// リトルエンディアン
    BpfEl,
    /// ビッグエンディアン
    BpfEb,
}

/// 文字列からアーキテクチャへの変換を実装
impl std::str::FromStr for Architecture {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bpfel-unknown-none" => Architecture::BpfEl,
            "bpfeb-unknown-none" => Architecture::BpfEb,
            _ => return Err("invalid target".to_owned()),
        })
    }
}

/// アーキテクチャの文字列表現を実装
impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Architecture::BpfEl => "bpfel-unknown-none",
            Architecture::BpfEb => "bpfeb-unknown-none",
        })
    }
}

/// eBPFビルドオプションを定義する構造体
#[derive(Debug, Parser)]
pub struct Options {
    /// BPFターゲットのエンディアンを設定
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub target: Architecture,
    /// リリースビルドを実行
    #[clap(long)]
    pub release: bool,
}

/// eBPFプログラムをビルドする関数
pub fn build_ebpf(opts: Options) -> Result<(), anyhow::Error> {
    // eBPFプログラムのディレクトリを設定
    let dir = PathBuf::from("xdp-log-ebpf");
    let target = format!("--target={}", opts.target);
    
    // ビルドコマンドの引数を構築
    let mut args = vec![
        "build",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    if opts.release {
        args.push("--release")
    }

    // 注意: Command::newは子プロセスを作成し、すべての環境変数を継承します。
    // これにより、cargo xtaskコマンドで設定された環境変数も継承されます。
    // RUSTUP_TOOLCHAINを削除して、-ebpfフォルダ内のrust-toolchain.tomlファイルを尊重します。

    // cargoコマンドを実行
    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
