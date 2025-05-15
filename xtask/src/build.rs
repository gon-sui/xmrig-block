use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuildOptions};

/// ビルドオプションを定義する構造体
#[derive(Debug, Parser)]
pub struct Options {
    /// BPFターゲットのエンディアンを設定
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// リリースビルドを実行
    #[clap(long)]
    pub release: bool,
}

/// ユーザースペースアプリケーションをビルドする関数
fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    // ビルドコマンドの引数を構築
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release")
    }
    
    // cargoコマンドを実行
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

/// eBPFプログラムとユーザースペースアプリケーションをビルドする関数
pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    // まずeBPFプログラムをビルドし、次にアプリケーションをビルド
    build_ebpf(BuildOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}