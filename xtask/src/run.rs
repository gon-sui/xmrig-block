use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{build::{build, Options as BuildOptions}, build_ebpf::Architecture};

/// 実行オプションを定義する構造体
#[derive(Debug, Parser)]
pub struct Options {
    /// BPFターゲットのエンディアンを設定
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// リリースビルドを実行
    #[clap(long)]
    pub release: bool,
    /// アプリケーションを実行するためのラッパーコマンド
    #[clap(short, long, default_value = "sudo -E")]
    pub runner: String,
    /// アプリケーションに渡す引数
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// プロジェクトをビルドして実行する関数
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // eBPFプログラムとプロジェクトをビルド
    build(BuildOptions{
        bpf_target: opts.bpf_target,
        release: opts.release,
    }).context("Error while building project")?;
    
    // ビルドプロファイルの設定（リリースまたはデバッグ）
    let profile = if opts.release { "release" } else { "debug" };
    let bin_path = format!("target/{profile}/xdp-log");

    // アプリケーションに渡す引数を準備
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // 実行コマンドの引数を設定
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // コマンドを実行
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    // 実行結果の確認
    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
