// サブモジュールのインポート
mod build_ebpf;
mod build;
mod run;

use std::process::exit;

use clap::Parser;

/// コマンドライン引数を定義する構造体
#[derive(Debug, Parser)]
pub struct Options {
    /// 実行するサブコマンド
    #[clap(subcommand)]
    command: Command,
}

/// 利用可能なサブコマンドを定義する列挙型
#[derive(Debug, Parser)]
enum Command {
    /// eBPFプログラムのビルド
    BuildEbpf(build_ebpf::Options),
    /// メインプログラムのビルド
    Build(build::Options),
    /// プログラムの実行
    Run(run::Options),
}

/// メインエントリーポイント
fn main() {
    // コマンドライン引数の解析
    let opts = Options::parse();

    // サブコマンドの実行
    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
        Build(opts) => build::build(opts),
    };

    // エラーハンドリング
    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
