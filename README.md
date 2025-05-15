# XDPを使用したxmrig通信ブロッカー

このプロジェクトは、eBPFとXDP（eXpress Data Path）を使用して、xmrigとの通信を検出し、ブロックするためのツールです。

## 機能

- マイニングプールの一般的なポート（3333, 14444, 14433）への通信を検出
- 検出されたマイニング通信のパケットを自動的にドロップ
- 通信の詳細（送信元ポート、宛先ポート、パケットサイズ）をログに記録

## 技術的な詳細

このプロジェクトは以下の技術を使用しています：

- Rust言語
- eBPF（Extended Berkeley Packet Filter）
- XDP（eXpress Data Path）
- aya-ebpfフレームワーク

## 必要条件

- Linux カーネル 4.9以上
- Rust ツールチェーン
- LLVM/Clang
- libbpf

## ビルド方法

```bash
cargo build --release
```

## 使用方法

1. プログラムをビルド
```bash
cargo build --release
```

2. 管理者権限で実行
```bash
sudo ./target/release/xdp-log
```

3. 指定されたネットワークインターフェースにXDPプログラムをアタッチ
```bash
# インターフェース名を指定して実行
sudo ./target/release/xdp-log -i eth0

# デバッグログを有効にして実行
sudo RUST_LOG=debug ./target/release/xdp-log -i eth0
```

4. プログラムの停止
```bash
# Ctrl+Cでプログラムを停止
# または
sudo killall xdp-log
```

## 注意事項

- このプログラムは管理者権限（root）で実行する必要があります
- ネットワークインターフェースの設定によっては、XDPの動作モードが制限される場合があります
