# creel

HTTP forward proxy です。動的に TLS 証明書を発行して MITM Proxy として動作し、
YAML で指定した domain / path / content-type にマッチしたレスポンスボディを、
domain と path の構造を保ったままファイルとして保存します。

## インストール

[Releases](https://github.com/yteraoka/creel/releases) から
Linux / macOS / Windows (amd64, arm64) 向けのビルド済みバイナリを取得できます。

```sh
go install github.com/yteraoka/creel@latest
```

リポジトリから直接ビルドする場合:

```sh
go build -o creel .
```

## 使い方

1. 設定ファイルを用意します。

   ```sh
   cp config.example.yaml creel.yaml
   ```

2. 起動します。初回起動時に CA 証明書が無ければ `$HOME/.config/creel/`
   (`XDG_CONFIG_HOME` が設定されていればその下の `creel/`) に作成されます。

   ```sh
   ./creel -config creel.yaml
   ```

3. CA 証明書をクライアントに信頼させます。パスは `creel -print-ca` で確認できます。

   ```sh
   curl --proxy http://127.0.0.1:8080 --cacert "$(creel -print-ca)" https://example.com/
   ```

   ブラウザや OS の信頼ストアに入れる場合の例:

   ```sh
   # Debian/Ubuntu
   sudo cp "$(creel -print-ca)" /usr/local/share/ca-certificates/creel.crt
   sudo update-ca-certificates
   ```

4. クライアントの HTTP/HTTPS プロキシに `http://127.0.0.1:8080` を設定します。

   ```sh
   export http_proxy=http://127.0.0.1:8080
   export https_proxy=http://127.0.0.1:8080
   ```

## 設定

```yaml
listen: 127.0.0.1:8080      # 待ち受けアドレス
output_dir: captured        # 保存先ディレクトリ
on_exist: overwrite         # 既存ファイルがある場合: overwrite / skip / number
add_extension: false        # Content-Type から拡張子を補うか
max_body_size: 67108864     # 保存のためにバッファするボディの上限 (バイト)
mitm_all: false             # true なら全ホストの TLS を復号する

rules:
  - name: example の API レスポンス
    domain: "**.example.com"
    path: /api/**
    content_type: application/json
```

`rules` は上から順に評価され、最初にマッチしたルールで保存されます。
`domain` / `path` / `content_type` はいずれも省略でき、省略した項目は何にでもマッチします。

| 項目 | マッチ対象 | ワイルドカード |
| --- | --- | --- |
| `domain` | ポートを除いたリクエストホスト (大文字小文字を区別しない) | `*` は 1 ラベル、`**` は 0 個以上のラベル。`*.example.com` は `api.example.com` にマッチし `a.b.example.com` にはマッチしない。`**.example.com` は `example.com` とすべてのサブドメインにマッチ |
| `path` | リクエストパス (大文字小文字を区別する) | `*` は `/` を跨がない、`**` は跨ぐ |
| `content_type` | `charset` などのパラメータを除いたレスポンスの Content-Type | `image/*` のような glob |

### TLS の復号範囲

`mitm_all: false` (デフォルト) では、CONNECT 先のホストが
いずれかのルールの `domain` にマッチする場合だけ TLS を復号します。
マッチしないホストはそのまま素通しするため、証明書ピンニングを行うアプリの
通信を壊しません。すべてのホストを復号したい場合は `mitm_all: true` にします。

## 保存されるファイル

`output_dir/<domain>/<path>` に保存されます。

| リクエスト | 保存先 |
| --- | --- |
| `https://example.com/api/v1/users` | `captured/example.com/api/v1/users` |
| `https://example.com/` | `captured/example.com/index` |
| `https://example.com/dir/` | `captured/example.com/dir/index` |
| `https://example.com/search?q=go` | `captured/example.com/search_61f03144` |

- クエリ文字列があるものは、内容が衝突しないようにパス末尾へクエリのダイジェストを付けます。
- `add_extension: true` にすると、ファイル名に適切な拡張子が無い場合に
  Content-Type から補います。既に合う拡張子があるものはそのままです。

  | リクエスト | Content-Type | `add_extension: true` での保存先 |
  | --- | --- | --- |
  | `https://example.com/api/v1/users` | `application/json` | `captured/example.com/api/v1/users.json` |
  | `https://example.com/` | `text/html` | `captured/example.com/index.html` |
  | `https://example.com/logo.png` | `image/png` | `captured/example.com/logo.png` (変化なし) |
  | `https://example.com/index.php` | `text/html` | `captured/example.com/index.php.html` |
  | `https://example.com/search?q=go` | `application/json` | `captured/example.com/search_61f03144.json` |

- `Content-Encoding: gzip` / `deflate` のレスポンスは復号して保存します
  (クライアントへは元のまま転送します)。`br` や `zstd` は受信したまま保存します。
- `/a` と `/a/b` のようにファイルとディレクトリが衝突する場合は、
  先にあるファイルを消さずに `a` と `a.d/b` のように分けて保存します。
- `max_body_size` を超えるレスポンスはクライアントへ素通しし、保存はしません。

## コマンドラインオプション

| オプション | 説明 |
| --- | --- |
| `-config` | 設定ファイルのパス (デフォルト `creel.yaml`) |
| `-listen` | 待ち受けアドレス (設定ファイルより優先) |
| `-output` | 保存先ディレクトリ (設定ファイルより優先) |
| `-ca-dir` | CA を置くディレクトリ (デフォルト `$HOME/.config/creel`) |
| `-log-level` | `debug` / `info` / `warn` / `error` |
| `-print-ca` | CA 証明書のパスを表示して終了 |
| `-version` | バージョンを表示して終了 |

## 注意

creel の CA を信頼させたクライアントは、creel が発行する任意のホストの証明書を
受け入れるようになります。`ca-key.pem` は他人に渡さないでください。
不要になったら `$HOME/.config/creel/` を削除し、信頼ストアからも取り除いてください。

## ライセンス

MIT License. [LICENSE](LICENSE) を参照してください。
