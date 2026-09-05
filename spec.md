HTTP の forward proxy です。動的に TLS 証明書を発行して MITM Proxy として機能します。
YAML の設定ファイルで domain, path, content-type を指定し、マッチしたレスポンスボディを
domain, path を維持してファイルとして保存します。
起動時に CA の証明書がなければ $HOME/.config/creel/ ディレクトリに作成します。

