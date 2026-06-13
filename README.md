# クラウド環境の基本的なセキュリティ設定が有効になっていることを確認するツール

## 機能

AWSのみ対応

### 標準チェック（全リージョン対象）
- **Security Hub CSPM**: CSPM の有効化・標準数をチェック
- **Security Hub Advanced**: Security Hub Advanced の有効化をチェック
- **Security Hub Add-on (GuardDuty)**: Add-on Capabilities の GuardDuty 項目（基本脅威検出、EC2マルウェア、EKS/S3/Lambda/RDS保護、Runtime Auto Management 3種）を個別判定（Security Hub Advanced が無効な場合は `warn` として underlying service の状態を表示）
- **Security Hub Add-on (Inspector)**: Add-on Capabilities の Inspector 項目（EC2/ECR/Lambda/Lambda Code/Code Security）を個別判定（Security Hub Advanced が無効な場合は `warn` として underlying service の状態を表示）
- **GuardDuty**: 有効化、Findings Export（S3）、保護プラン（S3/EKS/RDS/Lambda/Runtime）、マルウェア保護（EC2/S3）の状態を確認
- **IAM Access Analyzer**: アナライザーの存在確認
- **AWS Config**: レコーダーの有効化・記録状態を確認
- **AWS CloudTrail**: トレイルの有効化・ログ記録状態を確認
- **Inspector**: スキャンの有効化を確認
- **Detective**: 分析グラフの存在確認
- **Macie**: DLP サービスの有効化を確認
- **AWS Backup**: バックアップコンテナの存在確認

### グローバルチェック（最初のリージョンで実行）
- **AWS Shield**: Advanced サブスクリプションの有効化確認
- **AWS Firewall Manager**: 管理アカウントの設定確認
- **Trusted Advisor**: Business/Enterprise Support プランによる有効化確認

## 将来対応予定
- Google Cloudのセキュリティ設定を確認

## ディレクトリ/ファイル構成

```
oreno-sec-posture-checker/
├── cmd/aws/
│   └── main.go              # AWS チェックコマンドエントリーポイント
├── internal/aws/
│   ├── api.go               # AWS SDK クライアントファクトリ
│   ├── checker.go           # チェック実行エンジン（並列: 5）
│   ├── types.go             # CheckResult 型定義
│   ├── config.go            # AWS 設定ロード/リージョン検出
│   ├── securityhub.go       # Security Hub CSPM / Advanced (v2) チェック
│   ├── securityhub_addon.go # Security Hub Add-on Capabilities チェック
│   ├── guardduty.go         # GuardDuty チェック（5項目）
│   ├── iam.go               # IAM Access Analyzer チェック
│   ├── configservice.go     # AWS Config チェック
│   ├── cloudtrail.go        # CloudTrail チェック
│   ├── inspector.go         # Inspector チェック
│   ├── detective.go         # Detective チェック
│   ├── macie.go             # Macie チェック
│   ├── backup.go            # AWS Backup チェック
│   ├── shield.go            # AWS Shield Advanced チェック
│   ├── firewallmanager.go   # Firewall Manager チェック
│   └── trustedadvisor.go    # Trusted Advisor チェック
├── internal/utils/
│   └── render.go            # 結果出力（テーブル/JSON形式）
├── main.go                  # エントリーポイント
├── go.mod
├── go.sum
├── LICENSE                  # AGPLv3 ライセンス
└── README.md
```

## 結果ステータス

- **pass**: チェック項目が有効・構成済み
- **warn**: サービス未使用または推奨される設定が未実装
- **fail**: チェック失敗または重大な設定不備
- **error**: API呼び出しエラーなど

## 使い方

事前にAWS認証情報を設定したうえで、次を実行します。

```bash
oreno-sec-posture-checker [options]
oreno-sec-posture-checker logs [options]
```

- `all` (デフォルト): すべてのチェックを実行
- `logs`: ログ出力設定の確認のみ実行（AWS Config / CloudTrail / GuardDuty Findings Export）

### グローバルオプション

- `-v`: バージョンを表示して終了

### チェック実行オプション

- `-profile`: 利用するAWS profile名
- `-regions`: チェック対象リージョンをカンマ区切りで指定
- `-json`: JSON形式で結果を出力
- `-csv`: CSV形式で結果を出力
- `-progress`: 進捗を標準エラー出力に表示（デフォルト: true）
- `-verbose`: エラー詳細を出力（ERROR 列を表示、デフォルト: false）

並列実行数は固定で 6 です。

例:

```bash
oreno-sec-posture-checker -v
oreno-sec-posture-checker -profile dev
oreno-sec-posture-checker -regions ap-northeast-1,us-east-1
oreno-sec-posture-checker -verbose
oreno-sec-posture-checker logs -regions ap-northeast-1
oreno-sec-posture-checker -json
oreno-sec-posture-checker -csv
oreno-sec-posture-checker -progress=false
oreno-sec-posture-checker logs -regions ap-northeast-1 -verbose
oreno-sec-posture-checker logs -json -verbose
```

`logs` サブコマンドの表示列:

- `SERVICE`
- `REGION`
- `STATUS` (`S3` または `CloudWatch Logs` のどちらかに出力先があれば `pass`)
- `S3` (バケット名)
- `CloudWatch Logs` (ロググループ名)

補足:

- `AWS Config` と `GuardDuty Findings Export` はサービス仕様上 CloudWatch Logs への直接出力機能を持たないため、`CloudWatch Logs` 列は `-` を表示します
- ERROR 列（エラー詳細）はデフォルトで非表示です。表示する場合は `-verbose` フラグを使用してください

## 注釈

- **Shield Advanced/Firewall Manager**: 有料・オプションサービスのため warn ステータスで表示されます
- **Trusted Advisor**: Business/Enterprise Support プラン未契約の場合は warn になります
- **GuardDuty の一部機能**: Protection Plans は S3_DATA_EVENTS / EKS_AUDIT_LOGS / RDS_LOGIN_EVENTS / LAMBDA_NETWORK_LOGS を対象に判定し、Runtime Monitoring は EKS_ADDON_MANAGEMENT / ECS_FARGATE_AGENT_MANAGEMENT / EC2_AGENT_MANAGEMENT を個別判定します。提供されている対象機能がすべて有効なら pass・すべて無効なら fail・一部のみ有効なら warn になります。Malware Protection は EC2 と S3 を別チェックで判定します
- **AWS Backup**: バックアップボールトが存在しない場合は warn になります

## ライセンス

このプロジェクトは [GNU Affero General Public License v3 (AGPLv3)](LICENSE) の下で公開されています。

## バージョン

バージョン情報を表示するには `-v` フラグを使用します：

```bash
oreno-sec-posture-checker -v
```