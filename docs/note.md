# Leveret 読書会のハンズオン記録

## 全般

### 書籍・リポジトリリンク
- 書籍: [Goで作るセキュリティ分析LLMエージェント](https://zenn.dev/mizutani/books/sec-agent-book) by Masayoshi MIZUTANI
- 原リポジトリ: [m-mizutani/leveret](https://github.com/m-mizutani/leveret)
- 自分のリポジトリ: [mikkegt/leveret](https://github.com/mikkegt/leveret)
- 読書会: [Women Who Go Tokyo](https://womenwhogo-tokyo.connpass.com/)
- トラッキングIssue: [mikkegt/Jarvis#76](https://github.com/mikkegt/Jarvis/issues/76)

## 第1章 はじめに

この章で印象的なのは、著者が長年決定性アプローチで戦ってきた末に LLM を選んでいる点。LLM 流行ってるから使うではなく従来手法では届かない領域があるという確信に基づく判断。

注目したいのは「ルールの大量メンテが投資対効果を圧迫した」という指摘。これは SIEM/SOAR の世界で実際に起きていた問題で、決定性アプローチの限界。

```
脅威の種類・新パターン増加 → ルールも増える
        ↓
ルール書く工数 + メンテ工数 が爆発
        ↓
新ルール書くより、誤検知（false positive）対応に追われる
        ↓
自動化のROIが下がる
```

#### leveret アーキテクチャを先取りすると

このリポジトリの `CLAUDE.md` には以下の明記がある:

```
Use LLM for:
- Alert summarization and title generation
- IOC extraction
- Interactive analysis
...

Do NOT use LLM for:
- Deterministic filtering (use OPA/Rego policies instead)
- Regular expression-based pattern matching
- Simple threshold checks
```

つまり leveret は:
- 決定性が必要な処理 → OPA/Rego（ポリシー言語）
- 確率実行で良い処理 → Gemini（サマリー生成、対話分析）

この使い分けは著者の長年の苦労から出てきた設計判断で、章を読み進めるとなぜこの境界線を引いたかが見えてくるはず。

「現代においてLLMエージェントを自作するのは必ずしも正解ではありません」という一文は重要。SaaS で十分なケースは多い。

自作する価値:
- ドメイン特化（セキュリティのように特殊な業務知識が必要）
- データ機密性（ログを外部に出せない）
- 既存ワークフロー深掘り（社内ツールと密接統合）

---

### OPA/Rego とは

**OPA** = Open Policy Agent。CNCF（Cloud Native Computing Foundation）の汎用ポリシーエンジン。
**Rego** = OPA で書くための宣言型 DSL。

Yes/No 判定をするためのルール集を、アプリのコードから切り離して別ファイルに書ける仕組み。

よくある使いどころ:

| 領域 | 何を判定するか |
|---|---|
| Kubernetes | 「このPodデプロイを許可する？」（admission control） |
| API Gateway | 「このユーザーはこのエンドポイントにアクセス可？」 |
| マイクロサービス認可 | 「この操作はこのロールに許可されてる？」 |
| Infrastructure as Code | 「このTerraform設定はセキュリティ要件を満たす？」 |
| **leveret** | **「このアラートは分析する価値ある？それともノイズ？」** |

#### Rego のコード例（イメージ）

```rego
package alert

# デフォルトは「分析対象として受け付ける」
default allow = true

# 既知のノイズ源からのアラートは拒否
allow = false {
    input.source_ip == "10.0.0.1"
}

# 重要度が低すぎる場合も拒否
allow = false {
    input.severity == "informational"
}
```

`input` には JSON で渡されるアラートデータが入る。レポンスは `allow: true/false`。

#### なぜ Go のコードで `if-else` を書かないのか

これが核心の疑問。同じことできるなら別言語入れる意味は？

| 観点 | Go の if-else | OPA/Rego |
|---|---|---|
| ルール変更時 | コード書き換え → 再ビルド・再デプロイ | ポリシーファイルだけ差し替え（**hot reload 可**） |
| 監査 | コードベース全体から探す必要 | ポリシーファイルだけ見れば良い |
| テスト | Goのテストフレームワーク | OPA 専用の policy test ツール |
| 他システムとの共通化 | 不可（Go依存） | k8s でも API GW でも同じ Rego が使い回せる |

セキュリティの世界では「誰がいつどんなルールを変えたか」の追跡が重要なので、ルールをデータ（ポリシーファイル）として扱える仕組みが効く。

#### TS/Java/C# のアナロジー

- **Drools (Java)** — ルールエンジンの老舗。「ファクト」を投入すると「ルール」が発火する。Rego の親戚。
- **JSON Schema** — 検証ルールを宣言的に書く、という発想は近い。ただし JSON Schema は「データの形」を検証するもので、Rego は「データから判断」する点が違う。
- **AWS IAM ポリシー** — JSON で `Effect: Allow / Deny` 書くやつ。あれをもっと汎用化・プログラマブルにしたのが Rego。

#### leveret での位置づけ

CLAUDE.md の Alert Lifecycle に書いてある:

```
new → Policy Check → LLM Summary → Unanalyzed
```

`Policy Check` が OPA。LLM を呼ぶ前にノイズを弾く役割。

なぜ重要か:
- LLM API は お金がかかる（トークン課金）
- LLM は 遅い（数秒〜数十秒）
- どう見てもノイズなアラートに LLM 使うのは無駄

決定的に判定できるものは決定的に。曖昧なものだけ LLM に投げる。これが第1章で語られた「決定性アプローチ vs LLM」の使い分けの実装。

#### 補足: Rego の独特さ

Rego は Datalog 系の宣言型なので、Go や TS の手続き型に慣れてると最初すごく違和感がある。「ルールは true になる条件を書く」発想。

```rego
# これは「allow を false にする条件」
allow = false {
    input.severity == "informational"
}
```

「変数 allow に false を代入する」じゃなくて「`{}` の中の条件が全て成立する時、allow は false になる」と読む。Prolog の親戚と思うと納得しやすい。

---

### SIEM/SOAR とは

セキュリティ業界の2大ツールカテゴリ。

**SIEM** = Security Information and Event Management
システム全部のログを集めて、検知ルールで自動アラートを出す集中監視所。

- 入力: サーバー・ネットワーク機器・クラウド・アプリのログを全部集める
- 処理: 正規化 → 相関分析 → 検知ルールにマッチしたらアラート
- 出力: セキュリティアナリストに「これ調べて」と通知
- 製品例: Splunk（業界標準）、IBM QRadar、ArcSight、Elastic SIEM、Microsoft Sentinel、Datadog Security

**SOAR** = Security Orchestration, Automation and Response
SIEM が出したアラートを受けて、調査と対応を自動化するワークフローエンジン。

- 入力: SIEM からのアラート
- 処理: プレイブック（手順書）に従って自動調査・対応
- 例: 「IPブロックして Slack 通知してチケット作成」を自動実行
- 製品例: Palo Alto XSOAR（旧 Demisto）、Splunk Phantom、IBM Resilient

#### 全体の流れ

```
ログ → SIEM（検知）→ アラート → SOAR（自動対応）→ 必要なら人間にエスカレーション
```

#### C/C++/TS/Go のアナロジー

| レイヤー | プリミティブな実装 | エンタープライズ製品 |
|---|---|---|
| ログ集約 | `syslog-ng`、`tail -f \| grep`、C で fread+正規表現 | Splunk のインデックスサーバ |
| 検知 | C/Go の cron スクリプトで grep | SIEM の相関ルールエンジン |
| 対応 | Bash で `iptables -A` | SOAR のプレイブック |
| 監視UI | tail を tmux で眺める | SIEM のダッシュボード |

DevOps の Datadog / New Relic / Sentry に近いが、セキュリティ専用で「攻撃検知」「フォレンジック」に最適化されている。

C++ で言えば、`std::ifstream` でログ読んで `std::regex` でマッチして `std::cout` に流すような処理を、全社規模で・全ホストから・リアルタイムでやる巨大プラットフォーム。

#### なぜ第1章の文脈で重要か

著者が「ルールの大量メンテが投資対効果を圧迫した」と言っているのはまさに SIEM ルールの世界の話。

- 新しい攻撃パターン出る → 検知ルール追加
- 誤検知が出る → ルールチューニング
- ログフォーマット変わる → 全ルール影響受ける
- ルール数が数千〜数万に膨れ上がる → 誰が管理するの問題

この負担に押し潰されたエンジニアたちが「LLM で楽になりたい」と思うのは自然な流れ。

leveret は SIEM の後ろに付くツール。

```
ログ → SIEM → アラート → leveret（LLM で分析サポート）→ アナリスト
```

つまり leveret は「**SOAR の LLM 版**」のようなポジション。アラート受け取って分析を支援する。第1章の「分析プロセスの自動化」がこの位置づけ。

## 第2章 セキュリティアラート分析とLLMエージェント

### セキュリティアラートの守備範囲

アラートはアンチウィルス・IDS・EDR・ファイアウォール等の検知だけではない。

- 新しい脆弱性情報（CVE 公開など）
- 3rd party パッケージのサプライチェーン攻撃
- 内部システムの設定不備
- セキュリティ上の問題がありそうな通知全般

→ 守備範囲が広いほどルールで全部押さえるのが困難。第1章の「決定性アプローチの限界」とつながる。

### 担当者の3大負荷タスク

| タスク | 内容 |
|---|---|
| 初期分析 | このアラートは無視してよいか、影響があるかの調査 |
| 発報調整 | 無視してよいものを弾くためのルールチューニング |
| 結果整理 | 大量アラートから影響あるものを洗い出す triage |

leveret が支援するのは主に 初期分析 と 結果整理。

### 用語の整理

| 用語 | 範囲 |
|---|---|
| 生成AI | テキスト・画像・音声などコンテンツ生成 AI 全般（Stable Diffusion 等も含む） |
| LLM | 生成AIの一種、テキスト特化（ChatGPT、Claude、Gemini） |
| LLMエージェント | LLM を中核に、自律的に行動するシステム |

#### LLMエージェントの3要素

1. ツール呼び出し — 外部 API・DB を自ら選んで実行
2. 計画と実行 — 複雑なタスクをステップ分解して順序実行
3. 状態管理 — 過去の会話や結果を記憶して文脈考慮

→ 単なる対話 LLM との違いはこの3点。leveret もこの構造で作る。

### 本書の実装方針

- **LangChain / LangGraph を使わない**。Go で LLM サービスの API のみ使ってフルスクラッチ

#### なぜフルスクラッチ？

明示的には書かれてないが推測:
- LangChain は変化が激しく、薄いラッパーがすぐ陳腐化
- ある特定ドメイン（セキュリティ）に特化するなら、抽象レイヤーは自分で持つほうが拡張性が高い
- Go の型システムでドメインモデルを表現したい
- 学習目的では中身を全部見える状態にしたい

C/C++ の世界で言えば、ライブラリ依存を減らして自前で実装する流派と近い感覚。CG 系の人が「DirectX 使わず OpenGL も使わず描画ループを自分で書く」みたいな志向。

### 先取りキーワード（後の章で詳述される）

- **Lost in the middle**: 長い履歴の中央部分が LLM に無視される現象
- **Recency Bias**: 直近の履歴に過度に影響される偏り
- **RAG** (Retrieval-Augmented Generation): 検索した情報を生成に活用するパターン
- **MCP** (Model Context Protocol): ツール接続を標準化するプロトコル
- **AlienVault OTX**: 脅威インテリジェンス（IoC 評価）の公開 API
- **AIワークフロー** vs **Plan & Execute**: 決定性と柔軟性のバランスを取る2つのパターン

---

### IoC とは

**IoC** = Indicator of Compromise（侵害指標、侵害の痕跡）

「攻撃や侵害があったことを示す具体的なデータ片」のこと。アラートの本文や検知ログの中に埋め込まれている。

#### よく使われる IoC の種類

| 種類 | 例 |
|---|---|
| IP アドレス | C&C サーバの送信元 `185.220.101.42` |
| ドメイン名 | フィッシングサイト `evil-bank.example.com` |
| URL | マルウェア配布 `http://bad.example.com/payload.exe` |
| ファイルハッシュ | マルウェア検体の SHA256 `3a7bd3...` |
| メールアドレス | フィッシング送信元 `attacker@example.com` |
| ユーザーエージェント | 攻撃ツール特有の文字列 `sqlmap/1.5` |
| レジストリキー | Windows 永続化用のキーパス |
| 証明書フィンガープリント | 怪しい SSL 証明書の指紋 |

#### 何に使うか

- 脅威インテリジェンスフィードとの照合 — VirusTotal、AlienVault OTX 等に問い合わせて「これ既知の悪性？」を確認
- 過去ログ検索 — 「この IP がうちに来てた？」と SIEM で hunting
- ブロックリスト追加 — ファイアウォール・WAF・DNS フィルタに追加

#### leveret での扱い

leveret の `Alert` モデルに `Attributes` フィールドがある:

```go
type Attribute struct {
    Key   string
    Value string
    Type  AttributeType  // string, number, ip_address, etc.
}
```

第7章「構造化データ出力で IoC など属性値を抽出する」で、LLM にアラート JSON を読ませて IoC を `Attributes` として抜き出す処理を実装するはず？

#### C/C++/プログラミング的アナロジー

- ハッシュ値による識別に近い感覚 — `sha256(malware.exe)` のように、攻撃対象を一意に指す ID
- ブロックリストを作る時の要素 — `iptables -A INPUT -s <IP> -j DROP` の `<IP>` 部分が IoC
- C++ の例えで言えば、`std::unordered_set<std::string> known_bad_ips;` の中身が IoC のリスト。アラートが来たら `if (known_bad_ips.count(ip))` で照合する、その照合対象データ

#### 用語のニュアンス

- 表記: 「IoC」「IOC」両方使われる（書籍では「IoC」）
- 関連語: **IoA** (Indicator of Attack、攻撃手法の指標、TTPs に近い)、**TTPs** (Tactics, Techniques, Procedures、攻撃者の振る舞いパターン)
- IoC は「過去の痕跡」寄り、IoA / TTPs は「攻撃の手口」寄り、というニュアンス差

---

### IDS / EDR とは

セキュリティ監視ツールの代表格。アラートを発報する側のシステム。

**IDS** = Intrusion Detection System（侵入検知システム）
- ネットワーク（NIDS）またはホスト（HIDS）を監視して攻撃を検知
- 検知のみ（ブロックはしない）
- 製品例: Snort、Suricata、Zeek

近い概念: **IPS** (Intrusion Prevention System) = IDS + 自動ブロック。

**EDR** = Endpoint Detection and Response
- PC・サーバー等のエンドポイントに常駐するエージェント
- プロセス挙動・ファイル操作・レジストリ等を記録、挙動分析で検知
- AV (アンチウィルス) の進化形、検知 + 自動隔離・調査もできる
- 製品例: CrowdStrike Falcon、SentinelOne、Microsoft Defender for Endpoint

#### 並べると

| | 監視対象 | 検知方法 | 応答 |
|---|---|---|---|
| AV | エンドポイント | シグネチャ | ファイル削除 |
| IDS | ネットワーク or ホスト | パケット解析、シグネチャ、異常検知 | 検知のみ |
| IPS | ネットワーク | IDS + ブロック | 自動ブロック |
| EDR | エンドポイント | 挙動分析、テレメトリ | 検知 + 自動隔離・調査 |
| XDR | エンドポイント + ネットワーク + クラウド + メール | EDR の統合・拡張 | 統合的応答 |
| NDR | ネットワーク | 挙動分析、フロー分析 | 検知 + 応答 |

#### C/C++ アナロジー

- IDS = `tcpdump | grep "悪意パターン"` を24時間自動で回す装置
- EDR = `auditd` + `inotify` + `ptrace` 相当をホスト常駐させて全イベント記録する Linux サービスのイメージ

#### leveret との関係

leveret は IDS/EDR が出したアラート（JSON）を入力として受け取る側。第1章で出てきた AWS GuardDuty も同系統で、`examples/alert/` の GuardDuty サンプル JSON はこの種のシステムからの入力例。

```
EDR / IDS → アラート JSON → leveret（LLM で分析サポート）→ アナリスト
```

## 第3章 セキュリティアラートの分析業務における課題とLLMによる改善の可能性

読み物の章なので要点だけ。

### この章は

- アラート分析の課題は **量** + **複雑さ** + **専門知識の不足**
- 「Alert Fatigue」: SOC アナリストでもアラートの14%しか処理できていない (Palo Alto 調査)
- SOAR は2018年頃に登場、2024年 Gartner Hype Cycle で「幻滅期」入り → "SOAR is dead" とまで言われる
- SOAR の限界: 厳密なワークフロー定義のメンテコスト、動的判断ができない
- LLM が解決しうるもの:
  - 柔軟なデータ収集（Function Calling で必要なツールを動的選択）
  - 大量データの要約・解説
  - 自然言語での指示
  - コンテキストエンジニアリングで組織固有の文脈を与えられる
- LLM が苦手なもの:
  - 大規模データ分析（コンテキストウィンドウの制約、統計的処理は苦手）
  - 最終的な影響度判断（人間が判断すべき）

---

### CheckPoint / CrowdStrike は SOAR か？

正確には**違う**。これらは SOAR 専業ではなく、本業は別。

| 会社 | 主力製品 | SOAR との関係 |
|---|---|---|
| CheckPoint | ファイアウォール、IPS、Sandbox 等の防御製品スイート | Infinity SOC など SOAR 寄りの機能もあるが副次的 |
| CrowdStrike | Falcon (EDR/XDR の代表格) | Falcon Fusion で SOAR 機能を提供。主力は EDR |

SOAR の代表的な専業（または専業発祥）ベンダー:
- **Palo Alto XSOAR** — 元 Demisto を買収
- **Splunk Phantom** — 元 Phantom を買収（その後 Cisco が Splunk を買収）
- **IBM Resilient** — 元 Resilient Systems を買収
- **Tines、Torq** — モダンな新興 SOAR

つまり「SOAR は EDR/SIEM ベンダーが買収・統合した機能」になっているケースが多い。CrowdStrike も同じ流れ。

### プラトー期とは

**Gartner Hype Cycle** の5段階の最終フェーズ。

```
1. Innovation Trigger（黎明期）
2. Peak of Inflated Expectations（過度な期待のピーク）
3. Trough of Disillusionment（幻滅期）← 本文で SOAR がここに位置づけられた
4. Slope of Enlightenment（啓発期）
5. Plateau of Productivity（プラトー期、生産性の安定期）
```

プラトー期 = 技術が成熟して実用的に使われるようになるフェーズ。本文の「**プラトー期を迎える前に時代遅れになる**」= 成熟する前に陳腐化、という意味。

### MITRE ATT&CK フレームワーク

- MITRE = 米国の非営利研究機関（CVE データベースも管理）
- ATT&CK = Adversarial Tactics, Techniques, and Common Knowledge

攻撃者の **Tactics（戦術）** と **Techniques（技術）** を体系的に整理した知識体系。セキュリティ業界の共通言語。

#### 構造

14個の Tactics（攻撃の段階）× 各々の Techniques のマトリクス:

| Tactic（戦術） | 意味 |
|---|---|
| Initial Access | 初期侵入 |
| Execution | 実行 |
| Persistence | 永続化 |
| Privilege Escalation | 権限昇格 |
| Defense Evasion | 防御回避 |
| Credential Access | 認証情報窃取 |
| Discovery | 偵察 |
| Lateral Movement | 横展開 |
| Collection | 収集 |
| Command and Control | C2 通信 |
| Exfiltration | データ持ち出し |
| Impact | 破壊的影響 |
| 他に Reconnaissance、Resource Development |  |

各 Tactic の下に Techniques が紐づく。例: `T1059.001` = PowerShell の悪用（Execution カテゴリの一技術）。

#### 何に使うか

- 検知ルール開発: 「うちの監視は ATT&CK のどこをカバーしている？」
- 脅威モデリング: 攻撃シナリオの整理
- レッドチーム演習: 攻撃側が ATT&CK のどの Technique を使ったか記録
- 共通言語: 「これは T1486（Data Encrypted for Impact、ランサムウェア）」と一言で伝わる

本文で「近年のLLMには MITRE ATT&CK のような一般的なセキュリティ知識が組み込まれている」とあるのは、**LLMの学習データに ATT&CK の公開情報が含まれているので、`T1059.001` と言えば LLM が理解できる**ということ。これがセキュリティ専門家不在の組織でも LLM が役立つ理由の一つ。

## 第4章 システムアーキテクチャと設計方針

実装時の迷子防止用に、ここはコンポーネント分割を中心にまとめる。「今どこをやっている？」と思った時はこのセクションに戻る。

### この章は

- CLI 中心で実装（学習・テスト・自動化の容易さ）
- LLM = Google Gemini 一本（対話、ツール呼び出し、Embedding 全部）
- レイヤードアーキテクチャで責務分離 + DI
- LLM とルールベース（OPA/Rego）を**適材適所で組み合わせる**

### コンポーネント分割（実装中の参照軸）

依存方向: 上から下のみ（下位層は上位層を知らない）

```
CLI ( pkg/cli )
  ↓ depends on
UseCase ( pkg/usecase )
  ↓ depends on (interface only)
Repository ( pkg/repository ) / Adapter ( pkg/adapter )
                    ↓
                Model ( pkg/model )
```

| 層 | パッケージ | 役割 | 何を置く |
|---|---|---|---|
| フレームワーク層 | `pkg/cli` | CLI 解釈、レポジトリ/アダプターのセットアップ、設定読込、環境変数読込 | コマンド定義、フラグ、DIセットアップ |
| ユースケース層 | `pkg/usecase` | アプリのメインロジック、レポジトリ/アダプターを複合利用 | 各サブコマンドのロジック、Repository/Adapter のインターフェース定義 |
| レポジトリ層 | `pkg/repository` | データ永続化（Firestore） | Alert 保存・検索、ベクトル検索 |
| アダプター層 | `pkg/adapter` | 外部サービス接続抽象化 | Gemini クライアント、Cloud Storage（会話履歴） |
| モデル層 | `pkg/model` | 全体共通の構造体 | Alert、Attribute、AlertID 等 |

ルール:
- 環境変数読込は `pkg/cli` のみ
- インターフェースは UseCase 層で定義（依存性逆転）
- Repository / Adapter は UseCase が定義したインターフェースを実装
- ポリシー（Rego）は LLM 判定とは別系統で持つ。フィルタリング、分類、自動アクションを決定的に処理。
詳細は第13章以降。

### 適材適所の使い分け

**LLM を使う**:
- アラートの要約生成
- IoC 抽出
- 対話的分析
- ログクエリ生成
- 状況に応じたツール選択

**LLM を使わない（ルールベース・OPA/Rego）**:
- ホワイトリスト / ブラックリスト判定
- 正規表現で済むパターンマッチング
- 単純な閾値判定
- 大量データの一括処理
- 最終的な影響度判定（人間が判断）

## 第5章 開発環境の準備と事前実装済みコードの説明

- [x] エディタ（GoLand）
- [x] go version go1.26.0 darwin/arm64
- [x] clone
- [x] GCP
  - [x] プロジェクト作成
  - [x] Firestore 有効化
  - [x] DB作成
  - [x] Cloud Storage 有効化
  - [x] バケット作成
  - [x] Vertex AI (Gemini) 有効化
  - [x] gcloudツールのインストールとADCの認証
  - [x] Budget and Alertsの設定

### ベースコードのレイヤー構成と「配線」

init ブランチには事前実装済みのベースコードが入っていて、3章のレイヤードアーキテクチャ（CLI → UseCase → Repository/Adapter の一方向）がそのまま形になっている。`new` コマンドで main から Firestore 保存まで追うと役割分担が見える。

- main.go: `cli.Run(ctx, os.Args)` を呼ぶだけ。配線はしない
- pkg/cli/cli.go: `cli.Command` を組み立て、サブコマンド（newCommand() 等）を登録して `cmd.Run()`。あとは urfave/cli ライブラリが argv を見て該当コマンドの Action を呼ぶ
- pkg/cli/new.go の Action: ここが配線の本体
- pkg/usecase/alert: ビジネスロジック（受け取った依存を使うだけ）

配線の正体は new.go のこの流れ。部品を作る人（CLI層）と使う人（UseCase）が分離している。

```go
repo, _   := cfg.newRepository()     // 部品A（repository.Repository 型）
gemini, _ := cfg.newGemini(ctx)      // 部品B（adapter.Gemini 型）
uc := alert.New(repo, gemini)        // ← この引数渡しが「依存性注入＝配線」
uc.Insert(ctx, alertData)            // uc は u.repo を使うだけ。誰が作ったか知らない
```

`alert.New()` は受け取った repo/gemini を構造体フィールドに保管するだけ。`Insert()` の中には Firestore も cfg も firestoreProject も出てこない。「挿さっているものを使うだけ」というのが、コンストラクタインジェクションそのもの。C++ で言えば new.go が FirestoreRepo を new して、UseCase に基底ポインタ（Repository*）として渡し、UseCase はメンバに保持して使う、の構図。

設定は CLI 層の `config struct`（config.go）に集約。`globalFlags(cfg)` がフラグの `Destination` に `&cfg.firestoreProject` のようにフィールドのアドレスを結びつけ、パース時にそこへ書き込まれる（boost::program_options の `po::value(&var)` に近い）。`func (cfg *config) newRepository()` のように config 自身が部品を作るメソッドを持つので、各コマンドの Action は `cfg.newRepository()` を呼ぶだけで済む。

### 同じパッケージ＝同じディレクトリ

Go は「ディレクトリ＝パッケージ」。pkg/cli/ の中の cli.go / new.go / config.go … は別ファイルでもコンパイラから見れば1つの `cli` パッケージ。だから cli.go から new.go の `newCommand`（小文字＝非公開）を修飾なしでそのまま呼べるし、定義ジャンプも効く。逆に別パッケージのものは `alert.New()` のようにパッケージ名で修飾し、かつ大文字始まり（公開）でないと見えない。

読むときの勘どころ: 修飾が付いていない（`newCommand`, `Run`）＝同じパッケージ。`cli.Command` のように修飾が付く＝import した外部パッケージ。urfave/cli のパッケージ名がたまたま `cli` で、このファイルも `package cli` なので紛らわしいが、自分のパッケージのものは修飾なしで書くルールなので衝突しない。

### インターフェースの腑落ちメモ（C++ のアナロジー）

本物の interface はこのコードでは `cli.Flag` / `repository.Repository` / `adapter.Gemini`。urfave/cli の実物はこうなっていた（flag.go:104）。

```go
type Flag interface {
    fmt.Stringer                 // String() string
    Apply(*flag.FlagSet) error
    Names() []string
    IsSet() bool
}
```

これは「この4メソッドを全部持つ型は Flag を名乗ってよい」という募集要項。`StringFlag` も `BoolFlag` も4つ揃えているので、`[]cli.Flag` に別々の型を同居させられる。

C++ との対応で整理:

- interface ＝ 抽象基底クラスの「純粋仮想関数だけ・データなし」の極限版。C++ には専用キーワードがないので「純粋仮想だけの abstract class」で書くもの。Java/C# の `interface` と同じ立ち位置
- `[]cli.Flag{ &StringFlag{}, &BoolFlag{} }` は、C++ の `vector<Flag*>{ new StringFlag, new BoolFlag }` と同じでアップキャスト相当。実行時にどのメソッドが動くかは中身の本当の型で決まる（仮想関数テーブルと同じ）
- 決定的な違い: Go は継承を宣言しない。StringFlag はコード中に `Flag` の文字を一度も書かないのに、必要なメソッドが揃っているだけで自動的に Flag として通用する（構造的型付け＝ダックタイピング）。C++/Java は `: public Flag` / `implements Flag` と血縁を宣言して初めて仲間になれる（名前的型付け）

なぜ嬉しいか（一番具体的な姿）: 使う側はこう書ける。

```go
for _, f := range cmd.Flags {  // f は Flag。中身が String か Bool か気にしない
    f.Apply(flagSet)           // 約束されたメソッドだけ呼ぶ
}
```

interface がなければ `if *StringFlag {...} else if *BoolFlag {...}` の分岐が型の数だけ伸びる。interface があると、新しいフラグ型を足してもこのループは1文字も変えなくていい。「使う側が相手の具体型を知らずに、約束されたメソッドだけ呼べる」のが疎結合のうまみ。urfave/cli の作者と無関係に自作した型でも、`Apply`/`Names`/`IsSet`/`String` を実装すれば後付けで `[]cli.Flag` に混ざる。

つまずきログ: ここはまだ7割理解で先に進んだ。実際にコードを書く章（要約生成で Repository をモックに差し替える等）に来たら、「implements を書いていないのに繋がる」を実物で確認すると残りが埋まるはず。

補足: `cli.Flag` は標準ライブラリの `flag` パッケージとは別物。ただし `Apply(*flag.FlagSet)` の `flag.FlagSet` が標準の `flag` なので、urfave/cli は内部で標準 flag の上に作られている、という間接的な関係はある。

## 第6章 LLM利用の基礎とアラートの説明文の作成

この章でいいたいこと：
- LLM は確率的に動くものとして、出力を検証する
- 失敗に対処する仕組みづくりが大事

C++ のアナロジーで言うと、戻り値が必ず正しい関数ではなく、たまに失敗する I/O やネットワーク呼び出しに近い。read() が期待したバイト数を返さないことがあるのと同じ感覚で、LLM の戻り値も「検証してリトライする」前提で扱う、という話。

### 実装の流れ（基礎版）

`pkg/usecase/alert/insert.go` に `generateTitle` / `generateDescription` を追加して、`Insert` の段取りに挟み込んだ。Insert は「alert を作る → data を json.Marshal で文字列化 → タイトル・要約を生成（u.gemini に委譲）→ repo.PutAlert で保存」という順。gemini は第5章でやった DI（New() でのコンストラクタ注入）で既に入っているので、Insert からは u.gemini を渡すだけ。

generateTitle 自体は gemini_test.go で書いた GenerateContent 呼び出しとほぼ同じ構造。違いは「引数を具象 *GeminiClient でなく interface の adapter.Gemini で受ける（テストでモック差し替え可能にするため）」「resp から strings.TrimSpace でテキストを取り出して返す」。

実行は `zenv -- go run . new -i examples/alert/guardduty.json`。`Alert created: <id>` が出たら、Insert の中の Gemini 呼び出し2回も PutAlert も全部成功している証拠（途中で失敗したら return nil, err で抜けて created は出ない）。`zenv -- go run . show -i <id>` で中身を確認でき、Title と Description が日本語で入っていた。

### 観察1: LLM の抽出も元データも鵜呑みにできない

GuardDuty サンプルの finding を見ると、`Title` フィールドは「...EC2 instance **i-99999999**」、`InstanceDetails.InstanceId` は「**i-11111111**」で、元データ自体が食い違っている。生成された Description は i-11111111 を採用していた（InstanceId フィールドの方を拾った）。

教訓: 元データが矛盾していることもあるし、LLM がそのどちらを拾うかは制御できない。だから自由形式テキスト（タイトル・要約）はこれでいいが、IOC など「正確さが要る属性値」は別扱いが必要。次章（第7章）で構造化出力として抽出する、という流れにつながる。

### 観察2: 文字数制限は「バイト数」で効く（Go の len()）

プロンプトには「100文字未満」と日本語で書いたが、発展版で入れる検証 `len(title) <= maxLength` の `len()` は **文字数ではなくバイト数** を返す。日本語は UTF-8 で1文字≈3バイトなので、「100文字」のつもりでも約33文字でバイト上限に達する。本文でも「バイト数でカウントされる場合がある」と注意されている箇所。

つまり「LLM への指示（文字数）」と「コード側の検証（バイト数）」の単位がズレている。文字数で測りたいなら：

```go
import "unicode/utf8"

utf8.RuneCountInString(title) // ルーン（文字）数を数える
len([]rune(title))            // 同じ。[]rune に変換すると要素数=文字数
```

`len(title)` はバイト数、`utf8.RuneCountInString(title)` は文字数。C++ で言えば `std::string::size()`（バイト/コードユニット数）と、実際の文字数が UTF-8 だと一致しないのと同じ話。発展版のリトライ機構で `maxLength` と比べるとき、どちらの単位で揃えるか意識する。

### 発展版: リトライ機構とプロンプトの外部ファイル化

基礎版は「失敗したら即エラー」だったのを、実用的にするために2つ足す。リトライと、プロンプトのテンプレート管理。

#### リトライ機構（失敗情報を次のリクエストに積む）

肝は「失敗をただ繰り返すのではなく、前回の失敗内容を次のプロンプトに添える」こと。100文字に収まらなかったら、その title と文字数を `failedExamples` に append しておき、次のループでテンプレートの `{{range .FailedExamples}}` がそれを「前回は長すぎた」と描画する。LLM は「じゃあ短くしよう」と修正しやすくなる。初回は `failedExamples` が空なので `{{if .FailedExamples}}` ブロックごと出ない。最大3回試してダメなら error を返す。

このパターン（失敗を次の入力にフィードバックして成功率を上げる）は、後の Function Calling や Plan-Execute でも共通で使えると本文が言っている。

#### //go:embed でプロンプトを外部ファイル化

プロンプトを Go の文字列リテラルで持つとエディタ補助（ハイライト・整形）が効かないので、`prompt/title.md` に出して `//go:embed` でビルド時にバイナリへ焼き込む。

```go
//go:embed prompt/title.md
var titlePromptRaw string
```

- `//go:embed` コメントは変数宣言の直前に密着させる（間に空行 NG）。
- パスは .go ファイルからの相対。ファイルが無いとビルド失敗（`pattern prompt/title.md: no matching files found`）。実行時エラーじゃなくコンパイル時に気づけるのが利点。
- title.md を書き換えたら `go run`（再ビルド）で反映される。
- アナロジー: C++ の `#embed`（C23）や `xxd -i` でファイルをバイナリに同梱するのと同じ。Java の resources をコンパイル時に焼き込む版。

#### text/template の要点

- `{{.MaxLength}}` … Execute に渡したデータの値を差し込む。`.` は「今のデータ」。
- `{{if}}` `{{range}}` … 条件分岐とループ。Handlebars/Mustache の親戚。
- `{{-` `-}}` … その側の空白・改行を削る（出力が空行だらけになるのを防ぐ）。
- `template.Must(template.New("title").Parse(raw))` … パース失敗で panic するラッパー。パッケージ初期化で使い、テンプレが壊れてたら起動時に落とす（リクエスト時まで遅延させない）。
- 触れるのは**エクスポート済み（大文字始まり）フィールドだけ**。だから `failedExamples` の要素 struct は `Title` / `Length` と大文字。小文字だと `{{.Title}}` が空になる。
- データは `map[string]any` で渡し、キー名はテンプレートの `{{.MaxLength}}` と完全一致させる。

#### len の単位問題を実装で解消（観察2の続き）

検証を `len(title)` から `utf8.RuneCountInString(title)` に変えて、プロンプトの「文字数」と単位を揃えた。ここで大事なのは **`len()` は対象で意味が変わる** こと:

- `len(title)`（文字列）= バイト数 → RuneCountInString に変える
- `len(resp.Candidates)`（スライス）= 要素数 → 正しいので変えない

「`len(文字列)` だけ直す、`len(スライス)` は触らない」。C++ の `std::string::size()`（直したい）と `std::vector::size()`（そのまま）の区別と同じ。

#### タイトルの日本語化

title.md の1行目に「日本語で生成してください」を入れるとタイトルが日本語になる。プロンプトの言語が出力の言語を決める。`generateDescription` は別途インラインの日本語プロンプトなので、タイトルと要約でプロンプト管理が分かれている状態（揃えるなら両方テンプレート化する手もある）。

#### つまずきログ

- `//go:embed` の directive を書いたのに title.md を作る前にビルドして `no matching files found`。embed は対象ファイルが先に要る。
- `go build` は `_test.go` を含まないが、通常ソース（insert.go）は含む。だから前章のテストの typo は build をすり抜けたが、今回の insert.go のエラーは build で出た。テストのコンパイル確認は `go vet` か `go test`。
- 定数を `titleMaxLength` で定義したのに呼び出しで `maxLength` と書いて `undefined`。引数名（関数内）とパッケージ定数を混同した。
- 実走2回ともリトライ未発動（短いタイトルで即合格）。機構が動くのを見たいなら `titleMaxLength` を一時的に 20 などに下げて空振り→収束を観察する。

## 第7章 構造化データ出力でIoCなど属性値を抽出する

### 構造化出力の基本

#### ResponseMIMEType と ResponseSchema

Gemini APIに genai.GenerateContentConfig を渡す。ResponseMIMEType: "application/json" で応答をJSON形式にさせ、ResponseSchema: &genai.Schema{...} でJSON Schemaライクに出力の型を 制約する。役割分担は、スキーマが「形式の制約」、プロンプトが「意味的な指示」。スキーマで型を縛りつつプロンプトでも何を出してほしいか説明すると精度が上がる。

#### 実装
- generateTitle + generateDescription → generateSummary に統合
- 応答はJSON文字列で返ってくるので、`json.Unmarshal([]byte(rawJSON), &summary)` で `alertSummary` 構造体に復元する。
- 検証は `alertSummary.validate()` に集約し、リトライループの中で「Unmarshal → validate → 失敗なら failedExamples に積んで continue」という流れ。

#### つまずきログ
- `generateTitle` をコピーして作り替える過程で、出口（戻り値）の直し忘れが連鎖した。戻り値を string → `*alertSummary` に変えたら、関数内の `return ""` を全部 `return nil`
  に直す必要がある。一個直すと次のエラーが出る、の繰り返し。
- `maxLength` 引数を消したら、本体（テンプレに渡す値）とプロンプトのキー名の両方に波及した。
- テンプレートのキー不一致。`summary.md` は `{{.MaxTitleLength}}` を使うのに、コードで `MaxTitleLength` を渡し忘れていた。`text/template` は存在しないキーを参照してもエラーにせず `<no value>` を埋めるので、プロンプトに「文字未満で」と出てしまう。コンパイルもvetも通るのに出力だけ変、という見つけにくいバグ。前章の「キー名はテンプレートと完全一致」がここで効いた。
- `summary.md` を英語のままにしたら出力も英語になった。プロンプトの言語が出力言語を決める（第6章の再確認）。和訳して日本語出力に戻した。
- DEBUG用に `fmt.Printf` で生JSONを出すと、構造化出力が本当にJSONで返るのが目で見えて理解が進む。確認できたら消す。

#### go vet メモ

`go build` は構文・型チェック、`go vet` はそれに加えて「コンパイルは通るが怪しいコード」も見る静的解析。C++の `clang-tidy` / `-Wall` 的なもの。ただしGoのvetは型チェックも内包するので、構文エラーもvetで出る。

### IoC（IP、ドメイン、ハッシュ）の抽出実装

## 第8章 会話と履歴の管理

<!-- 未着手 -->

## 第9章 Function Callingによる外部ツール連携

<!-- 未着手 -->

## 第10章 シンプルなツールの実装：脅威インテリジェンスツール

<!-- 未着手 -->

## 第11章 より実践的なツールの実装：BigQueryからのログ取得

<!-- 未着手 -->

## 第12章 エージェントのプロンプトエンジニアリング

<!-- 未着手 -->

## 第13章 コンテキスト圧縮とサブエージェントパターン

<!-- 未着手 -->

## 第14章 AIワークフロー - 設計と実装

<!-- 未着手 -->

## 第15章 Plan & Execute パターン - 設計と実装

<!-- 未着手 -->

## 第16章 Embeddingとエージェントの記憶システム

<!-- 未着手 -->

## 第17章 エージェントの記憶システム実装

<!-- 未着手 -->

## 第18章 セキュリティ分析のためのツール・サブエージェント

<!-- 未着手 -->

## 第19章 エージェントのテスト

<!-- 未着手 -->

## 第20章 MCPによるツール利用の拡張

<!-- 未着手 -->

## 第21章 実運用への統合と今後の展望

<!-- 未着手 -->
