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

- 入力: サーバー・ネットワーク機器・クラウド・アプリの**ログ**を全部集める
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

DevOps の **Datadog / New Relic / Sentry** に近いが、セキュリティ専用で「攻撃検知」「フォレンジック」に最適化されている。

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

<!-- 未着手 -->

## 第3章 セキュリティアラートの分析業務における課題とLLMによる改善の可能性

<!-- 未着手 -->

## 第4章 システムアーキテクチャと設計方針

<!-- 未着手 -->

## 第5章 開発環境の準備と事前実装済みコードの説明

<!-- 未着手 -->

## 第6章 LLM利用の基礎とアラートの説明文の作成

<!-- 作業中（未コミット）: pkg/usecase/alert/insert.go にサマリー生成ロジック追加中 -->
<!-- typo: s.Title}a → s.Title} -->

## 第7章 構造化データ出力でIoCなど属性値を抽出する

<!-- 未着手 -->

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
