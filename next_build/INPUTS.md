# 次回ビルドで使う版と親を決める

Bare成果担当が次回の起動前に行う読取用の入口。コマンドはリポジトリのルートから実行する。出力は判定・入力表で、権限付与やビルド起動は行わない。委任済みの担当が版を固定できるなら、本人への再照会は不要。新たな上流版を取り込むかが未決定で、変更内容や対象が本人の選択に依存するときにだけ確認する。2.0.8は比較に使った一例。

## 1. 入力を固定する

Bare公式Gitのオブジェクト（必要なblobを含む）とChromiumの同じコミットのGit treeを使用する。最初は upstream のタグをコミットまで解決し、その40桁を使う。Chromiumを独立に選び直す必要はない。Bareの固定した `BUILDING.md` に書かれたコミットが唯一の照合対象。これらのローカルGitストアがなければ、公式の `https://github.com/BareBrowser/bare-browser.git` を固定SHAで浅くfetchし、そこから読んだChromiumコミットを `https://chromium.googlesource.com/chromium/src.git` から `--depth=1 --filter=blob:none` で取得する。

```sh
python3 next_build/inputs.py source "$bare_git" "$chromium_git" "$requested_bare_commit" \
  --expected-chromium "$reviewed_chromium_commit" --compare-to "$previous_bare_commit"
```

同じ `source` に `--compare-to` を付けず `--emit-gn` を指定すると、選んだ版の実パッチ用の同居版 `args.gn` を標準出力に得る。VERSIONのABI用版コードと版名を公式GNと照合し、パッケージ設定1行だけを変換する。

パッチ木、ARM64 GN、同居パッケージ、版名・版コード、埋込みuBOの実バイトと公式チェックサム、ビルダー・Clang・NDKほかを拘束するDEPS・ARM64 orderfile入力のGitオブジェクトを記録する。変わったソース世代は出力の無条件な再利用を許さない。照合済みソースblob、固定NDK・ツールの同じバイトは準備段階で再利用できる。実コンパイル時は従来の `checkpoint.provenance_identity` と独立受領時のグラフ・必要成果の再検証を引き続き使う。変更した部分がCIだけでも元の生産SHAと現在の入力を両方照合する。

## 2. 同版の以前の受領と未終端を照合する

本人用の特定保存先に署名済み成果があれば、**先に**既存の回収担当が自分で取得した版・証明書・SHA・APKを照合する。下記のファイルは既存 `preflight28/collector/production.py owner` と同じ形式で、登録時の本人専用locatorと、信頼済み署名キットの証明書指紋を使う。

```sh
python3 next_build/inputs.py delivered "$private_locator" "$existing_owner_evidence" "$aapt2" "$apksigner_jar"
```

ディレクトリ内の `owner.json, listing.json, publication.json, retrieved.apk` は実在する同じ受領から取る。異なる宛先、共有版、署名違い、上書きされた別版、パッケージ・CRX相違は拒否する。既に目的の版を引渡し済みなら同版を作り直さない。

新たな完成が確認できないときは既存登録担当が元のlocatorから、`preflight28/collector/PRODUCTION.md` の capture 手順で既存run・受領列を読む。以下には元の `actions/runs/<physical_run>/attempts/1` に加え、同じサービスの `actions/runs/<physical_run>` も前後2回のcaptureに含める。これは現在の手動再実行との競合を除くため。本人がrun IDを手渡す必要はない。

```sh
# 現行の回収経路と同じ準備。既存担当の非公開領域を使用する。
python3 preflight28/transport/prepare.py tools
python3 next_build/inputs.py campaign "$private_locator" "$existing_owner_capture"
```

| 判定 | 次の通常動作 |
|---|---|
| `existing-operation-active` | 元の登録に任せる。新たな計算を起動しない。 |
| `collect-and-verify-owner-delivery` | 既存の collect → clear → owner。暗号文があれば転送・回収の復旧を優先。 |
| `reconcile-original-transfer-or-confirm-loss` | 原VMの最終状態、実Artifact／Draft・本人台帳を照合。存在不明では計算しない。両方の喪失を既存の `loss_resume.py` が認証した場合だけ既存の一回復旧。 |
| `correct-failed-frontier-before-new-campaign` | 元コンパイルと静止は成功し、APKグラフの分類で停止、梱包・APK保管・正式受領の各書込はスキップ。実outcome ZIPが残るときは `artifacts/<id>.zip` と `actions/artifacts/<id>` の実GETをcaptureに含める。親SHA・ID・初回ジョブ時間・stop本体を照合する。既に期限切れなら同一ジョブの工程証拠から是正に進める。未受領の子は採用しない。復旧dispatchや同版の自動再計算を許可しない。 |
| `correct-stop-before-any-new-build` | 無進展・サイズ上限は原因と対象工程を是正してから判断する。 |
| `prepare-new-campaign-from-independently-verified-parent` | 12区間の後の検証専用区間（例外復旧は同じく検証済み末尾）の受領を確認した場合。出力の実run・元SHA・親key/sha/identity・manifest ID/SHAを新規案件の候補に固定。前のS2へ戻さない。新登録前にも同じ親を独立に読み直す。 |
| 照合失敗・記録失効・変化 | 本人保存済み暗号文、署名結果、既存台帳・回収入口を照合。欠落、再実行、未照合の新着を根拠に新しいS2ビルドへ進めない。 |

## 3. 新規案件の通常入口と適用条件

現行 `bare-checkpoint-transfer.yml` の通常12区間は R27 S2、`registration.CAMPAIGN` の最初の一回の請求、予約済み宛先・受付時のHEADに固定される。**新しい版・新しい本番SHA・R28の後継親・新規キャンペーンをこの旧登録で起動することはできない。** 回収と確定喪失の例外復旧は元のSHA／受領列を保持する。

* 同版の新キャンペーンでは、成果担当が出力した `reviewed_parent` の実バイト・親生成環境・全必要成果の独立読戻し、回収担当が新たな一意のキャンペーン／HEAD／その親／本人宛先を拘束したticketとACKを入力にする。継続父が未確定なら固定値を作らない。新たな空ビルドが必要な場合も既存claimの再利用はしない。
* 上流版変更時は `source` の固定値を使い、Bare CIの通常準備・パッチ数・GNハッシュ・uBO・producerおよびcollectorのAPK版検査を揃える。OS依存のsnapshot、depot、Dockerのdigest、Clang/NDK・PGO、生成ヘッダを新しい実入力で照合し、別入力世代として作る。旧出力を一括で展開しない。版コードは本人端末の版と比較し、同居ID・署名の継続も検査する。入手済みの同一ソース・ツールだけを準備で使用する。
* 変更レビューの対象は通常入口 `bare-checkpoint-transfer.yml`、`bare-arm64-probe.yml`（生成・APKの両方）、`bare-r28-native-slot.yml`（親・権利）、`coexist_inputs.py`、control の registration/admission/recover/loss_resume と橋渡しの名前空間、`preflight28/graph/retained.py`、`preflight28/transport/recipes/install_six.sh`、`preflight28/collector/production.py` と署名・回収担当の同一宛先。古い版の実回収能力を保持する。新しい一般dispatchを開く目的の差替えはしない。
* 成果担当は新キャンペーンの固定値と検証をまとめ、本人の本番反映・起動判断後にだけ運用に適用する。現時点で未確定の版や未受領の親に対する本番binderは発行していない。

### 版依存の差分を自動生成する

次回の担当は、両方の公式Gitストアと選んだCIの厳密なSHAを指定し、新しい隔離出力だけを作る。元の checkout、受領・権限・dispatch・署名の設定は書き換わらない。

```sh
python3 next_build/render_input_assertions.py "$bare_git" "$chromium_git" "$new_preview_directory" \
  --ci-head "$reviewed_ci_commit" --bare-sha "$requested_bare_commit" --chromium-sha "$reviewed_chromium_commit"
python3 next_build/test_render_inputs.py verify-preview "$new_preview_directory" "$bare_git"
```

`rendered/` が通常producer・同居GN生成・回収APK検査の版依存設定を置換したコピー、`product-assertions.patch` が元のCIコミットへの差分、`args.gn` が同居版の実入力。元の検査行の欠落・重複や異なるChromium指定は出力前に拒否する。完了時の `review.json` は元/先のGitオブジェクト、差分ファイル、未解決の受入条件を記録する。再現試験のcollector検査は公式CRXの実バイトと小さなELFヘッダを使い、aapt2の版名・版コード出力だけを固定した対照。公式APKの署名検査を通したことにはならない。

同じ版の生成は差分0バイト。異なる版で生成した部分差分は新キャンペーン側のソース検査向けレビュー材料で、稼働中のR28の回収を担当するコードに適用しない。新しい版のBUILD.gnまたはOS依存インストーラーが変わった場合は実Gitオブジェクトを示して止める。輸送ファイル名やR28のbranch/claim/回収の名前を一括置換せず、別キャンペーンの承認後に対象の宛先とともに拘束する。どの場合も `dispatch_ready` はfalse。
