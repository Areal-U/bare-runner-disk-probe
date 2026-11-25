# 繰返しビルドのソース受渡しを選ぶ

対象は通常入口が固定するBare、Chromium、depot_tools。`source-v8` はそのChromiumの実gitlinkが指定するV8、`source-chromium` はChromiumのルートGitリポジトリを測る。どちらも履歴1コミットのGit入力だけを持ち運ぶ。対象版を変える場合は通常入口の3つの固定値をレビューしてから、同じ試験をその版で使う。APKの生成物、CI設定、履歴、他のSDKやCIPDを送らない。

Bare成果担当が第28回と回収の競合が解けた時、既存 `bare-disk-probe.yml` の検証用refを使う。まず `source-v8` で1件。計算量だけを見て採用せず、2回再利用できる見込みで純短縮を確かめる。1日内に複数区間で再利用する見込みがない場合、この試験の保持時間では償却できない。別の日のビルドまで置く場合は実際の保持費・権限・容量で再判定する。`source-chromium` はV8で差が出て、全ルートに広げる価値・保管枠・ディスクの余裕がある時の追加試験。通常のAPK入口からこの試験を自動で起動することはない。

計測入口 `.github/workflows/next-source-compare.yml` は `workflow_call` 専用。GitHub上では呼出元の手動試験番号とattemptに結び付く。送信役が正規の上流から取得した*.packだけを1世代・1日保管し、別の標準ランナーでImmutable Artifact IDから取得する。候補の実バイト上限を送信直前に照合する。V8は外装上限192 MiB、全ルートは3.5 GiB。占有・期限・他runを確認できない場合は送信前に停止する。全体の実効空きと20000以上の予備inodeも確認し、同じVMで2個のcheckoutを同時に持たない。

受取側は同じ固定 `gclient sync --no-history --nohooks --noprehooks --jobs 4` に、空の作業領域と事前展開済みの作業領域を渡す。正規リモートの実SHAを持つ単一のDEPS項目で、チェックアウトのHEAD・tree・接続性・作業木を検査する。パッケージの破損、違う版、上限超過なら停止する。`BARE_SOURCE_COMPARISON` とjob summaryに転送、復元、両区間の壁時計、追加packバイト、SHA、受取開始までの時間を出す。実行結果で `seeded_new_pack_bytes` を点検する。

**採用条件**　まず実SHAとtreeが一致し、受取・復元・検証の合計が直接同期より短いこと。予定する利用回数を掛けた差が、初回の取得・束作成・アップロードと余分な待ちを回収すること。`net_s_over_planned_uses` は初回作成と全回分の送受を含む。`net_s_with_observed_one_time_handoff` は試験の2ジョブ間の待ちも一度引いた値。計算VMを早く起こしてビルドの時計まで消費する場合は、その失う時間も引く。差が回線の揺れ程度なら標準の直接同期を維持する。V8試験の成立は13分台のChromium+Android全同期の省略を意味しない。新世代への出力継承やソース用Artifactを本番に有効化する変更は別途レビューする。

再現はリポジトリのトップで `python3 -m unittest discover -s next_build/trials -p test_source_reuse.py`。独立したローカル空領域と正規公開上流が使える場合は `python3 next_build/trials/source_reuse.py local v8 /path/to/new-directory` で実gclient対照を行える。ローカルJSONの時間はHosted VM・中継・待ちを含まない。
