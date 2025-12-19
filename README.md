# vt-multi-hash-checker

多筆檔案雜湊（MD5/SHA1/SHA256）查詢 VirusTotal 偵測結果的指令工具。支援指定安全供應商、非同步並行查詢、JSON/CSV 輸出，以及安全載入 API key（環境變數/檔案）。

## 特性
- 多筆雜湊：可由命令列或檔案一次輸入 10 筆以上
- 供應商指定：`--vendor` 指定安全供應商（預設 Trend Micro），大小寫/空白不敏感
- 非同步並行：`-c` 控制並行數，提高查詢速度
- 安全載入 API key：`--apikey`、`--apikey-file`、或環境變數 `VT_API_KEY`
- 格式化輸出：`--output json|csv`，並用 `--output-file` 存檔

## 安裝需求
- Python 3.7+
- 安裝 VirusTotal 官方 Python 客戶端：

```powershell
pip install vt-py
```

## 使用方式（Windows PowerShell）

### 1. 透過環境變數提供 API key
```powershell
$env:VT_API_KEY="<你的API_KEY>"
python check_hash.py --hash-file hashes.txt -c 5 --output csv --output-file out.csv
```

### 2. 透過檔案提供 API key
```powershell
Set-Content -Path apikey.txt -Value "<你的API_KEY>"
Set-Content -Path hashes.txt -Value "c4bec46bfc6b42fa47641080f19577093f8591c7`n3395856ce81f2b7382dee72602f798b642f14140"
python check_hash.py --apikey-file apikey.txt --hash-file hashes.txt --vendor "trend micro" -c 5 --output json --output-file out.json
```

### 3. 直接輸入多筆雜湊
```powershell
$env:VT_API_KEY="<你的API_KEY>"
python check_hash.py c4bec46bfc6b42fa47641080f19577093f8591c7 3395856ce81f2b7382dee72602f798b642f14140 --vendor "trend micro" -c 5 --output csv
```

## 參數說明
- `hashes`：命令列直接輸入的檔案雜湊（可多個）
- `--hash-file <path>`：從檔案讀取雜湊（每行一個，支援 `#` 註解）
- `--vendor <name>`：指定安全供應商（預設 `trend micro`）
- `--concurrency -c <n>`：並行數量，建議 3–5（避免 API 速率限制）
- `--apikey`：以參數提供 API key（不建議）
- `--apikey-file <path>`：從檔案載入 API key（建議）
- `VT_API_KEY`：環境變數提供 API key（建議）
- `--output json|csv`：輸出格式
- `--output-file <path>`：將輸出寫入檔案

## 輸出格式
- 指定 vendor 時：
  - JSON 每筆為：`{"hash","vendor","status","result"}`
  - CSV 欄位：`hash,vendor,status,result,malicious,undetected,error`
- 未指定 vendor 時（預設 Trend Micro 也會查）：
  - JSON/CSV 仍包含統一欄位，未使用的欄位留空

## 範例輸出
- JSON：
```json
[
  {"hash":"c4bec46bfc6b42fa47641080f19577093f8591c7","vendor":"TrendMicro","status":"malicious","result":"TROJ_FRS.VSNTKI25"},
  {"hash":"3395856ce81f2b7382dee72602f798b642f14140","vendor":"TrendMicro","status":"malicious","result":"Eicar_test_file"}
]
```

- CSV：
```
hash,vendor,status,result,malicious,undetected,error
c4bec46bfc6b42fa47641080f19577093f8591c7,TrendMicro,malicious,TROJ_FRS.VSNTKI25,,,
3395856ce81f2b7382dee72602f798b642f14140,TrendMicro,malicious,Eicar_test_file,,,
```

## 原理摘要
- 以 `vt.Client.get_object_async("/files/{hash}")` 取得檔案物件，解析 `last_analysis_results` 比對指定供應商結果；若未指定，預設查 Trend Micro。
- 非同步並行用 `asyncio` 與 `Semaphore` 控制併發；完成後統一輸出為 JSON/CSV。

## 安全建議
- 優先使用 `VT_API_KEY` 環境變數或 `--apikey-file`，避免在命令列中直接輸入 API key。
- 控制 `-c` 並行數以避免觸發 API 速率限制；必要時可加入退避重試策略。
