# iAPT source deobfuscate + static DEX restore

普通混淆还原：

```bash
python app/tools/iapp_deobfuscate.py src.zip -o out.zip
```

开启纯静态 DEX 还原，并同时保留其它混淆还原参数：

```bash
python app/tools/iapp_deobfuscate.py src.zip --dex-restore --dex OqR.dex -o out.zip
python app/tools/iapp_deobfuscate.py src.zip --dex-restore --dex helper.apk --dex ./dexs -o out.zip --no-rename-vars
```

`--dex` 不是必填。开启 `--dex-restore` 后，脚本会自动扫描源码 ZIP 内的 `*.dex`、`*.apk`、`*.zip`、`*.jar`，包括客户端默认打包进去的 `apk/lib/**`。因此项目里 `apk/lib/OqR.dex`、`apk/lib/helper.jar` 等会直接参与还原。

多余文件保留规则：

- 源码 ZIP 里已有的 `apk/lib/**` 会原样输出回结果包。
- 额外通过 `--dex` 传入的文件/目录会复制到 `_iapt_extra_inputs/`。
- 无法静态执行的 `cls/javax` 调用会保留原代码，并记录到 `static_dex_restore_map.txt`。
