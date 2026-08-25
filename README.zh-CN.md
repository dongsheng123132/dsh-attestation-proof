# dsh-attestation-proof

面向 DeepSeek Harness 发布链的离线证明验证器：按显式清单校验本地目标文件、固定公钥和 DSSE/in-toto 声明，输出可复核、内容寻址的 JSON 判决。

它与 `dsh-release-proof`（下载源字节/版本一致）、`dsh-profile-lock-proof`（安装后配置锁）和 `dsh-audit-bundle`（多证据聚合）互补。首版不联网、不发现信任根、不执行命令，也不宣称完整实现 Sigstore 或 SLSA。

```bash
dsh-attestation-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

报告不包含签名载荷、目标文件、公钥 PEM、秘密或原始业务正文；路径逃逸、符号链接、超限输入和覆盖写入会被拒绝。
