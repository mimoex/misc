# wolfSSL Modular Square Root Tests

`SQRTMOD_USE_MOD_EXP`を定義したときの剰余平方根テスト

## Programs

- `ecc_import_probe.c`: wolfCrypt APIを用いて圧縮された楕円曲線の点のインポートテスト
- `sqrt_probe.c`: 剰余平方根関数のテスト
- `run_tests.py`: テスト
- `expose_sqrt.py`: static関数を外部から呼び出すようにする
- `run.sh`: ビルドとテスト

## References

- テスト対象:
  c8e78a3489a946773aaf4206f0f7f8fc19243f78
- wolfSSL fix:
  https://github.com/wolfSSL/wolfssl/pull/11982
