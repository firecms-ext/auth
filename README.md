# firecms-ext/auth

```shell
# 安装依赖
composer require firecms-ext/auth

# 发布配置(配置、数据迁移、用户模型)
php bin/hyperf.php vendor:publish firecms-ext/auth

# 生成（JWT）签名 Token 令牌 私钥和公钥
php bin/hyperf.php gen:jwt-keypair

# 生成（JWT）签名 Token 令牌 密钥
php bin/hyperf.php gen:jwt-secret

```
