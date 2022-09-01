# firecms-ext/auth

```shell
# 登录授权 依赖安装
composer require firecms-ext/auth

# 发布配置(配置、数据迁移、用户模型)
php bin/hyperf.php vendor:publish firecms-ext/auth

# 密码加密 依赖安装
composer require firecms-ext/hashing

# 发布配置
php bin/hyperf.php vendor:publish firecms-ext/hashing

# JWT 登录扩展 依赖安装
composer require firecms-ext/jwt

# 生成（JWT）签名 Token 令牌 私钥和公钥
php bin/hyperf.php gen:jwt-keypair

# 生成（JWT）签名 Token 令牌 密钥
php bin/hyperf.php gen:jwt-secret

```
