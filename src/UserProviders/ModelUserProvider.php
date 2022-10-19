<?php

declare(strict_types=1);
/**
 * This file is part of FirecmsExt Auth.
 *
 * @link     https://www.klmis.cn
 * @document https://www.klmis.cn
 * @contact  zhimengxingyun@klmis.cn
 * @license  https://github.com/firecms-ext/auth/blob/master/LICENSE
 */
namespace FirecmsExt\Auth\UserProviders;

use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\UserProviderInterface;
use FirecmsExt\Hashing\Contract\DriverInterface;
use FirecmsExt\Hashing\Contract\HashInterface;
use Hyperf\Database\Model\Builder;
use Hyperf\Utils\Contracts\Arrayable;
use Hyperf\Utils\Str;

class ModelUserProvider implements UserProviderInterface
{
    /**
     * The hashed implementation.
     */
    protected DriverInterface $hasher;

    /**
     * The Eloquent user model.
     */
    protected string $model;

    /**
     * Create a new database user provider.
     */
    public function __construct(HashInterface $hash, array $options)
    {
        $this->model = $options['model'] ?? null;
        $this->hasher = ($hasher = $options['hash_driver'] ?? null) instanceof DriverInterface
            ? $hasher : $hash->getDriver($hasher);
    }

    /**
     * Retrieve a user by their unique identifier.
     */
    public function retrieveById(int|string $identifier): ?AuthenticateInterface
    {
        $model = $this->createModel();

        return method_exists($model, 'findFromCache')
            ? $model->findFromCache($identifier)
            : $this->newModelQuery($model)
                ->where($model->getAuthIdentifierName(), $identifier)
                ->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     */
    public function retrieveByToken(int|string $identifier, string $token): ?AuthenticateInterface
    {
        $model = $this->createModel();

        $retrievedModel = $this->newModelQuery($model)->where(
            $model->getAuthIdentifierName(),
            $identifier
        )->first();

        if (! $retrievedModel) {
            return null;
        }

        $rememberToken = $retrievedModel->getRememberToken();

        return $rememberToken && hash_equals($rememberToken, $token)
            ? $retrievedModel : null;
    }

    /**
     * Update the "remember me" token for the given user in storage.
     */
    public function updateRememberToken(AuthenticateInterface $user, string $token): void
    {
        $user->setRememberToken($token);

        $timestamps = $user->timestamps;

        $user->timestamps = false;

        $user->save();

        $user->timestamps = $timestamps;
    }

    /**
     * Retrieve a user by the given credentials.
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticateInterface
    {
        if (empty($credentials)
            || (count($credentials) === 1
                && Str::contains($this->firstCredentialKey($credentials), 'password'))) {
            return null;
        }

        // First we will add each credential element to the query as a where clause.
        // Then we can execute the query and, if we found a user, return it in a
        // Eloquent User "model" that will be utilized by the Guard instances.
        $query = $this->newModelQuery();

        foreach ($credentials as $key => $value) {
            if (Str::contains($key, 'password')) {
                continue;
            }

            if (is_array($value) || $value instanceof Arrayable) {
                $query->whereIn($key, $value);
            } else {
                $query->where($key, $value);
            }
        }

        return $query->first();
    }

    /**
     * Validate a user against the given credentials.
     */
    public function validateCredentials(AuthenticateInterface $user, array $credentials): bool
    {
        $plain = $credentials['password'];

        return $this->hasher->check($plain, $user->getAuthPassword());
    }

    /**
     * Create a new instance of the model.
     */
    public function createModel(): ?AuthenticateInterface
    {
        $class = '\\' . ltrim($this->model, '\\');

        return new $class();
    }

    /**
     * Gets the hashed implementation.
     */
    public function getHashInterface(): HashInterface
    {
        return $this->hasher;
    }

    /**
     * Sets the hashed implementation.
     *
     * @return $this
     */
    public function setHashInterface(HashInterface $hasher): static
    {
        $this->hasher = $hasher;

        return $this;
    }

    /**
     * Gets the name of the Eloquent user model.
     */
    public function getModel(): string
    {
        return $this->model;
    }

    /**
     * Sets the name of the Eloquent user model.
     *
     * @return $this
     */
    public function setModel(string $model): static
    {
        $this->model = $model;

        return $this;
    }

    /**
     * Get the first key from the credential array.
     */
    protected function firstCredentialKey(array $credentials): ?string
    {
        foreach ($credentials as $key => $value) {
            return $key;
        }
        return null;
    }

    /**
     * Get a new query builder for the model instance.
     */
    protected function newModelQuery(?AuthenticateInterface $model = null): ?Builder
    {
        return is_null($model)
            ? $this->createModel()->newQuery()
            : $model->newQuery();
    }
}
