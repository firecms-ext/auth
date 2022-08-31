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
namespace FirecmsExt\Auth\Guards;

use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\GuardInterface;
use FirecmsExt\Auth\Contracts\UserProviderInterface;
use FirecmsExt\Auth\GuardHelpers;
use Hyperf\Utils\Str;
use Psr\Http\Message\ServerRequestInterface;

class TokenGuard implements GuardInterface
{
    use GuardHelpers;

    /**
     * The request instance.
     */
    protected ServerRequestInterface $request;

    /**
     * The name of the query string item from the request containing the API token.
     */
    protected string $inputKey;

    /**
     * The name of the token "column" in persistent storage.
     */
    protected string $storageKey;

    /**
     * Indicates if the API token is hashed in storage.
     */
    protected bool $hash = false;

    /**
     * Create a new authentication guard.
     */
    public function __construct(
        ServerRequestInterface $request,
        UserProviderInterface $provider,
        string $name,
        array $options = []
    ) {
        $this->request = $request;
        $this->provider = $provider;
        $this->inputKey = $options['input_key'] ?? 'api_token';
        $this->storageKey = $options['storage_key'] ?? 'api_token';
        $this->hash = $options['hash'] ?? false;
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticateInterface
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $user = null;

        $token = $this->getTokenForRequest();

        if (! empty($token)) {
            $user = $this->provider->retrieveByCredentials([
                $this->storageKey => $this->hash ? hash('sha256', $token) : $token,
            ]);
        }

        return $this->user = $user;
    }

    /**
     * Get the token for the current request.
     */
    public function getTokenForRequest(): string
    {
        $token = $this->request->query($this->inputKey);

        if (empty($token)) {
            $token = $this->request->input($this->inputKey);
        }

        if (empty($token)) {
            $token = $this->getBearerToken();
        }

        if (empty($token)) {
            $token = $this->getBasicAuthorization()[1];
        }

        return $token;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        if (empty($credentials[$this->inputKey])) {
            return false;
        }

        $credentials = [$this->storageKey => $credentials[$this->inputKey]];

        if ($this->provider->retrieveByCredentials($credentials)) {
            return true;
        }

        return false;
    }

    /**
     * Set the current request instance.
     *
     * @return $this
     */
    public function setRequest(ServerRequestInterface $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the bearer token from the request headers.
     */
    protected function getBearerToken(): ?string
    {
        $header = $this->request->header('Authorization', '');

        if (Str::startsWith($header, 'Bearer ')) {
            return Str::substr($header, 7);
        }
        return null;
    }

    /**
     * Get the bearer token from the request headers.
     *
     * @return string[]
     */
    protected function getBasicAuthorization(): array
    {
        $header = $this->request->header('Authorization');

        if (Str::startsWith($header, 'Basic ')) {
            try {
                return explode(':', base64_decode(Str::substr($header, 6)));
            } catch (\Throwable $throwable) {
            }
        }
        return [null, null];
    }
}
