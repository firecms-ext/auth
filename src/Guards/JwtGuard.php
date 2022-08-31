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

use BadMethodCallException;
use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Contracts\StatelessGuardInterface;
use FirecmsExt\Auth\Contracts\UserProviderInterface;
use FirecmsExt\Auth\EventHelpers;
use FirecmsExt\Auth\GuardHelpers;
use FirecmsExt\Jwt\Exceptions\JwtException;
use FirecmsExt\Jwt\Exceptions\TokenBlacklistedException;
use FirecmsExt\Jwt\Exceptions\TokenExpiredException;
use FirecmsExt\Jwt\Exceptions\TokenInvalidException;
use FirecmsExt\Jwt\Exceptions\UserNotDefinedException;
use FirecmsExt\Jwt\Jwt;
use FirecmsExt\Jwt\JwtFactory;
use FirecmsExt\Jwt\Payload;
use FirecmsExt\Jwt\Token;
use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\Macroable\Macroable;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

class JwtGuard implements StatelessGuardInterface
{
    use EventHelpers, GuardHelpers, Macroable {
        __call as macroCall;
    }

    /**
     * The name of the Guard. Typically, "jwt".
     *
     * Corresponds to guard name in authentication configuration.
     */
    protected string $name;

    /**
     * The user we last attempted to retrieve.
     */
    protected AuthenticateInterface $lastAttempted;

    protected \Hyperf\Contract\ContainerInterface $container;

    protected Jwt $jwt;

    protected RequestInterface $request;

    protected EventDispatcherInterface $eventDispatcher;

    /**
     * Instantiate the class.
     */
    public function __construct(
        ContainerInterface $container,
        RequestInterface $request,
        JwtFactory $jwtFactory,
        EventDispatcherInterface $eventDispatcher,
        UserProviderInterface $provider,
        string $name
    ) {
        $this->container = $container;
        $this->request = $request;
        $this->jwt = $jwtFactory->make();
        $this->eventDispatcher = $eventDispatcher;
        $this->provider = $provider;
        $this->name = $name;
    }

    /**
     * Magically call the JWT instance.
     *
     * @throws BadMethodCallException
     * @return mixed
     */
    public function __call(string $method, array $parameters)
    {
        if (method_exists($this->jwt, $method)) {
            return call_user_func_array([$this->jwt, $method], $parameters);
        }

        if (static::hasMacro($method)) {
            return $this->macroCall($method, $parameters);
        }

        throw new BadMethodCallException("Method [{$method}] does not exist.");
    }

    public function user(): ?AuthenticateInterface
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->jwt->getToken()
            and ($payload = $this->jwt->check(true))
            and $this->validateSubject()
            and ($this->user = $this->provider->retrieveById($payload['sub']))
        ) {
            $this->dispatchAuthenticatedEvent($this->user);
            return $this->user;
        }

        return null;
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @throws UserNotDefinedException
     */
    public function userOrFail(): AuthenticateInterface
    {
        if (! $user = $this->user()) {
            throw new UserNotDefinedException();
        }

        return $user;
    }

    public function validate(array $credentials = []): bool
    {
        return (bool) $this->attempt($credentials, false);
    }

    public function attempt(array $credentials = []): bool
    {
        $this->dispatchAttemptingEvent($credentials);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $this->login($user);
        }

        $this->dispatchFailedEvent($user, $credentials);

        return false;
    }

    public function once(array $credentials = []): bool
    {
        $this->dispatchAttemptingEvent($credentials);

        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    public function login(AuthenticateInterface $user): bool
    {
        $token = $this->jwt->fromUser($user);
        $this->setToken($token)->setUser($user);

        $this->dispatchLoginEvent($user);

        return (bool) $token;
    }

    /**
     * @throws UserNotDefinedException
     */
    public function loginUsingId(int|string $id): bool
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            return $this->login($user);
        }

        throw new UserNotDefinedException();
    }

    /**
     * @throws JwtException
     * @throws TokenBlacklistedException
     * @throws TokenExpiredException
     * @throws TokenInvalidException
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function logout(bool $forceForever = false): void
    {
        $user = $this->user();

        $this->requireToken()->invalidate($forceForever);

        $this->dispatchLogoutEvent($user);

        $this->user = null;
        $this->jwt->unsetToken();
    }

    public function refresh(bool $forceForever = false): ?string
    {
        return $this->requireToken()->refresh($forceForever);
    }

    public function invalidate(bool $forceForever = false): Jwt
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    /**
     * Log the given User into the application.
     */
    public function onceUsingId(int|string $id): bool
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Add any custom claims.
     *
     * @return $this
     */
    public function setCustomClaims(array $claims): static
    {
        $this->jwt->setCustomClaims($claims);

        return $this;
    }

    /**
     * Get the raw Payload instance.
     *
     * @throws JwtException
     */
    public function getPayload(): Payload
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Set the token.
     *
     * @return $this
     */
    public function setToken(Token|string $token): static
    {
        $this->jwt->setToken($token);

        return $this;
    }

    public function getToken()
    {
        return $this->jwt->getToken();
    }

    public function getUser(): ?AuthenticateInterface
    {
        return $this->user;
    }

    public function setUser(AuthenticateInterface $user): static
    {
        $this->user = $user;

        $this->dispatchAuthenticatedEvent($user);

        return $this;
    }

    /**
     * Get the last user we attempted to authenticate.
     */
    public function getLastAttempted(): AuthenticateInterface
    {
        return $this->lastAttempted;
    }

    /**
     * Determine if the user matches the credentials.
     */
    protected function hasValidCredentials(?AuthenticateInterface $user, array $credentials): bool
    {
        $validated = ($user !== null and $this->provider->validateCredentials($user, $credentials));

        if ($validated) {
            $this->dispatchValidatedEvent($user);
        }

        return $validated;
    }

    /**
     * Ensure the JWTSubject matches what is in the token.
     *
     * @throws JwtException
     */
    protected function validateSubject(): bool
    {
        // If the provider doesn't have the necessary method
        // to get the underlying model name then allow.
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        return $this->jwt->checkSubjectModel($this->provider->getModel());
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @throws JwtException
     */
    protected function requireToken(): Jwt
    {
        if (! $this->jwt->getToken()) {
            throw new JwtException('Token could not be parsed from the request.');
        }

        return $this->jwt;
    }
}
