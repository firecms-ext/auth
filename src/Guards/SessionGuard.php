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
use FirecmsExt\Auth\Contracts\StatefulGuardInterface;
use FirecmsExt\Auth\Contracts\SupportsBasicAuthInterface;
use FirecmsExt\Auth\Contracts\UserProviderInterface;
use FirecmsExt\Auth\EventHelpers;
use FirecmsExt\Auth\Exceptions\AuthenticationException;
use FirecmsExt\Auth\GuardHelpers;
use FirecmsExt\Auth\Recalled;
use FirecmsExt\Cookie\Contract\CookieJarInterface;
use Hyperf\Contract\SessionInterface;
use Hyperf\HttpMessage\Cookie\Cookie;
use Hyperf\Macroable\Macroable;
use Hyperf\Utils\Str;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ServerRequestInterface;

class SessionGuard implements StatefulGuardInterface, SupportsBasicAuthInterface
{
    use EventHelpers;
    use GuardHelpers;
    use Macroable;

    /**
     * The name of the Guard. Typically, "session".
     *
     * Corresponds to guard name in authentication configuration.
     *
     * @var string
     */
    protected mixed $name;

    /**
     * The user we last attempted to retrieve.
     */
    protected AuthenticateInterface $lastAttempted;

    /**
     * Indicates if the user was authenticated via a recalled cookie.
     */
    protected bool $viaRemember = false;

    /**
     * The session used by the guard.
     */
    protected SessionInterface $session;

    /**
     * The FirecmsExt cookie jar instance.
     */
    protected CookieJarInterface $cookieJar;

    /**
     * The request instance.
     */
    protected ServerRequestInterface|null $request;

    /**
     * The event dispatcher instance.
     */
    protected EventDispatcherInterface $eventDispatcher;

    /**
     * Indicates if the logout method has been called.
     */
    protected bool $loggedOut = false;

    /**
     * Indicates if a token user retrieval has been attempted.
     */
    protected bool $recallAttempted = false;

    /**
     * Create a new authentication guard.
     */
    public function __construct(
        ServerRequestInterface $request,
        SessionInterface $session,
        EventDispatcherInterface $eventDispatcher,
        CookieJarInterface $cookieJar,
        UserProviderInterface $provider,
        string $name,
        array $options = []
    ) {
        $this->request = $request;
        $this->session = $session;
        $this->eventDispatcher = $eventDispatcher;
        $this->cookieJar = $cookieJar;
        $this->provider = $provider;
        $this->name = $options['name'] ?? 'session';
    }

    /**
     * Get the currently authenticated user.
     */
    public function user(): ?AuthenticateInterface
    {
        if ($this->loggedOut) {
            return null;
        }

        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if (! is_null($this->user)) {
            return $this->user;
        }

        $id = $this->session->get($this->getName());

        // First we will try to load the user using the identifier in the session if
        // one exists. Otherwise, we will check for a "remember me" cookie in this
        // request, and if one exists, attempt to retrieve the user using that.
        if (! is_null($id) && $this->user = $this->provider->retrieveById($id)) {
            $this->dispatchAuthenticatedEvent($this->user);
        }

        // If the user is null, but we decrypt a "recalled" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        if (is_null($this->user) && ! is_null($recaller = $this->recalled())) {
            $this->user = $this->userFromRecalled($recaller);

            if ($this->user) {
                $this->updateSession($this->user->getAuthIdentifier());

                $this->dispatchLoginEvent($this->user, true);
            }
        }

        return $this->user;
    }

    /**
     * Get the ID for the currently authenticated user.
     */
    public function id(): null|int|string
    {
        if ($this->loggedOut) {
            return null;
        }

        return $this->user()
            ? $this->user()->getAuthIdentifier()
            : $this->session->get($this->getName());
    }

    /**
     * Log a user into the application without sessions or cookies.
     */
    public function once(array $credentials = []): bool
    {
        $this->dispatchAttemptingEvent($credentials);

        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given user ID into the application without sessions or cookies.
     *
     * @param mixed $id
     */
    public function onceUsingId($id): bool
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate using HTTP Basic Auth.
     *
     * @throws AuthenticationException
     */
    public function basic(string $field = 'email', array $extraConditions = []): void
    {
        if ($this->check()) {
            return;
        }

        // If a username is set on the HTTP basic request, we will return out without
        // interrupting the request lifecycle. Otherwise, we'll need to generate a
        // request indicating that the given credentials were invalid for login.
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }

        $this->failedBasicResponse();
    }

    /**
     * Perform a stateless HTTP Basic login attempt.
     */
    public function onceBasic(string $field = 'email', array $extraConditions = []): void
    {
        $credentials = $this->basicCredentials($this->getRequest(), $field);

        if (! $this->once(array_merge($credentials, $extraConditions))) {
            $this->failedBasicResponse();
        }
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     */
    public function attempt(array $credentials = [], bool $remember = false): bool
    {
        $this->dispatchAttemptingEvent($credentials, $remember);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user, $remember);

            return true;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->dispatchFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     */
    public function loginUsingId($id, bool $remember = false): bool
    {
        if (! is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return true;
        }

        return false;
    }

    /**
     * Log a user into the application.
     */
    public function login(AuthenticateInterface $user, bool $remember = false): bool
    {
        $this->updateSession($user->getAuthIdentifier());

        // If the user should be permanently "remembered" by the application we will
        // queue a permanent cookie that contains the encrypted copy of the user
        // identifier. We will then decrypt this later to retrieve the users.
        if ($remember) {
            $this->ensureRememberTokenIsSet($user);

            $this->queueRecalledCookie($user);
        }

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->dispatchLoginEvent($user, $remember);

        $this->setUser($user);

        return true;
    }

    /**
     * Log the user out of the application.
     */
    public function logout(): void
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        if (! is_null($this->user) && ! empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }

        $this->dispatchLogoutEvent($user);

        // Once we have fired the logout event we will clear the users out of memory,
        // so they are no longer available as the user is no longer considered as
        // being signed in to this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Log the user out of the application on their current device only.
     */
    public function logoutCurrentDevice(): void
    {
        $user = $this->user();

        $this->clearUserDataFromStorage();

        $this->dispatchCurrentDeviceLogoutEvent($user);

        // Once we have fired the logout event we will clear the users out of memory,
        // so they are no longer available as the user is no longer considered as
        // being signed in to this application and should not be available here.
        $this->user = null;

        $this->loggedOut = true;
    }

    /**
     * Invalidate other sessions for the current user.
     *
     * The application must be using the AuthenticateSession middleware.
     */
    public function logoutOtherDevices(string $password, string $attribute = 'password'): ?bool
    {
        if (! $this->user()) {
            return null;
        }

        $result = tap($this->user()->forceFill([
            $attribute => getRecalledName::make($password),
        ]))->save();

        if ($this->recalled() || $this->cookieJar->hasQueued($this->getRecalledName())) {
            $this->queueRecalledCookie($this->user());
        }

        $this->dispatchOtherDeviceLogoutEvent($this->user());

        return $result;
    }

    /**
     * Get the last user we attempted to authenticate.
     */
    public function getLastAttempted(): AuthenticateInterface
    {
        return $this->lastAttempted;
    }

    /**
     * Get a unique identifier for the auth session value.
     */
    public function getName(): string
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Get the name of the cookie used to store the "recalled".
     */
    public function getRecalledName(): string
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }

    /**
     * Determine if the user was authenticated via "remember me" cookie.
     */
    public function viaRemember(): bool
    {
        return $this->viaRemember;
    }

    /**
     * Get the cookie creator instance used by the guard.
     */
    public function getCookieJar(): CookieJarInterface
    {
        return $this->cookieJar;
    }

    /**
     * Get the session store used by the guard.
     */
    public function getSession(): SessionInterface
    {
        return $this->session;
    }

    /**
     * Return the currently cached user.
     */
    public function getUser(): ?AuthenticateInterface
    {
        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @return $this
     */
    public function setUser(AuthenticateInterface $user): static
    {
        $this->user = $user;

        $this->loggedOut = false;

        $this->dispatchAuthenticatedEvent($user);

        return $this;
    }

    /**
     * Get the current request instance.
     */
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
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
     * Get the event dispatcher instance.
     */
    public function getEventDispatcher(): EventDispatcherInterface
    {
        return $this->eventDispatcher;
    }

    /**
     * Set the event dispatcher instance.
     */
    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * Pull a user from the repository by its "remember me" cookie token.
     */
    protected function userFromRecalled(Recalled $recalled): ?AuthenticateInterface
    {
        if (! $recalled->valid() || $this->recallAttempted) {
            return null;
        }

        // If the user is null, but we decrypt a "recalled" cookie we can attempt to
        // pull the user data on that cookie which serves as a remember cookie on
        // the application. Once we have a user we can return it to the caller.
        $this->recallAttempted = true;

        $this->viaRemember = ! is_null($user = $this->provider->retrieveByToken(
            $recalled->id(),
            $recalled->token()
        ));

        return $user;
    }

    /**
     * Get the decrypted recalled cookie for the request.
     */
    protected function recalled(): ?Recalled
    {
        if (is_null($this->request)) {
            return null;
        }

        if ($recalled = $this->request->cookie($this->getRecalledName())) {
            return new Recalled($recalled);
        }
        return null;
    }

    /**
     * Attempt to authenticate using basic authentication.
     */
    protected function attemptBasic(ServerRequestInterface $request, string $field, array $extraConditions = []): bool
    {
        if (empty($request->getHeaderLine('Authorization'))) {
            return false;
        }

        return $this->attempt(array_merge(
            $this->basicCredentials($request, $field),
            $extraConditions
        ));
    }

    /**
     * Get the credential array for a HTTP Basic request.
     *
     * @return string[]
     */
    protected function basicCredentials(ServerRequestInterface $request, string $field): array
    {
        $authorization = $this->getBasicAuthorization($request);
        return array_combine([$field, 'password'], $authorization);
    }

    /**
     * @return string[]
     */
    protected function getBasicAuthorization(ServerRequestInterface $request): array
    {
        $header = $request->getHeaderLine('Authorization');

        if (Str::startsWith($header, 'Basic ')) {
            try {
                return explode(':', base64_decode(Str::substr($header, 6)));
            } catch (\Throwable $throwable) {
            }
        }
        return [null, null];
    }

    /**
     * Get the response for basic authentication.
     *
     * @throws AuthenticationException
     */
    protected function failedBasicResponse(): void
    {
        throw new AuthenticationException('Invalid Basic credentials.');
    }

    /**
     * Determine if the user matches the credentials.
     */
    protected function hasValidCredentials(mixed $user, array $credentials): bool
    {
        $validated = ! is_null($user) && $this->provider->validateCredentials($user, $credentials);

        if ($validated) {
            $this->dispatchValidatedEvent($user);
        }

        return $validated;
    }

    /**
     * Update the session with the given ID.
     */
    protected function updateSession(int|string $id): void
    {
        $this->session->put($this->getName(), $id);

        $this->session->migrate(true);
    }

    /**
     * Create a new "remember me" token for the user if one doesn't already exist.
     */
    protected function ensureRememberTokenIsSet(AuthenticateInterface $user): void
    {
        if (empty($user->getRememberToken())) {
            $this->cycleRememberToken($user);
        }
    }

    /**
     * Queue the recalled cookie into the cookie jar.
     */
    protected function queueRecalledCookie(AuthenticateInterface $user): void
    {
        $this->cookieJar->queue($this->createRecalled(
            $user->getAuthIdentifier() . '|' . $user->getRememberToken() . '|' . $user->getAuthPassword()
        ));
    }

    /**
     * Create a "remember me" cookie for a given ID.
     */
    protected function createRecalled(string $value): Cookie
    {
        return $this->cookieJar->forever($this->getRecalledName(), $value);
    }

    /**
     * Remove the user data from the session and cookies.
     */
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());

        if (! is_null($this->recalled())) {
            $this->cookieJar->queue($this->cookieJar->forget($this->getRecalledName()));
        }
    }

    /**
     * Refresh the "remember me" token for the user.
     */
    protected function cycleRememberToken(AuthenticateInterface $user)
    {
        $user->setRememberToken($token = Str::random(60));

        $this->provider->updateRememberToken($user, $token);
    }
}
