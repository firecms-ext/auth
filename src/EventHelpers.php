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
namespace FirecmsExt\Auth;

use FirecmsExt\Auth\Contracts\AuthenticateInterface;
use FirecmsExt\Auth\Events\Attempting;
use FirecmsExt\Auth\Events\Authenticated;
use FirecmsExt\Auth\Events\CurrentDeviceLogout;
use FirecmsExt\Auth\Events\Failed;
use FirecmsExt\Auth\Events\Login;
use FirecmsExt\Auth\Events\Logout;
use FirecmsExt\Auth\Events\OtherDeviceLogout;
use FirecmsExt\Auth\Events\Validated;

trait EventHelpers
{
    /**
     * Fire the attempt event with the arguments.
     */
    protected function dispatchAttemptingEvent(array $credentials, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Attempting(
            $this->name,
            $credentials,
            $remember
        ));
    }

    /**
     * Fires the validated event if the dispatcher is set.
     */
    protected function dispatchValidatedEvent(AuthenticateInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Validated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the login event if the dispatcher is set.
     */
    protected function dispatchLoginEvent(AuthenticateInterface $user, bool $remember = false): void
    {
        $this->eventDispatcher->dispatch(new Login(
            $this->name,
            $user,
            $remember
        ));
    }

    /**
     * Fire the authenticated event if the dispatcher is set.
     */
    protected function dispatchAuthenticatedEvent(AuthenticateInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Authenticated(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the logout event if the dispatcher is set.
     */
    protected function dispatchLogoutEvent(AuthenticateInterface $user): void
    {
        $this->eventDispatcher->dispatch(new Logout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the current device logout event if the dispatcher is set.
     */
    protected function dispatchCurrentDeviceLogoutEvent(AuthenticateInterface $user): void
    {
        $this->eventDispatcher->dispatch(new CurrentDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the other device logout event if the dispatcher is set.
     */
    protected function dispatchOtherDeviceLogoutEvent(AuthenticateInterface $user): void
    {
        $this->eventDispatcher->dispatch(new OtherDeviceLogout(
            $this->name,
            $user
        ));
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     */
    protected function dispatchFailedEvent(?AuthenticateInterface $user, array $credentials): void
    {
        $this->eventDispatcher->dispatch(new Failed(
            $this->name,
            $user,
            $credentials
        ));
    }
}
