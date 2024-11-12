<?php

namespace App\Security;

use App\Repository\JwtTokenRepository;
use App\Repository\UserRepository;
use App\Service\JwtService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class JWTAuthenticator extends AbstractAuthenticator
{
    private $jwtService;
    private $jwtTokenRepository;
    private $userRepository;

    public function __construct(JwtService $jwtService, JwtTokenRepository $jwtTokenRepository, UserRepository $userRepository)
    {
        $this->jwtService = $jwtService;
        $this->jwtTokenRepository = $jwtTokenRepository;
        $this->userRepository = $userRepository;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization') && str_starts_with($request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization');
        $tokenString = substr($authHeader, 7);

        $jwtToken = $this->jwtTokenRepository->findOneBy(['token' => $tokenString]);

        if (!$jwtToken || $jwtToken->getExpiresAt() < new \DateTimeImmutable('now', new \DateTimeZone('Europe/Paris'))) {
            throw new AuthenticationException('Invalid or expired token.');
        }

        $token = $this->jwtService->parseToken($tokenString);
        if (!$token) {
            throw new AuthenticationException('Invalid token.');
        }

        $userId = $token->claims()->get('uid');
        return new SelfValidatingPassport(new UserBadge($userId, function ($userId) {
            // Implement a method to load the user by their ID
            return $this->userRepository->find($userId);
        }));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse
    {
        return new JsonResponse(['error' => $exception->getMessage()], JsonResponse::HTTP_UNAUTHORIZED);
    }

    public function onAuthenticationSuccess(Request $request, $token, string $firewallName): ?JsonResponse
    {
        return null;
    }
}
